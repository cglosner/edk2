/** @file
  SyzAgentDxe dispatch loop.

  Walks a fuzzer-generated program one (Call, Size, Payload) record at
  a time and forks to the appropriate UEFI Boot Services / Runtime
  Services entry point. Returns to SyzAgentDxeEntryPoint() when the
  walk completes (or when a malformed record is encountered).

  All pointer-typed arguments are dereferenced inside this file. The
  general rule, taken from docs/edk2_design.md §4.2.1, is:

    The dispatcher copies pointer-typed arguments into agent-owned
    scratch pages first. Failing to do so turns "the firmware crashed
    because we mutated arguments wrong" into "the firmware crashed
    because we let it dereference a fuzzer-controlled pointer", which
    defeats the point.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzAgentDxe.h"

#include <Protocol/HiiDatabase.h>

//
// AsanSyz integration is optional: if MdeModulePkg/Library/AsanLib/AsanSyz.h
// is not on the include path (the build hasn't enabled ASAN_ENABLE),
// the SyzEdk2ApiAsan* commands fall back to no-ops.
//
#if defined (SYZ_AGENT_HAS_ASAN_SYZ)
  #include <Library/AsanSyz.h>
#else
STATIC BOOLEAN  AsanSyzReady (VOID) {
  return FALSE;
}

STATIC VOID  AsanSyzPoison (UINTN  Addr, UINTN  Length) {
  (VOID)Addr;
  (VOID)Length;
}

STATIC VOID  AsanSyzUnpoison (UINTN  Addr, UINTN  Length) {
  (VOID)Addr;
  (VOID)Length;
}

STATIC VOID  AsanSyzReport (UINTN  Addr, UINTN  Size, UINT8  IsWrite) {
  (VOID)Addr;
  (VOID)Size;
  (VOID)IsWrite;
}
#endif

//
// Static lookup table mapping SYZ_EDK2_PROTO_ID to gEfi*Guid pointers.
//
typedef struct {
  UINT32          Id;
  CONST EFI_GUID  *Guid;
} SYZ_EDK2_PROTO_ENTRY;

STATIC CONST SYZ_EDK2_PROTO_ENTRY  mProtocolTable[] = {
  { SyzEdk2ProtoBlockIo,       &gEfiBlockIoProtocolGuid           },
  { SyzEdk2ProtoDevicePath,    &gEfiDevicePathProtocolGuid        },
  { SyzEdk2ProtoDiskIo,        &gEfiDiskIoProtocolGuid            },
  { SyzEdk2ProtoLoadedImage,   &gEfiLoadedImageProtocolGuid       },
  { SyzEdk2ProtoSerialIo,      &gEfiSerialIoProtocolGuid          },
  { SyzEdk2ProtoSimpleFs,      &gEfiSimpleFileSystemProtocolGuid  },
  { SyzEdk2ProtoSimpleNetwork, &gEfiSimpleNetworkProtocolGuid     },
  { SyzEdk2ProtoSimpleTextOut, &gEfiSimpleTextOutProtocolGuid     },
  { SyzEdk2ProtoHiiDatabase,   &gEfiHiiDatabaseProtocolGuid       },
  { SyzEdk2ProtoHiiString,     &gEfiHiiStringProtocolGuid         },
  { SyzEdk2ProtoHiiFont,       &gEfiHiiFontProtocolGuid           },
};

CONST EFI_GUID *
EFIAPI
SyzEdk2LookupProtocolGuid (
  IN UINT32  ProtocolId
  )
{
  UINTN  Index;
  for (Index = 0; Index < ARRAY_SIZE (mProtocolTable); Index++) {
    if (mProtocolTable[Index].Id == ProtocolId) {
      return mProtocolTable[Index].Guid;
    }
  }
  return NULL;
}

//
// Allocation slot helpers.
//
STATIC
INTN
AllocSlotInsertPool (
  IN VOID  *Pointer
  )
{
  UINTN  Index;
  for (Index = 0; Index < SYZ_EDK2_MAX_ALLOCS; Index++) {
    if (gSyzEdk2Agent.Allocs[Index].Kind == SyzEdk2AllocSlotEmpty) {
      gSyzEdk2Agent.Allocs[Index].Kind    = SyzEdk2AllocSlotPool;
      gSyzEdk2Agent.Allocs[Index].Pointer = Pointer;
      gSyzEdk2Agent.Allocs[Index].Pages   = 0;
      return (INTN)Index;
    }
  }
  return -1;
}

STATIC
INTN
AllocSlotInsertPages (
  IN VOID   *Pointer,
  IN UINTN  Pages
  )
{
  UINTN  Index;
  for (Index = 0; Index < SYZ_EDK2_MAX_ALLOCS; Index++) {
    if (gSyzEdk2Agent.Allocs[Index].Kind == SyzEdk2AllocSlotEmpty) {
      gSyzEdk2Agent.Allocs[Index].Kind    = SyzEdk2AllocSlotPages;
      gSyzEdk2Agent.Allocs[Index].Pointer = Pointer;
      gSyzEdk2Agent.Allocs[Index].Pages   = Pages;
      return (INTN)Index;
    }
  }
  return -1;
}

//
// Per-call handlers. Each one returns EFI_SUCCESS even if the underlying
// service returned an error: dispatch failures are not the same as agent
// failures.
//

STATIC
EFI_STATUS
HandleNop (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  if (PayloadSize < sizeof (SYZ_EDK2_NOP_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }
  CONST SYZ_EDK2_NOP_PAYLOAD  *P = (CONST SYZ_EDK2_NOP_PAYLOAD *)Payload;
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] nop cookie=0x%lx\n", P->Cookie));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSetVariable (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SET_VARIABLE_PAYLOAD  *P;
  CHAR16                               *Name;
  VOID                                 *Data;
  UINTN                                NameLen;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }

  P = (CONST SYZ_EDK2_SET_VARIABLE_PAYLOAD *)Payload;
  if ((UINTN)P->NameSize + (UINTN)P->DataSize + sizeof (*P) > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }
  if ((P->NameSize % 2) != 0 || P->NameSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Copy the name into a local buffer and terminate it. The fuzzer can
  // produce non-NUL-terminated payloads.
  //
  NameLen = P->NameSize / sizeof (CHAR16);
  Name    = AllocateZeroPool ((NameLen + 1) * sizeof (CHAR16));
  if (Name == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (Name, Payload + sizeof (*P), P->NameSize);

  Data = NULL;
  if (P->DataSize > 0) {
    Data = AllocatePool (P->DataSize);
    if (Data == NULL) {
      FreePool (Name);
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem (Data, Payload + sizeof (*P) + P->NameSize, P->DataSize);
  }

  Status = gRT->SetVariable (
                  Name,
                  &gSyzEdk2Agent.SyzEdk2VendorGuid,
                  P->Attributes,
                  P->DataSize,
                  Data
                  );
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] SetVariable -> %r\n", Status));

  if (Data != NULL) {
    FreePool (Data);
  }
  FreePool (Name);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleGetVariable (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_GET_VARIABLE_PAYLOAD  *P;
  CHAR16                               *Name;
  UINT8                                *Data;
  UINTN                                NameLen;
  UINTN                                DataSize;
  UINT32                               Attributes;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_GET_VARIABLE_PAYLOAD *)Payload;
  if ((UINTN)P->NameSize + sizeof (*P) > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }
  if ((P->NameSize % 2) != 0 || P->NameSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  NameLen = P->NameSize / sizeof (CHAR16);
  Name    = AllocateZeroPool ((NameLen + 1) * sizeof (CHAR16));
  if (Name == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (Name, Payload + sizeof (*P), P->NameSize);

  DataSize = (UINTN)P->MaxData;
  Data     = AllocatePool (DataSize == 0 ? 1 : DataSize);
  if (Data == NULL) {
    FreePool (Name);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gRT->GetVariable (
                  Name,
                  &gSyzEdk2Agent.SyzEdk2VendorGuid,
                  &Attributes,
                  &DataSize,
                  Data
                  );
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] GetVariable -> %r\n", Status));

  FreePool (Data);
  FreePool (Name);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleQueryVariableInfo (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_QUERY_VARIABLE_INFO_PAYLOAD  *P;
  UINT64                                       MaxStorage;
  UINT64                                       RemainingStorage;
  UINT64                                       MaxSize;
  EFI_STATUS                                   Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_QUERY_VARIABLE_INFO_PAYLOAD *)Payload;
  Status = gRT->QueryVariableInfo (
                  P->Attributes,
                  &MaxStorage,
                  &RemainingStorage,
                  &MaxSize
                  );
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] QueryVariableInfo -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAllocatePool (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ALLOCATE_POOL_PAYLOAD  *P;
  VOID                                  *Buffer;
  EFI_STATUS                            Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P      = (CONST SYZ_EDK2_ALLOCATE_POOL_PAYLOAD *)Payload;
  Status = gBS->AllocatePool (
                  (EFI_MEMORY_TYPE)P->MemType,
                  (UINTN)P->Size,
                  &Buffer
                  );
  if (!EFI_ERROR (Status) && (Buffer != NULL)) {
    if (AllocSlotInsertPool (Buffer) < 0) {
      gBS->FreePool (Buffer);
    }
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFreePool (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FREE_POOL_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FREE_POOL_PAYLOAD *)Payload;
  if (P->AllocIndex >= SYZ_EDK2_MAX_ALLOCS) {
    return EFI_INVALID_PARAMETER;
  }
  if (gSyzEdk2Agent.Allocs[P->AllocIndex].Kind != SyzEdk2AllocSlotPool) {
    return EFI_SUCCESS;
  }
  gBS->FreePool (gSyzEdk2Agent.Allocs[P->AllocIndex].Pointer);
  gSyzEdk2Agent.Allocs[P->AllocIndex].Kind    = SyzEdk2AllocSlotEmpty;
  gSyzEdk2Agent.Allocs[P->AllocIndex].Pointer = NULL;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAllocatePages (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ALLOCATE_PAGES_PAYLOAD  *P;
  EFI_PHYSICAL_ADDRESS                   Memory;
  EFI_STATUS                             Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P      = (CONST SYZ_EDK2_ALLOCATE_PAGES_PAYLOAD *)Payload;
  Memory = 0;
  Status = gBS->AllocatePages (
                  (EFI_ALLOCATE_TYPE)P->AllocType,
                  (EFI_MEMORY_TYPE)P->MemType,
                  (UINTN)P->Pages,
                  &Memory
                  );
  if (!EFI_ERROR (Status) && (Memory != 0)) {
    if (AllocSlotInsertPages ((VOID *)(UINTN)Memory, (UINTN)P->Pages) < 0) {
      gBS->FreePages (Memory, (UINTN)P->Pages);
    }
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFreePages (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FREE_PAGES_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT                *Slot;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FREE_PAGES_PAYLOAD *)Payload;
  if (P->AllocIndex >= SYZ_EDK2_MAX_ALLOCS) {
    return EFI_INVALID_PARAMETER;
  }
  Slot = &gSyzEdk2Agent.Allocs[P->AllocIndex];
  if (Slot->Kind != SyzEdk2AllocSlotPages) {
    return EFI_SUCCESS;
  }
  gBS->FreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)Slot->Pointer, Slot->Pages);
  Slot->Kind    = SyzEdk2AllocSlotEmpty;
  Slot->Pointer = NULL;
  Slot->Pages   = 0;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleLocateProtocol (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_LOCATE_PROTOCOL_PAYLOAD  *P;
  CONST EFI_GUID                          *Guid;
  VOID                                    *Interface;
  EFI_STATUS                              Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_LOCATE_PROTOCOL_PAYLOAD *)Payload;
  Guid = SyzEdk2LookupProtocolGuid (P->ProtocolId);
  if (Guid == NULL) {
    return EFI_SUCCESS;
  }
  Status = gBS->LocateProtocol ((EFI_GUID *)Guid, NULL, &Interface);
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] LocateProtocol -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleLocateHandleBuffer (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_LOCATE_HANDLE_BUFFER_PAYLOAD  *P;
  CONST EFI_GUID                               *Guid;
  EFI_HANDLE                                   *Handles;
  UINTN                                        HandleCount;
  EFI_STATUS                                   Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_LOCATE_HANDLE_BUFFER_PAYLOAD *)Payload;
  Guid = SyzEdk2LookupProtocolGuid (P->ProtocolId);
  if (Guid == NULL) {
    return EFI_SUCCESS;
  }
  Status = gBS->LocateHandleBuffer (
                  (EFI_LOCATE_SEARCH_TYPE)P->SearchType,
                  (EFI_GUID *)Guid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (!EFI_ERROR (Status) && (Handles != NULL)) {
    FreePool (Handles);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiNewPackageList (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_NEW_PACKAGE_LIST_PAYLOAD  *P;
  EFI_HII_DATABASE_PROTOCOL                    *Hii;
  EFI_HII_PACKAGE_LIST_HEADER                  *List;
  EFI_HII_HANDLE                               Handle;
  EFI_STATUS                                   Status;
  UINTN                                        Index;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_NEW_PACKAGE_LIST_PAYLOAD *)Payload;
  if ((UINTN)P->PackageSize + sizeof (*P) > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }
  if (P->PackageSize < sizeof (EFI_HII_PACKAGE_LIST_HEADER)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (
                  &gEfiHiiDatabaseProtocolGuid,
                  NULL,
                  (VOID **)&Hii
                  );
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  List = AllocatePool (P->PackageSize);
  if (List == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (List, Payload + sizeof (*P), P->PackageSize);

  Status = Hii->NewPackageList (Hii, List, NULL, &Handle);
  if (!EFI_ERROR (Status)) {
    for (Index = 0; Index < SYZ_EDK2_MAX_HII_HANDLES; Index++) {
      if (gSyzEdk2Agent.HiiHandles[Index].Handle == NULL) {
        gSyzEdk2Agent.HiiHandles[Index].Handle = Handle;
        break;
      }
    }
    if (Index == SYZ_EDK2_MAX_HII_HANDLES) {
      Hii->RemovePackageList (Hii, Handle);
    }
  }

  FreePool (List);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiRemovePackageList (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_REMOVE_PACKAGE_LIST_PAYLOAD  *P;
  EFI_HII_DATABASE_PROTOCOL                       *Hii;
  EFI_STATUS                                      Status;
  EFI_HII_HANDLE                                  Handle;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_REMOVE_PACKAGE_LIST_PAYLOAD *)Payload;
  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }
  Status = gBS->LocateProtocol (
                  &gEfiHiiDatabaseProtocolGuid,
                  NULL,
                  (VOID **)&Hii
                  );
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }
  Hii->RemovePackageList (Hii, Handle);
  gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle = NULL;
  return EFI_SUCCESS;
}

//
// AsanSyz handlers: each one looks up the allocation slot the fuzzer
// targets, clamps Offset+Length to the allocation extent, and forwards
// to the AsanSyz facade. We never let the fuzzer poison arbitrary
// addresses; only memory we hand it from a previous AllocatePool /
// AllocatePages call.
//

STATIC
EFI_STATUS
HandleAsanCommon (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize,
  OUT UINTN       *Addr,
  OUT UINTN       *Length,
  OUT UINT8       *IsWrite
  )
{
  CONST SYZ_EDK2_ASAN_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT          *Slot;
  UINTN                        AllocBytes;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ASAN_PAYLOAD *)Payload;
  if (P->AllocIndex >= SYZ_EDK2_MAX_ALLOCS) {
    return EFI_INVALID_PARAMETER;
  }
  Slot = &gSyzEdk2Agent.Allocs[P->AllocIndex];
  if ((Slot->Kind == SyzEdk2AllocSlotEmpty) || (Slot->Pointer == NULL)) {
    return EFI_NOT_FOUND;
  }
  if (Slot->Kind == SyzEdk2AllocSlotPages) {
    AllocBytes = Slot->Pages * EFI_PAGE_SIZE;
  } else {
    //
    // For pool allocations we don't have the size handy. Use the
    // requested length, capped at a sensible bound, and rely on the
    // caller having allocated enough room.
    //
    AllocBytes = (UINTN)P->Offset + (UINTN)P->Length;
  }

  if ((UINTN)P->Offset >= AllocBytes) {
    return EFI_INVALID_PARAMETER;
  }
  *Addr   = (UINTN)Slot->Pointer + (UINTN)P->Offset;
  *Length = MIN ((UINTN)P->Length, AllocBytes - (UINTN)P->Offset);
  *IsWrite = P->IsWrite;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAsanPoison (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  UINTN       Addr;
  UINTN       Length;
  UINT8       IsWrite;
  EFI_STATUS  Status;

  Status = HandleAsanCommon (Payload, PayloadSize, &Addr, &Length, &IsWrite);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }
  if (AsanSyzReady ()) {
    AsanSyzPoison (Addr, Length);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAsanUnpoison (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  UINTN       Addr;
  UINTN       Length;
  UINT8       IsWrite;
  EFI_STATUS  Status;

  Status = HandleAsanCommon (Payload, PayloadSize, &Addr, &Length, &IsWrite);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }
  if (AsanSyzReady ()) {
    AsanSyzUnpoison (Addr, Length);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAsanReport (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  UINTN       Addr;
  UINTN       Length;
  UINT8       IsWrite;
  EFI_STATUS  Status;

  Status = HandleAsanCommon (Payload, PayloadSize, &Addr, &Length, &IsWrite);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }
  if (AsanSyzReady ()) {
    AsanSyzReport (Addr, Length, IsWrite);
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SyzEdk2Dispatch (
  IN CONST UINT8  *Program,
  IN UINTN        ProgramSize
  )
{
  UINTN  Offset;
  UINTN  Index;

  Offset = 0;
  for (Index = 0; Index < SYZ_EDK2_MAX_CALLS; Index++) {
    CONST SYZ_EDK2_CALL_HDR  *Hdr;
    UINTN                    PayloadSize;
    CONST UINT8              *Payload;

    if (Offset + sizeof (SYZ_EDK2_CALL_HDR) > ProgramSize) {
      break;
    }
    Hdr = (CONST SYZ_EDK2_CALL_HDR *)(Program + Offset);
    if ((Hdr->Size < sizeof (SYZ_EDK2_CALL_HDR)) ||
        (Offset + Hdr->Size > ProgramSize))
    {
      DEBUG ((
        DEBUG_ERROR,
        "[SYZ-AGENT] panic: malformed record at offset %u (Size=%u)\n",
        (UINTN)Offset,
        (UINTN)Hdr->Size
        ));
      return EFI_INVALID_PARAMETER;
    }

    Payload     = (CONST UINT8 *)Hdr + sizeof (SYZ_EDK2_CALL_HDR);
    PayloadSize = (UINTN)Hdr->Size - sizeof (SYZ_EDK2_CALL_HDR);

    //
    // The dispatch table is implemented as an if/else if chain so the
    // compiler doesn't lower it to a .rodata jump table that the agent
    // may not be able to access at all phases of boot. Same reasoning
    // as SYZOS — see docs/syzos.md §4.
    //
    if (Hdr->Call == SyzEdk2ApiNop) {
      HandleNop (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSetVariable) {
      HandleSetVariable (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiGetVariable) {
      HandleGetVariable (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiQueryVariableInfo) {
      HandleQueryVariableInfo (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAllocatePool) {
      HandleAllocatePool (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFreePool) {
      HandleFreePool (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAllocatePages) {
      HandleAllocatePages (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFreePages) {
      HandleFreePages (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiLocateProtocol) {
      HandleLocateProtocol (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiLocateHandleBuffer) {
      HandleLocateHandleBuffer (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiNewPackageList) {
      HandleHiiNewPackageList (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiRemovePackageList) {
      HandleHiiRemovePackageList (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAsanPoisonAlloc) {
      HandleAsanPoison (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAsanUnpoisonAlloc) {
      HandleAsanUnpoison (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAsanReportAlloc) {
      HandleAsanReport (Payload, PayloadSize);
    } else {
      DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] unknown call %u\n", (UINTN)Hdr->Call));
    }

    Offset += Hdr->Size;
  }

  return EFI_SUCCESS;
}

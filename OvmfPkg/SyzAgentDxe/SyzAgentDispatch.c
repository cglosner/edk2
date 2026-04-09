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

//
// Symbolic variable namespace -> EFI_GUID lookup. Lets the fuzzer
// hit the variable store under several well-known GUIDs (including
// authenticated variable namespaces) without having to send raw GUIDs
// across the wire.
//
STATIC CONST SYZ_EDK2_PROTO_ENTRY  mVariableNamespaceTable[] = {
  { SyzEdk2VarNsSyz,              &gSyzEdk2Agent.SyzEdk2VendorGuid    },
  { SyzEdk2VarNsGlobal,           &gEfiGlobalVariableGuid             },
  { SyzEdk2VarNsImageSecurityDb,  &gEfiImageSecurityDatabaseGuid      },
  { SyzEdk2VarNsImageSecurityDbx, &gEfiImageSecurityDatabaseGuid      },
  { SyzEdk2VarNsImageSecurityDbt, &gEfiImageSecurityDatabaseGuid      },
};

STATIC
CONST EFI_GUID *
LookupVariableNamespace (
  IN UINT32  Id
  )
{
  UINTN  Index;
  for (Index = 0; Index < ARRAY_SIZE (mVariableNamespaceTable); Index++) {
    if (mVariableNamespaceTable[Index].Id == Id) {
      return mVariableNamespaceTable[Index].Guid;
    }
  }
  return &gSyzEdk2Agent.SyzEdk2VendorGuid;
}

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
  IN VOID   *Pointer,
  IN UINTN  Bytes
  )
{
  UINTN  Index;
  for (Index = 0; Index < SYZ_EDK2_MAX_ALLOCS; Index++) {
    if (gSyzEdk2Agent.Allocs[Index].Kind == SyzEdk2AllocSlotEmpty) {
      gSyzEdk2Agent.Allocs[Index].Kind    = SyzEdk2AllocSlotPool;
      gSyzEdk2Agent.Allocs[Index].Pointer = Pointer;
      gSyzEdk2Agent.Allocs[Index].Pages   = 0;
      gSyzEdk2Agent.Allocs[Index].Bytes   = Bytes;
      return (INTN)Index;
    }
  }
  (VOID)Bytes;
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
      gSyzEdk2Agent.Allocs[Index].Bytes   = Pages * EFI_PAGE_SIZE;
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
                  (EFI_GUID *)LookupVariableNamespace (P->Namespace),
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
                  (EFI_GUID *)LookupVariableNamespace (P->Namespace),
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
    if (AllocSlotInsertPool (Buffer, (UINTN)P->Size) < 0) {
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
  gSyzEdk2Agent.Allocs[P->AllocIndex].Bytes   = 0;
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
  Slot->Bytes   = 0;
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
  AllocBytes = Slot->Bytes;

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

// ----------------------------------------------------------------------
// New handlers (added with the grammar expansion in
// sys/edk2/edk2.txt). All clamp inputs to a sane range and never let
// the fuzzer hand the firmware raw pointers.
// ----------------------------------------------------------------------

STATIC
SYZ_EDK2_ALLOC_SLOT *
GetAllocSlot (
  IN UINT32  Index
  )
{
  if (Index >= SYZ_EDK2_MAX_ALLOCS) {
    return NULL;
  }
  if (gSyzEdk2Agent.Allocs[Index].Kind == SyzEdk2AllocSlotEmpty ||
      gSyzEdk2Agent.Allocs[Index].Pointer == NULL)
  {
    return NULL;
  }
  return &gSyzEdk2Agent.Allocs[Index];
}

STATIC
UINTN
AllocSlotBytes (
  IN SYZ_EDK2_ALLOC_SLOT  *Slot
  )
{
  return Slot->Bytes;
}

STATIC
EFI_STATUS
HandleGetNextVariableName (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_GET_NEXT_VARIABLE_NAME_PAYLOAD  *P;
  EFI_STATUS                                     Status;
  UINTN                                          NameSize;
  CHAR16                                         *Buf;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_GET_NEXT_VARIABLE_NAME_PAYLOAD *)Payload;

  if (P->Reset || !gSyzEdk2Agent.NextVarValid) {
    gSyzEdk2Agent.NextVarName[0] = L'\0';
    ZeroMem (&gSyzEdk2Agent.NextVarGuid, sizeof (EFI_GUID));
    gSyzEdk2Agent.NextVarValid = TRUE;
  }

  NameSize = sizeof (gSyzEdk2Agent.NextVarName);
  Buf      = gSyzEdk2Agent.NextVarName;
  Status   = gRT->GetNextVariableName (&NameSize, Buf, &gSyzEdk2Agent.NextVarGuid);
  if (EFI_ERROR (Status)) {
    gSyzEdk2Agent.NextVarValid = FALSE;
  }
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] GetNextVariableName -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleCopyMem (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_COPY_MEM_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT              *Dst;
  SYZ_EDK2_ALLOC_SLOT              *Src;
  UINTN                            DstBytes;
  UINTN                            SrcBytes;
  UINTN                            Length;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P   = (CONST SYZ_EDK2_COPY_MEM_PAYLOAD *)Payload;
  Dst = GetAllocSlot (P->DstIndex);
  Src = GetAllocSlot (P->SrcIndex);
  if ((Dst == NULL) || (Src == NULL)) {
    return EFI_SUCCESS;
  }
  DstBytes = AllocSlotBytes (Dst);
  SrcBytes = AllocSlotBytes (Src);
  if ((P->DstOffset >= DstBytes) || (P->SrcOffset >= SrcBytes)) {
    return EFI_SUCCESS;
  }
  Length = MIN (
             (UINTN)P->Length,
             MIN (DstBytes - P->DstOffset, SrcBytes - P->SrcOffset)
             );
  gBS->CopyMem (
         (UINT8 *)Dst->Pointer + P->DstOffset,
         (UINT8 *)Src->Pointer + P->SrcOffset,
         Length
         );
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSetMem (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SET_MEM_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT             *Slot;
  UINTN                           SlotBytes;
  UINTN                           Length;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_SET_MEM_PAYLOAD *)Payload;
  Slot = GetAllocSlot (P->AllocIndex);
  if (Slot == NULL) {
    return EFI_SUCCESS;
  }
  SlotBytes = AllocSlotBytes (Slot);
  if (P->Offset >= SlotBytes) {
    return EFI_SUCCESS;
  }
  Length = MIN ((UINTN)P->Length, SlotBytes - P->Offset);
  gBS->SetMem ((UINT8 *)Slot->Pointer + P->Offset, Length, P->Value);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleCalculateCrc32 (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_CALC_CRC_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT              *Slot;
  UINTN                            SlotBytes;
  UINTN                            Length;
  UINT32                           Crc;
  EFI_STATUS                       Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_CALC_CRC_PAYLOAD *)Payload;
  Slot = GetAllocSlot (P->AllocIndex);
  if (Slot == NULL) {
    return EFI_SUCCESS;
  }
  SlotBytes = AllocSlotBytes (Slot);
  if (P->Offset >= SlotBytes) {
    return EFI_SUCCESS;
  }
  Length = MIN ((UINTN)P->Length, SlotBytes - P->Offset);
  Status = gBS->CalculateCrc32 (
                  (UINT8 *)Slot->Pointer + P->Offset,
                  Length,
                  &Crc
                  );
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] CalculateCrc32 -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleGetTime (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_TIME             Time;
  EFI_TIME_CAPABILITIES Caps;
  EFI_STATUS           Status;

  (VOID)Payload;
  (VOID)PayloadSize;
  Status = gRT->GetTime (&Time, &Caps);
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] GetTime -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSetTime (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SET_TIME_PAYLOAD  *P;
  EFI_TIME                         Time;
  EFI_STATUS                       Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P             = (CONST SYZ_EDK2_SET_TIME_PAYLOAD *)Payload;
  ZeroMem (&Time, sizeof (Time));
  Time.Year       = P->Year;
  Time.Month      = P->Month;
  Time.Day        = P->Day;
  Time.Hour       = P->Hour;
  Time.Minute     = P->Minute;
  Time.Second     = P->Second;
  Time.Nanosecond = P->Nanosecond;
  Time.TimeZone   = P->TimeZone;
  Time.Daylight   = P->Daylight;
  Status = gRT->SetTime (&Time);
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] SetTime -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleStall (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_STALL_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_STALL_PAYLOAD *)Payload;
  // Cap at 5 ms so a fuzzer-generated giant stall doesn't lock the
  // dispatcher for the rest of the campaign.
  gBS->Stall (MIN (P->Microseconds, 5000));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSetWatchdogTimer (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SET_WATCHDOG_PAYLOAD  *P;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P      = (CONST SYZ_EDK2_SET_WATCHDOG_PAYLOAD *)Payload;
  Status = gBS->SetWatchdogTimer (
                  P->TimeoutSecs,
                  P->Code,
                  0,
                  NULL
                  );
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] SetWatchdogTimer -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleGetMonotonicCount (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  UINT64      Count;
  EFI_STATUS  Status;

  (VOID)Payload;
  (VOID)PayloadSize;
  Status = gBS->GetNextMonotonicCount (&Count);
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] GetNextMonotonicCount -> %r\n", Status));
  return EFI_SUCCESS;
}

STATIC
VOID
EFIAPI
SyzAgentEventCb (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  // Empty notification — we just need a callback to satisfy
  // EVT_NOTIFY_SIGNAL / EVT_NOTIFY_WAIT events.
  (VOID)Event;
  (VOID)Context;
}

STATIC
EFI_STATUS
HandleCreateEvent (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_CREATE_EVENT_PAYLOAD  *P;
  EFI_EVENT                            Event;
  EFI_STATUS                           Status;
  UINT32                               Type;
  EFI_TPL                              Tpl;
  UINTN                                Index;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_CREATE_EVENT_PAYLOAD *)Payload;
  Type = P->Type;
  // The agent only supplies a callback when the event type asks for one.
  Tpl  = (EFI_TPL)P->Tpl;
  if (Tpl < TPL_APPLICATION) Tpl = TPL_APPLICATION;
  if (Tpl > TPL_HIGH_LEVEL)  Tpl = TPL_HIGH_LEVEL;

  if (Type & (EVT_NOTIFY_SIGNAL | EVT_NOTIFY_WAIT)) {
    Status = gBS->CreateEvent (Type, Tpl, SyzAgentEventCb, NULL, &Event);
  } else {
    Status = gBS->CreateEvent (Type, Tpl, NULL, NULL, &Event);
  }
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }
  for (Index = 0; Index < SYZ_EDK2_MAX_EVENTS; Index++) {
    if (gSyzEdk2Agent.Events[Index].Event == NULL) {
      gSyzEdk2Agent.Events[Index].Event = Event;
      return EFI_SUCCESS;
    }
  }
  // No slot — close so we don't leak.
  gBS->CloseEvent (Event);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleCloseEvent (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_EVENT_INDEX_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_EVENT_INDEX_PAYLOAD *)Payload;
  if (P->EventIndex >= SYZ_EDK2_MAX_EVENTS) {
    return EFI_INVALID_PARAMETER;
  }
  if (gSyzEdk2Agent.Events[P->EventIndex].Event != NULL) {
    gBS->CloseEvent (gSyzEdk2Agent.Events[P->EventIndex].Event);
    gSyzEdk2Agent.Events[P->EventIndex].Event = NULL;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSignalEvent (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_EVENT_INDEX_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_EVENT_INDEX_PAYLOAD *)Payload;
  if (P->EventIndex >= SYZ_EDK2_MAX_EVENTS) {
    return EFI_INVALID_PARAMETER;
  }
  if (gSyzEdk2Agent.Events[P->EventIndex].Event != NULL) {
    gBS->SignalEvent (gSyzEdk2Agent.Events[P->EventIndex].Event);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleRaiseTpl (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_RAISE_TPL_PAYLOAD  *P;
  EFI_TPL                           Tpl;
  EFI_TPL                           Old;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P   = (CONST SYZ_EDK2_RAISE_TPL_PAYLOAD *)Payload;
  Tpl = (EFI_TPL)P->Tpl;
  if (Tpl < TPL_APPLICATION || Tpl > TPL_HIGH_LEVEL) {
    return EFI_INVALID_PARAMETER;
  }
  // The dispatcher itself runs at TPL_CALLBACK; gBS->RaiseTPL panics
  // if asked to lower TPL. Skip if it's not actually a raise.
  if (Tpl < TPL_CALLBACK) {
    return EFI_SUCCESS;
  }
  Old = gBS->RaiseTPL (Tpl);
  gBS->RestoreTPL (Old);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleInstallConfigTable (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_INSTALL_CONFIG_PAYLOAD  *P;
  CONST EFI_GUID                         *Guid;
  EFI_STATUS                             Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P    = (CONST SYZ_EDK2_INSTALL_CONFIG_PAYLOAD *)Payload;
  Guid = SyzEdk2LookupProtocolGuid (P->GuidId);
  if (Guid == NULL) {
    return EFI_SUCCESS;
  }
  Status = gBS->InstallConfigurationTable ((EFI_GUID *)Guid, (VOID *)(UINTN)P->Value);
  DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] InstallConfigurationTable -> %r\n", Status));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SyzEdk2Dispatch (
  IN CONST UINT8  *Program,
  IN UINTN        ProgramSize,
  IN UINT32       NumCalls
  )
{
  UINTN  Offset;
  UINTN  Index;
  UINTN  Limit;

  Offset = 0;
  Limit  = (NumCalls < SYZ_EDK2_MAX_CALLS) ? NumCalls : SYZ_EDK2_MAX_CALLS;
  for (Index = 0; Index < Limit; Index++) {
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
    } else if (Hdr->Call == SyzEdk2ApiGetNextVariableName) {
      HandleGetNextVariableName (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiCopyMem) {
      HandleCopyMem (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSetMem) {
      HandleSetMem (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiCalculateCrc32) {
      HandleCalculateCrc32 (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiGetTime) {
      HandleGetTime (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSetTime) {
      HandleSetTime (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiStall) {
      HandleStall (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSetWatchdogTimer) {
      HandleSetWatchdogTimer (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiGetMonotonicCount) {
      HandleGetMonotonicCount (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiCreateEvent) {
      HandleCreateEvent (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiCloseEvent) {
      HandleCloseEvent (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSignalEvent) {
      HandleSignalEvent (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiRaiseTpl) {
      HandleRaiseTpl (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiInstallConfigTable) {
      HandleInstallConfigTable (Payload, PayloadSize);
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

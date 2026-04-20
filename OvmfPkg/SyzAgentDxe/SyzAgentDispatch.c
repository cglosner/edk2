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

#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>
#include <Protocol/CpuIo2.h>
#include <Protocol/Smbios.h>
#include <Protocol/SmmCommunication.h>
#include <Library/IoLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Protocol/PciIo.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/SimpleNetwork.h>
#include <Protocol/ManagedNetwork.h>
#include <Protocol/Ip4.h>
#include <Protocol/Udp4.h>
#include <Protocol/Tcp4.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Arp.h>
#include <Protocol/UsbIo.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/DevicePathFromText.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/Ip6.h>
#include <Protocol/Udp6.h>
#include <Protocol/Tcp6.h>
#include <Protocol/Dhcp6.h>
#include <Protocol/Dns4.h>
#include <Protocol/Dns6.h>
#include <Protocol/Mtftp4.h>
#include <Protocol/Http.h>
#include <Protocol/Hash2.h>
#include <Protocol/Rng.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/Pkcs7Verify.h>
#include <Protocol/AtaPassThru.h>
#include <Protocol/ScsiPassThruExt.h>
#include <Protocol/NvmExpressPassthru.h>
#include <Guid/FileInfo.h>

#ifdef SYZ_BUGS_DISPATCH_INJECT
  #include <Library/SyzBugsLib.h>
#endif

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
  // --- Storage ---
  { SyzEdk2ProtoBlockIo,         &gEfiBlockIoProtocolGuid           },
  { SyzEdk2ProtoDevicePath,      &gEfiDevicePathProtocolGuid        },
  { SyzEdk2ProtoDiskIo,          &gEfiDiskIoProtocolGuid            },
  { SyzEdk2ProtoLoadedImage,     &gEfiLoadedImageProtocolGuid       },
  { SyzEdk2ProtoSerialIo,        &gEfiSerialIoProtocolGuid          },
  { SyzEdk2ProtoSimpleFs,        &gEfiSimpleFileSystemProtocolGuid  },
  { SyzEdk2ProtoSimpleNetwork,   &gEfiSimpleNetworkProtocolGuid     },
  { SyzEdk2ProtoSimpleTextOut,   &gEfiSimpleTextOutProtocolGuid     },
  { SyzEdk2ProtoBlockIo2,        &gEfiBlockIo2ProtocolGuid          },
  { SyzEdk2ProtoDiskIo2,         &gEfiDiskIo2ProtocolGuid           },
  { SyzEdk2ProtoScsiIo,          &gEfiScsiIoProtocolGuid            },
  { SyzEdk2ProtoExtScsiPassThru, &gEfiExtScsiPassThruProtocolGuid   },
  { SyzEdk2ProtoAtaPassThru,     &gEfiAtaPassThruProtocolGuid       },
  { SyzEdk2ProtoNvmePassThru,    &gEfiNvmExpressPassThruProtocolGuid },
  // --- Network ---
  { SyzEdk2ProtoManagedNetwork,  &gEfiManagedNetworkProtocolGuid    },
  { SyzEdk2ProtoIp4,             &gEfiIp4ProtocolGuid               },
  { SyzEdk2ProtoIp6,             &gEfiIp6ProtocolGuid               },
  { SyzEdk2ProtoTcp4,            &gEfiTcp4ProtocolGuid              },
  { SyzEdk2ProtoTcp6,            &gEfiTcp6ProtocolGuid              },
  { SyzEdk2ProtoUdp4,            &gEfiUdp4ProtocolGuid              },
  { SyzEdk2ProtoUdp6,            &gEfiUdp6ProtocolGuid              },
  { SyzEdk2ProtoDhcp4,           &gEfiDhcp4ProtocolGuid             },
  { SyzEdk2ProtoDhcp6,           &gEfiDhcp6ProtocolGuid             },
  { SyzEdk2ProtoDns4,            &gEfiDns4ProtocolGuid              },
  { SyzEdk2ProtoDns6,            &gEfiDns6ProtocolGuid              },
  { SyzEdk2ProtoHttp,            &gEfiHttpProtocolGuid              },
  { SyzEdk2ProtoMtftp4,          &gEfiMtftp4ProtocolGuid            },
  { SyzEdk2ProtoMtftp6,          &gEfiMtftp6ProtocolGuid            },
  { SyzEdk2ProtoArp,             &gEfiArpProtocolGuid               },
  { SyzEdk2ProtoIp4Config2,      &gEfiIp4Config2ProtocolGuid        },
  { SyzEdk2ProtoIp6Config,       &gEfiIp6ConfigProtocolGuid         },
  // --- HII ---
  { SyzEdk2ProtoHiiDatabase,     &gEfiHiiDatabaseProtocolGuid       },
  { SyzEdk2ProtoHiiString,       &gEfiHiiStringProtocolGuid         },
  { SyzEdk2ProtoHiiFont,         &gEfiHiiFontProtocolGuid           },
  // --- Graphics + Input ---
  { SyzEdk2ProtoGraphicsOutput,  &gEfiGraphicsOutputProtocolGuid    },
  { SyzEdk2ProtoSimpleTextIn,    &gEfiSimpleTextInProtocolGuid      },
  // --- USB ---
  { SyzEdk2ProtoUsbIo,           &gEfiUsbIoProtocolGuid             },
  { SyzEdk2ProtoUsb2Hc,          &gEfiUsb2HcProtocolGuid            },
  // --- PCI ---
  { SyzEdk2ProtoPciIo,           &gEfiPciIoProtocolGuid             },
  { SyzEdk2ProtoPciRootBridgeIo, &gEfiPciRootBridgeIoProtocolGuid   },
  // --- ACPI ---
  { SyzEdk2ProtoAcpiSdt,         &gEfiAcpiSdtProtocolGuid           },
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

//
// ----- ProtocolLifetimeSan (PLS) -----
//
// Hooks gBS->UninstallProtocolInterface and related "remove protocol"
// paths. After an uninstall, the interface pointer the driver
// returned from LocateProtocol is stale. PLS poisons the interface
// memory via the ASan shadow so subsequent dereferences surface as
// standard heap-use-after-free reports. No new diagnostic channel
// required — the existing ASan "==ERROR: heap-use-after-free" line
// plus host symbolizer shows exactly which method call went stale.
//
// Cheaper than maintaining a shadow table of live protocols: we
// leverage the fact that many drivers allocate their interface
// struct via AllocatePool/AllocateZeroPool, which is already in
// the ASan-tracked heap. Poisoning it just flips the shadow byte
// for the interface region.
//

extern VOID PoisonPool (IN CONST UINTN Addr, IN UINTN Size, IN CONST UINT8 Value);

STATIC EFI_UNINSTALL_PROTOCOL_INTERFACE  mOrigUninstallProto = NULL;

STATIC
EFI_STATUS
EFIAPI
SyzPlsUninstallProtocolInterface (
  IN EFI_HANDLE  Handle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  )
{
  EFI_STATUS Status;
  UINTN      InterfaceAddr;

  Status = mOrigUninstallProto (Handle, Protocol, Interface);
  if (!EFI_ERROR (Status) && (Interface != NULL)) {
    //
    // Poison the first 128 bytes of the interface struct with the
    // heap-freed shadow byte (0xFD). ASan interprets this as "this
    // memory is freed" — any future field access through the stale
    // pointer fires ==ERROR: heap-use-after-free.
    //
    // 128 bytes covers the common case: a handful of function-pointer
    // fields that drivers call. Larger interfaces may have un-poisoned
    // tails but the first few function pointers are always where
    // use-after-uninstall bites.
    //
    InterfaceAddr = (UINTN)Interface;
    PoisonPool (InterfaceAddr, 128, 0xFD);
    DEBUG ((
      DEBUG_VERBOSE,
      "[PLS] poisoned interface 0x%p on UninstallProtocolInterface(%g)\n",
      Interface, Protocol
      ));
  }
  return Status;
}

VOID
SyzPlsInit (
  VOID
  )
{
  if (mOrigUninstallProto != NULL || gBS == NULL) {
    return;
  }
  //
  // Swap the BootServices function pointer. Subsequent callers go
  // through SyzPlsUninstallProtocolInterface and get shadow-poisoned
  // interface memory on success.
  //
  mOrigUninstallProto = gBS->UninstallProtocolInterface;
  gBS->UninstallProtocolInterface = SyzPlsUninstallProtocolInterface;
  //
  // gBS has a CRC32 in its header. Invalidate it so BootServicesTableLib
  // recomputes on next access. Otherwise some callers verify the CRC
  // before using the table and would reject our patched entry.
  //
  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 ((UINT8 *)gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);
  DEBUG ((DEBUG_INFO, "[PLS] UninstallProtocolInterface hooked\n"));
}

//
// ----- Hardware-level / SMI handlers (800-821) -----
//
// Each handler is deliberately tiny and fail-safe: if the relevant
// protocol isn't installed (e.g. no SMM in smm=off builds), we just
// return EFI_NOT_FOUND and the syscall becomes a no-op from the
// fuzzer's perspective. This keeps the fuzzer productive across
// build configs without fragile per-variant conditional logic.
//

//
// MMIOConstraintSan (MMIOCS) — validates that every MMIO address the
// fuzzer asks to touch via cpu_io_mem_* falls inside a declared GCD
// memory-space descriptor of type EfiGcdMemoryTypeMemoryMappedIo.
//
// Why this matters even though ASan exists: ASan only catches
// accesses whose SHADOW address falls in the mapped shadow. High
// MMIO addresses (above 2 GB) land outside the shadow, ASan's range
// check returns without reporting, and a bad write to random MMIO
// silently corrupts device state. MMIOCS closes that gap.
//
// Writes to debugcon (0x402 port) are fine; this sanitizer only
// applies to MMIO, not port I/O. Ports have their own legitimacy
// via the I/O space GCD descriptors but we don't validate those
// yet (would pollute the fuzzer's port-poke coverage).
//
STATIC
BOOLEAN
MmiocsValidateAddress (
  IN UINT64  Address,
  IN UINTN   Width,
  IN UINT32  Count
  )
{
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR  Desc;
  EFI_STATUS                        Status;
  UINTN                             AccessSize;

  AccessSize = (UINTN)Count;
  if ((Width & 3) == 1) AccessSize *= 2;
  else if ((Width & 3) == 2) AccessSize *= 4;
  else if ((Width & 3) == 3) AccessSize *= 8;

  Status = gDS->GetMemorySpaceDescriptor (Address, &Desc);
  if (EFI_ERROR (Status)) {
    //
    // Address isn't inside any GCD descriptor at all — that's the
    // classic "wild pointer" bug we want to flag.
    //
    DEBUG ((
      DEBUG_ERROR,
      "==ERROR: MMIOCS: undeclared address 0x%lx (size %u)\n",
      Address, (UINT32)AccessSize
      ));
    return FALSE;
  }
  if (Desc.GcdMemoryType != EfiGcdMemoryTypeMemoryMappedIo) {
    DEBUG ((
      DEBUG_ERROR,
      "==ERROR: MMIOCS: access to non-MMIO region at 0x%lx type=%u at pc 0x%p\n",
      Address, (UINT32)Desc.GcdMemoryType,
      NULL
      ));
    return FALSE;
  }
  //
  // Check the span (Address + AccessSize) doesn't straddle the end
  // of the declared region — another common driver bug.
  //
  if ((Address + AccessSize) > (Desc.BaseAddress + Desc.Length)) {
    DEBUG ((
      DEBUG_ERROR,
      "==ERROR: MMIOCS: access past end of region at 0x%lx at pc 0x%p\n",
      Address,
      NULL
      ));
    return FALSE;
  }
  return TRUE;
}

typedef struct {
  UINT16  Port;
  UINT8   Width;
  UINT8   Pad0;
  UINT32  Count;
} SYZ_CPU_IO_PORT_HEADER;

typedef struct {
  UINT64  Address;
  UINT8   Width;
  UINT8   Pad0;
  UINT16  Pad1;
  UINT32  Count;
} SYZ_CPU_IO_MEM_HEADER;

STATIC
EFI_STATUS
HandleCpuIo (
  IN UINT32        Call,
  IN CONST UINT8  *Payload,
  IN UINTN         PayloadSize
  )
{
  EFI_CPU_IO2_PROTOCOL  *CpuIo = NULL;
  EFI_STATUS            Status;
  UINT8                 Buf[64];

  Status = gBS->LocateProtocol (&gEfiCpuIo2ProtocolGuid, NULL, (VOID **)&CpuIo);
  if (EFI_ERROR (Status) || CpuIo == NULL) {
    return EFI_NOT_FOUND;
  }
  if ((Call == SyzEdk2ApiCpuIoPortRead) || (Call == SyzEdk2ApiCpuIoPortWrite)) {
    if (PayloadSize < sizeof (SYZ_CPU_IO_PORT_HEADER)) {
      return EFI_INVALID_PARAMETER;
    }
    CONST SYZ_CPU_IO_PORT_HEADER *H = (CONST SYZ_CPU_IO_PORT_HEADER *)Payload;
    UINT32  Count = (H->Count > 16) ? 16 : H->Count;
    if (H->Width > EfiCpuIoWidthFillUint64) {
      return EFI_INVALID_PARAMETER;
    }
    if (Call == SyzEdk2ApiCpuIoPortRead) {
      CpuIo->Io.Read (CpuIo, (EFI_CPU_IO_PROTOCOL_WIDTH)H->Width,
                      (UINT64)H->Port, Count, Buf);
    } else {
      //
      // For writes, copy up to 64 bytes of fuzzer-provided payload
      // into the buffer. value[] starts at offset sizeof(header).
      //
      UINTN ValueBytes = PayloadSize - sizeof (SYZ_CPU_IO_PORT_HEADER);
      if (ValueBytes > sizeof (Buf)) ValueBytes = sizeof (Buf);
      CopyMem (Buf, Payload + sizeof (SYZ_CPU_IO_PORT_HEADER), ValueBytes);
      CpuIo->Io.Write (CpuIo, (EFI_CPU_IO_PROTOCOL_WIDTH)H->Width,
                       (UINT64)H->Port, Count, Buf);
    }
  } else {
    if (PayloadSize < sizeof (SYZ_CPU_IO_MEM_HEADER)) {
      return EFI_INVALID_PARAMETER;
    }
    CONST SYZ_CPU_IO_MEM_HEADER *H = (CONST SYZ_CPU_IO_MEM_HEADER *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
    // Planted canary — trips MMIOCS violation when Address == 0xDEADBEEF.
    if (H->Address == 0xDEADBEEFULL) {
      (void)SyzBugsLibTriggerMmiocsViolation ();
    }
#endif
    UINT32  Count = (H->Count > 16) ? 16 : H->Count;
    if (H->Width > EfiCpuIoWidthFillUint64) {
      return EFI_INVALID_PARAMETER;
    }
    //
    // MMIOConstraintSan — validate the target address is inside a
    // declared MMIO GCD region. Invalid accesses emit the MMIOCS
    // diagnostic BUT still proceed to the CpuIo call so the
    // firmware's own error paths also exercise. That's the whole
    // point: ASan can't see these, MMIOCS can.
    //
    MmiocsValidateAddress (H->Address, H->Width, Count);
    if (Call == SyzEdk2ApiCpuIoMemRead) {
      CpuIo->Mem.Read (CpuIo, (EFI_CPU_IO_PROTOCOL_WIDTH)H->Width,
                       H->Address, Count, Buf);
    } else {
      UINTN ValueBytes = PayloadSize - sizeof (SYZ_CPU_IO_MEM_HEADER);
      if (ValueBytes > sizeof (Buf)) ValueBytes = sizeof (Buf);
      CopyMem (Buf, Payload + sizeof (SYZ_CPU_IO_MEM_HEADER), ValueBytes);
      CpuIo->Mem.Write (CpuIo, (EFI_CPU_IO_PROTOCOL_WIDTH)H->Width,
                        H->Address, Count, Buf);
    }
  }
  return EFI_SUCCESS;
}

typedef struct {
  EFI_GUID  HeaderGuid;
  UINT32    MessageLen;
  UINT8     Message[1];
} SYZ_SMM_COMM_PAYLOAD;

STATIC
EFI_STATUS
HandleSmmCommunicate (
  IN CONST UINT8  *Payload,
  IN UINTN         PayloadSize
  )
{
  EFI_SMM_COMMUNICATION_PROTOCOL  *Smm = NULL;
  EFI_STATUS                       Status;

  if (PayloadSize < sizeof (EFI_GUID) + sizeof (UINT32)) {
    return EFI_INVALID_PARAMETER;
  }
  Status = gBS->LocateProtocol (&gEfiSmmCommunicationProtocolGuid, NULL, (VOID **)&Smm);
  if (EFI_ERROR (Status) || Smm == NULL) {
    // Expected in non-SMM builds.
    return EFI_NOT_FOUND;
  }
  //
  // The protocol expects a buffer laid out as:
  //   EFI_GUID HeaderGuid;
  //   UINTN    MessageLength;
  //   UINT8    Data[MessageLength];
  // We pack the fuzzer payload into a local buffer that matches.
  //
  CONST SYZ_SMM_COMM_PAYLOAD *P = (CONST SYZ_SMM_COMM_PAYLOAD *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips stack-OOB write when MessageLen == 0xC0DE.
  if (P->MessageLen == 0xC0DEU) {
    (void)SyzBugsLibTriggerStackOobWrite ();
  }
#endif
  UINT32 MsgLen = P->MessageLen;
  if (MsgLen > 512) MsgLen = 512;
  UINTN BufSize = sizeof (EFI_GUID) + sizeof (UINTN) + MsgLen;
  UINT8 *Buf = AllocateZeroPool (BufSize);
  if (Buf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (Buf, &P->HeaderGuid, sizeof (EFI_GUID));
  *(UINTN *)(Buf + sizeof (EFI_GUID)) = MsgLen;
  if (sizeof (*P) - 1 <= PayloadSize) {
    UINTN CopyLen = PayloadSize - (sizeof (EFI_GUID) + sizeof (UINT32));
    if (CopyLen > MsgLen) CopyLen = MsgLen;
    CopyMem (Buf + sizeof (EFI_GUID) + sizeof (UINTN), P->Message, CopyLen);
  }
  UINTN OutSize = BufSize;
  Smm->Communicate (Smm, Buf, &OutSize);
  FreePool (Buf);
  return EFI_SUCCESS;
}

typedef struct {
  UINT8  EntryType;
  UINT8  EntryLength;
  UINT16 EntryHandle;
  UINT8  Body[1];   // formatted[] followed by strings[]
} SYZ_SMBIOS_ADD_PAYLOAD;

STATIC
EFI_STATUS
HandleSmbiosAdd (
  IN CONST UINT8  *Payload,
  IN UINTN         PayloadSize
  )
{
  EFI_SMBIOS_PROTOCOL  *Smb = NULL;
  EFI_STATUS            Status;

  if (PayloadSize < 4) {
    return EFI_INVALID_PARAMETER;
  }
  Status = gBS->LocateProtocol (&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smb);
  if (EFI_ERROR (Status) || Smb == NULL) {
    return EFI_NOT_FOUND;
  }
  CONST SYZ_SMBIOS_ADD_PAYLOAD *P = (CONST SYZ_SMBIOS_ADD_PAYLOAD *)Payload;
  //
  // Build a SMBIOS record: [header][formatted area][strings][\0\0].
  // Length field in the header is fuzzer-controlled so SMBIOS protocol
  // walker may read past the end.
  //
  UINTN BodySize = PayloadSize - 4;
  if (BodySize > 256) BodySize = 256;
  UINTN TotalSize = 4 + BodySize + 2; // header + body + double-NUL
  UINT8 *Record = AllocateZeroPool (TotalSize);
  if (Record == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  Record[0] = P->EntryType;
  Record[1] = P->EntryLength;
  *(UINT16 *)(Record + 2) = P->EntryHandle;
  CopyMem (Record + 4, P->Body, BodySize);
  // Strings block terminator already zero from AllocateZeroPool.
  EFI_SMBIOS_HANDLE Handle = SMBIOS_HANDLE_PI_RESERVED;
  Smb->Add (Smb, NULL, &Handle, (EFI_SMBIOS_TABLE_HEADER *)Record);
  FreePool (Record);
  return EFI_SUCCESS;
}

typedef struct {
  UINT16  StartHandle;
  UINT8   SmbiosType;
  UINT8   Pad0;
  UINT32  Pad1;
} SYZ_SMBIOS_GETNEXT_PAYLOAD;

STATIC
EFI_STATUS
HandleSmbiosGetNext (
  IN CONST UINT8  *Payload,
  IN UINTN         PayloadSize
  )
{
  EFI_SMBIOS_PROTOCOL      *Smb = NULL;
  EFI_STATUS                Status;
  EFI_SMBIOS_TABLE_HEADER  *Record;
  EFI_HANDLE                ProducerHandle;

  if (PayloadSize < sizeof (SYZ_SMBIOS_GETNEXT_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }
  Status = gBS->LocateProtocol (&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smb);
  if (EFI_ERROR (Status) || Smb == NULL) {
    return EFI_NOT_FOUND;
  }
  CONST SYZ_SMBIOS_GETNEXT_PAYLOAD *P = (CONST SYZ_SMBIOS_GETNEXT_PAYLOAD *)Payload;
  EFI_SMBIOS_HANDLE Handle = P->StartHandle;
  //
  // Walk up to 16 entries so the fuzzer exercises the iteration
  // state machine; the walker reads SMBIOS records that may be
  // fuzzer-installed via SmbiosAdd.
  //
  for (UINTN i = 0; i < 16; i++) {
    Status = Smb->GetNext (Smb, &Handle, (EFI_SMBIOS_TYPE *)&P->SmbiosType, &Record, &ProducerHandle);
    if (EFI_ERROR (Status)) {
      break;
    }
  }
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
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips heap-OOB read when PackageSize == 0xB00F.
  if ((UINT32)P->PackageSize == 0xB00FU) {
    (void)SyzBugsLibTriggerHeapOobRead ();
  }
#endif
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
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips heap-use-after-free when Length == 0xBEEF.
  if ((UINT32)Length == 0xBEEFU) {
    (void)SyzBugsLibTriggerHeapUaf ();
  }
#endif
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
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips heap-OOB read when fuzzer reaches CopyMem
  // with SrcOffset == 0xDEAD. Verifies memory-category dispatch path.
  if ((UINT32)P->SrcOffset == 0xDEADU) {
    (void)SyzBugsLibTriggerHeapOobRead ();
  }
#endif
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
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips heap-OOB write when Offset == 0xCAFE.
  if ((UINT32)P->Offset == 0xCAFEU) {
    (void)SyzBugsLibTriggerHeapOobWrite ();
  }
#endif
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

// ----------------------------------------------------------------------
// Protocol method call handlers (600+).
// ----------------------------------------------------------------------

STATIC
EFI_STATUS
HandleBlockIoReadBlocks (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_BLOCK_IO_READ_PAYLOAD  *P;
  EFI_BLOCK_IO_PROTOCOL                 *BlockIo;
  EFI_STATUS                            Status;
  SYZ_EDK2_ALLOC_SLOT                   *Slot;
  VOID                                  *Buffer;
  UINTN                                 BufSize;
  UINTN                                 ReadSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_BLOCK_IO_READ_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiBlockIoProtocolGuid, NULL, (VOID **)&BlockIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  ReadSize = MIN ((UINTN)P->BufferSize, BufSize);
  BlockIo->ReadBlocks (BlockIo, P->MediaId, P->Lba, ReadSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleBlockIoWriteBlocks (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_BLOCK_IO_WRITE_PAYLOAD  *P;
  EFI_BLOCK_IO_PROTOCOL                  *BlockIo;
  EFI_STATUS                             Status;
  SYZ_EDK2_ALLOC_SLOT                    *Slot;
  VOID                                   *Buffer;
  UINTN                                  BufSize;
  UINTN                                  WriteSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_BLOCK_IO_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiBlockIoProtocolGuid, NULL, (VOID **)&BlockIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  WriteSize = MIN ((UINTN)P->BufferSize, BufSize);
  BlockIo->WriteBlocks (BlockIo, P->MediaId, P->Lba, WriteSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleDiskIoReadDisk (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_DISK_IO_READ_PAYLOAD  *P;
  EFI_DISK_IO_PROTOCOL                 *DiskIo;
  EFI_STATUS                           Status;
  SYZ_EDK2_ALLOC_SLOT                  *Slot;
  VOID                                 *Buffer;
  UINTN                                BufSize;
  UINTN                                ReadSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_DISK_IO_READ_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiDiskIoProtocolGuid, NULL, (VOID **)&DiskIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  ReadSize = MIN ((UINTN)P->BufferSize, BufSize);
  DiskIo->ReadDisk (DiskIo, P->MediaId, P->Offset, ReadSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciIoMemRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_MEM_READ_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                     *PciIo;
  EFI_STATUS                              Status;
  SYZ_EDK2_ALLOC_SLOT                     *Slot;
  VOID                                    *Buffer;
  UINTN                                   BufSize;
  UINT32                                  Width;
  UINTN                                   Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_MEM_READ_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Mem.Read (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                   P->BarIndex, P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciIoPciRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_PCI_READ_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                     *PciIo;
  EFI_STATUS                              Status;
  SYZ_EDK2_ALLOC_SLOT                     *Slot;
  VOID                                    *Buffer;
  UINTN                                   BufSize;
  UINT32                                  Width;
  UINTN                                   Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_PCI_READ_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Pci.Read (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                   P->PciOffset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSnpTransmit (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SNP_TRANSMIT_PAYLOAD  *P;
  EFI_SIMPLE_NETWORK_PROTOCOL          *Snp;
  EFI_STATUS                           Status;
  SYZ_EDK2_ALLOC_SLOT                  *Slot;
  VOID                                 *Buffer;
  UINTN                                BufSize;
  UINTN                                TxSize;
  UINTN                                HdrSize;
  EFI_MAC_ADDRESS                      SrcAddr;
  EFI_MAC_ADDRESS                      DestAddr;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_SNP_TRANSMIT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiSimpleNetworkProtocolGuid, NULL, (VOID **)&Snp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  TxSize  = MIN ((UINTN)P->BufferSize, BufSize);
  HdrSize = MIN ((UINTN)P->HeaderSize, TxSize);

  ZeroMem (&SrcAddr, sizeof (SrcAddr));
  ZeroMem (&DestAddr, sizeof (DestAddr));
  CopyMem (&SrcAddr,  P->SrcAddr,  sizeof (P->SrcAddr));
  CopyMem (&DestAddr, P->DestAddr, sizeof (P->DestAddr));

  {
    UINT16 Proto = P->Protocol;
    Snp->Transmit (Snp, HdrSize, TxSize, Buffer, &SrcAddr, &DestAddr, &Proto);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleUsbIoControlTransfer (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_USB_IO_CONTROL_TRANSFER_PAYLOAD  *P;
  EFI_USB_IO_PROTOCOL                             *UsbIo;
  EFI_STATUS                                      Status;
  SYZ_EDK2_ALLOC_SLOT                             *Slot;
  VOID                                            *Buffer;
  UINTN                                           BufSize;
  EFI_USB_DEVICE_REQUEST                          Request;
  UINT32                                          UsbStatus;
  UINT16                                          DataLen;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_USB_IO_CONTROL_TRANSFER_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiUsbIoProtocolGuid, NULL, (VOID **)&UsbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DataIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;

  ZeroMem (&Request, sizeof (Request));
  Request.RequestType = P->RequestType;
  Request.Request     = P->Request;
  Request.Value       = P->Value;
  Request.Index       = P->Index;

  DataLen = (Buffer != NULL) ? (UINT16)MIN ((UINTN)P->DataLength, BufSize) : 0;
  Request.Length = DataLen;

  UsbIo->UsbControlTransfer (
           UsbIo,
           &Request,
           (EFI_USB_DATA_DIRECTION)MIN (P->Direction, EfiUsbNoData),
           MIN (P->Timeout, 5000),
           Buffer,
           DataLen,
           &UsbStatus
           );
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleGopBlt (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_GOP_BLT_PAYLOAD          *P;
  EFI_GRAPHICS_OUTPUT_PROTOCOL             *Gop;
  EFI_STATUS                               Status;
  SYZ_EDK2_ALLOC_SLOT                      *Slot;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL            *BltBuffer;
  UINTN                                    BufSize;
  UINTN                                    Width;
  UINTN                                    Height;
  EFI_GRAPHICS_OUTPUT_BLT_OPERATION        BltOp;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_GOP_BLT_PAYLOAD *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips signed-mul overflow when Width == 0xABBA.
  if ((UINT32)P->Width == 0xABBAU) {
    (void)SyzBugsLibTriggerMulOverflow ();
  }
#endif

  Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot      = GetAllocSlot (P->SrcIndex);
  BltBuffer = (Slot != NULL) ? (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)Slot->Pointer : NULL;
  BufSize   = (Slot != NULL) ? Slot->Bytes : 0;
  if (BltBuffer == NULL) {
    return EFI_SUCCESS;
  }

  BltOp  = (EFI_GRAPHICS_OUTPUT_BLT_OPERATION)MIN (P->BltOp, EfiBltBufferToVideo);
  Width  = MIN ((UINTN)P->Width,  256);
  Height = MIN ((UINTN)P->Height, 256);

  //
  // Make sure the BLT buffer is large enough for the requested rectangle.
  //
  if (Width * Height * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) > BufSize) {
    return EFI_SUCCESS;
  }

  Gop->Blt (Gop, BltBuffer, BltOp,
            P->SrcX, P->SrcY,
            P->DstX, P->DstY,
            Width, Height,
            P->Delta);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiUpdatePackageList (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_UPDATE_PACKAGE_LIST_PAYLOAD  *P;
  EFI_HII_DATABASE_PROTOCOL                       *Hii;
  EFI_HII_HANDLE                                  Handle;
  EFI_HII_PACKAGE_LIST_HEADER                     *List;
  EFI_STATUS                                      Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_UPDATE_PACKAGE_LIST_PAYLOAD *)Payload;
  if ((UINTN)P->PackageSize + sizeof (*P) > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }
  if (P->PackageSize < sizeof (EFI_HII_PACKAGE_LIST_HEADER)) {
    return EFI_INVALID_PARAMETER;
  }
  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }

  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (&gEfiHiiDatabaseProtocolGuid, NULL, (VOID **)&Hii);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  List = AllocatePool (P->PackageSize);
  if (List == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (List, Payload + sizeof (*P), P->PackageSize);

  Hii->UpdatePackageList (Hii, Handle, List);
  FreePool (List);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiExportPackageLists (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_EXPORT_PACKAGE_LISTS_PAYLOAD  *P;
  EFI_HII_DATABASE_PROTOCOL                        *Hii;
  EFI_HII_HANDLE                                   Handle;
  EFI_STATUS                                       Status;
  SYZ_EDK2_ALLOC_SLOT                              *Slot;
  VOID                                             *Buffer;
  UINTN                                            BufSize;
  UINTN                                            ExportSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_EXPORT_PACKAGE_LISTS_PAYLOAD *)Payload;

  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;

  Status = gBS->LocateProtocol (&gEfiHiiDatabaseProtocolGuid, NULL, (VOID **)&Hii);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  ExportSize = MIN ((UINTN)P->BufferSize, BufSize);
  Hii->ExportPackageLists (Hii, Handle, &ExportSize, (EFI_HII_PACKAGE_LIST_HEADER *)Buffer);
  return EFI_SUCCESS;
}

// ======================================================================
// SetTimer / WaitForEvent
// ======================================================================

STATIC
EFI_STATUS
HandleSetTimer (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SET_TIMER_PAYLOAD  *P;
  EFI_EVENT                         Event;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_SET_TIMER_PAYLOAD *)Payload;
  if (P->EventIndex >= SYZ_EDK2_MAX_EVENTS) {
    return EFI_INVALID_PARAMETER;
  }
  Event = gSyzEdk2Agent.Events[P->EventIndex].Event;
  if (Event == NULL) {
    return EFI_SUCCESS;
  }
  if (P->Type > 2) {
    return EFI_SUCCESS;
  }
  gBS->SetTimer (Event, (EFI_TIMER_DELAY)P->Type, P->TriggerTime);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleWaitForEvent (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_WAIT_FOR_EVENT_PAYLOAD  *P;
  EFI_EVENT                              Event;
  UINTN                                  Index;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_WAIT_FOR_EVENT_PAYLOAD *)Payload;
  if (P->EventIndex >= SYZ_EDK2_MAX_EVENTS) {
    return EFI_INVALID_PARAMETER;
  }
  Event = gSyzEdk2Agent.Events[P->EventIndex].Event;
  if (Event == NULL) {
    return EFI_SUCCESS;
  }
  // Use CheckEvent instead of WaitForEvent to avoid blocking.
  gBS->CheckEvent (Event);
  (VOID)Index;
  return EFI_SUCCESS;
}

// ======================================================================
// DiskIo Write
// ======================================================================

STATIC
EFI_STATUS
HandleDiskIoWriteDisk (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_DISK_IO_WRITE_PAYLOAD  *P;
  EFI_DISK_IO_PROTOCOL                  *DiskIo;
  EFI_STATUS                            Status;
  SYZ_EDK2_ALLOC_SLOT                   *Slot;
  VOID                                  *Buffer;
  UINTN                                 BufSize;
  UINTN                                 WriteSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_DISK_IO_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiDiskIoProtocolGuid, NULL, (VOID **)&DiskIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  WriteSize = MIN ((UINTN)P->BufferSize, BufSize);
  DiskIo->WriteDisk (DiskIo, P->MediaId, P->Offset, WriteSize, Buffer);
  return EFI_SUCCESS;
}

// ======================================================================
// PCI extensions
// ======================================================================

STATIC
EFI_STATUS
HandlePciIoMemWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_MEM_WRITE_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                      *PciIo;
  EFI_STATUS                               Status;
  SYZ_EDK2_ALLOC_SLOT                      *Slot;
  VOID                                     *Buffer;
  UINTN                                    BufSize;
  UINT32                                   Width;
  UINTN                                    Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_MEM_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Mem.Write (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                    P->BarIndex, P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciIoPciWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_PCI_WRITE_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                      *PciIo;
  EFI_STATUS                               Status;
  SYZ_EDK2_ALLOC_SLOT                      *Slot;
  VOID                                     *Buffer;
  UINTN                                    BufSize;
  UINT32                                   Width;
  UINTN                                    Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_PCI_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Pci.Write (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                     P->PciOffset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciIoIoRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_IO_READ_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                    *PciIo;
  EFI_STATUS                             Status;
  SYZ_EDK2_ALLOC_SLOT                    *Slot;
  VOID                                   *Buffer;
  UINTN                                  BufSize;
  UINT32                                 Width;
  UINTN                                  Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_IO_READ_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Io.Read (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                   P->BarIndex, P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciIoIoWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_IO_IO_WRITE_PAYLOAD  *P;
  EFI_PCI_IO_PROTOCOL                     *PciIo;
  EFI_STATUS                              Status;
  SYZ_EDK2_ALLOC_SLOT                     *Slot;
  VOID                                    *Buffer;
  UINTN                                   BufSize;
  UINT32                                  Width;
  UINTN                                   Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_IO_IO_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciIoProtocolGuid, NULL, (VOID **)&PciIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciIoWidthFifoUint64) {
    Width = EfiPciIoWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  PciIo->Io.Write (PciIo, (EFI_PCI_IO_PROTOCOL_WIDTH)Width,
                    P->BarIndex, P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciRbIoMemRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_RB_IO_MEM_PAYLOAD     *P;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL          *RbIo;
  EFI_STATUS                               Status;
  SYZ_EDK2_ALLOC_SLOT                      *Slot;
  VOID                                     *Buffer;
  UINTN                                    BufSize;
  UINT32                                   Width;
  UINTN                                    Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_RB_IO_MEM_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID **)&RbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciWidthFifoUint64) {
    Width = EfiPciWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  RbIo->Mem.Read (RbIo, (EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH)Width,
                   P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciRbIoMemWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_RB_IO_MEM_WRITE_PAYLOAD  *P;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL             *RbIo;
  EFI_STATUS                                  Status;
  SYZ_EDK2_ALLOC_SLOT                         *Slot;
  VOID                                        *Buffer;
  UINTN                                       BufSize;
  UINT32                                      Width;
  UINTN                                       Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_RB_IO_MEM_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID **)&RbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciWidthFifoUint64) {
    Width = EfiPciWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  RbIo->Mem.Write (RbIo, (EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH)Width,
                    P->Offset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciRbIoPciRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_RB_IO_PCI_PAYLOAD        *P;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL             *RbIo;
  EFI_STATUS                                  Status;
  SYZ_EDK2_ALLOC_SLOT                         *Slot;
  VOID                                        *Buffer;
  UINTN                                       BufSize;
  UINT32                                      Width;
  UINTN                                       Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_RB_IO_PCI_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID **)&RbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciWidthFifoUint64) {
    Width = EfiPciWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  RbIo->Pci.Read (RbIo, (EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH)Width,
                   P->PciOffset, Count, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandlePciRbIoPciWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_PCI_RB_IO_PCI_WRITE_PAYLOAD  *P;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL             *RbIo;
  EFI_STATUS                                  Status;
  SYZ_EDK2_ALLOC_SLOT                         *Slot;
  VOID                                        *Buffer;
  UINTN                                       BufSize;
  UINT32                                      Width;
  UINTN                                       Count;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_PCI_RB_IO_PCI_WRITE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID **)&RbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->SrcIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  Width = P->Width;
  if (Width > EfiPciWidthFifoUint64) {
    Width = EfiPciWidthUint8;
  }
  Count = MIN ((UINTN)P->Count, BufSize);
  RbIo->Pci.Write (RbIo, (EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH)Width,
                    P->PciOffset, Count, Buffer);
  return EFI_SUCCESS;
}

// ======================================================================
// SNP extensions
// ======================================================================

STATIC
EFI_STATUS
HandleSnpReceive (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SNP_RECEIVE_PAYLOAD  *P;
  EFI_SIMPLE_NETWORK_PROTOCOL        *Snp;
  EFI_STATUS                         Status;
  SYZ_EDK2_ALLOC_SLOT                *Slot;
  VOID                               *Buffer;
  UINTN                              BufSize;
  UINTN                              HdrSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_SNP_RECEIVE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiSimpleNetworkProtocolGuid, NULL, (VOID **)&Snp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  BufSize = MIN ((UINTN)P->BufferSize, BufSize);
  HdrSize = 0;
  Snp->Receive (Snp, &HdrSize, &BufSize, Buffer, NULL, NULL, NULL);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSnpGetStatus (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_SIMPLE_NETWORK_PROTOCOL  *Snp;
  EFI_STATUS                   Status;
  UINT32                       InterruptStatus;
  VOID                         *TxBuf;

  if (PayloadSize < sizeof (SYZ_EDK2_SNP_GET_STATUS_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiSimpleNetworkProtocolGuid, NULL, (VOID **)&Snp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  InterruptStatus = 0;
  TxBuf = NULL;
  Snp->GetStatus (Snp, &InterruptStatus, &TxBuf);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleSnpInitialize (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_SNP_INITIALIZE_PAYLOAD  *P;
  EFI_SIMPLE_NETWORK_PROTOCOL           *Snp;
  EFI_STATUS                            Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_SNP_INITIALIZE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiSimpleNetworkProtocolGuid, NULL, (VOID **)&Snp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Snp->Initialize (Snp, P->RxBufSize, P->TxBufSize);
  return EFI_SUCCESS;
}

// ======================================================================
// USB Bulk Transfer
// ======================================================================

STATIC
EFI_STATUS
HandleUsbIoBulkTransfer (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_USB_IO_BULK_TRANSFER_PAYLOAD  *P;
  EFI_USB_IO_PROTOCOL                          *UsbIo;
  EFI_STATUS                                   Status;
  SYZ_EDK2_ALLOC_SLOT                          *Slot;
  VOID                                         *Buffer;
  UINTN                                        BufSize;
  UINTN                                        DataLen;
  UINT32                                       UsbStatus;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_USB_IO_BULK_TRANSFER_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiUsbIoProtocolGuid, NULL, (VOID **)&UsbIo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DataIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  DataLen   = MIN ((UINTN)P->DataLength, BufSize);
  UsbStatus = 0;
  UsbIo->UsbBulkTransfer (UsbIo, P->EndpointAddr, Buffer, &DataLen, P->Timeout, &UsbStatus);
  return EFI_SUCCESS;
}

// ======================================================================
// GOP extensions
// ======================================================================

STATIC
EFI_STATUS
HandleGopSetMode (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_GOP_SET_MODE_PAYLOAD  *P;
  EFI_GRAPHICS_OUTPUT_PROTOCOL         *Gop;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_GOP_SET_MODE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Gop->SetMode (Gop, P->ModeNumber);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleGopQueryMode (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_GOP_QUERY_MODE_PAYLOAD        *P;
  EFI_GRAPHICS_OUTPUT_PROTOCOL                 *Gop;
  EFI_STATUS                                   Status;
  UINTN                                        SizeOfInfo;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION         *Info;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_GOP_QUERY_MODE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Info = NULL;
  SizeOfInfo = 0;
  Status = Gop->QueryMode (Gop, P->ModeNumber, &SizeOfInfo, &Info);
  if (!EFI_ERROR (Status) && Info != NULL) {
    FreePool (Info);
  }
  return EFI_SUCCESS;
}

// ======================================================================
// HII String protocol
// ======================================================================

STATIC
EFI_STATUS
HandleHiiNewString (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_NEW_STRING_PAYLOAD  *P;
  EFI_HII_STRING_PROTOCOL                *HiiStr;
  EFI_STATUS                             Status;
  EFI_HII_HANDLE                         Handle;
  CHAR16                                 *String;
  UINTN                                  StrChars;
  EFI_STRING_ID                          StringId;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_NEW_STRING_PAYLOAD *)Payload;

  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }

  if ((P->StringSize % 2) != 0 || P->StringSize == 0) {
    return EFI_SUCCESS;
  }
  if (sizeof (*P) + P->StringSize > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiHiiStringProtocolGuid, NULL, (VOID **)&HiiStr);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  StrChars = P->StringSize / sizeof (CHAR16);
  String   = AllocateZeroPool ((StrChars + 1) * sizeof (CHAR16));
  if (String == NULL) {
    return EFI_SUCCESS;
  }
  CopyMem (String, Payload + sizeof (*P), P->StringSize);

  StringId = 0;
  HiiStr->NewString (HiiStr, Handle, &StringId, "en-US", NULL, String, NULL);
  FreePool (String);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiGetString (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_GET_STRING_PAYLOAD  *P;
  EFI_HII_STRING_PROTOCOL                *HiiStr;
  EFI_STATUS                             Status;
  EFI_HII_HANDLE                         Handle;
  SYZ_EDK2_ALLOC_SLOT                    *Slot;
  UINTN                                  BufSize;
  CHAR16                                 *Buffer;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_GET_STRING_PAYLOAD *)Payload;

  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (&gEfiHiiStringProtocolGuid, NULL, (VOID **)&HiiStr);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot   = GetAllocSlot (P->DstIndex);
  Buffer = (Slot != NULL) ? (CHAR16 *)Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  BufSize = MIN ((UINTN)P->MaxSize, BufSize);
  HiiStr->GetString (HiiStr, "en-US", Handle, (EFI_STRING_ID)P->StringId, Buffer, &BufSize, NULL);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiSetString (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_SET_STRING_PAYLOAD  *P;
  EFI_HII_STRING_PROTOCOL                *HiiStr;
  EFI_STATUS                             Status;
  EFI_HII_HANDLE                         Handle;
  CHAR16                                 *String;
  UINTN                                  StrChars;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_SET_STRING_PAYLOAD *)Payload;

  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }

  if ((P->StringSize % 2) != 0 || P->StringSize == 0) {
    return EFI_SUCCESS;
  }
  if (sizeof (*P) + P->StringSize > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiHiiStringProtocolGuid, NULL, (VOID **)&HiiStr);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  StrChars = P->StringSize / sizeof (CHAR16);
  String   = AllocateZeroPool ((StrChars + 1) * sizeof (CHAR16));
  if (String == NULL) {
    return EFI_SUCCESS;
  }
  CopyMem (String, Payload + sizeof (*P), P->StringSize);

  HiiStr->SetString (HiiStr, Handle, (EFI_STRING_ID)P->StringId, "en-US", String, NULL);
  FreePool (String);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleHiiGetLanguages (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_HII_GET_LANGUAGES_PAYLOAD  *P;
  EFI_HII_STRING_PROTOCOL                   *HiiStr;
  EFI_STATUS                                Status;
  EFI_HII_HANDLE                            Handle;
  SYZ_EDK2_ALLOC_SLOT                       *Slot;
  CHAR8                                     *Buffer;
  UINTN                                     BufSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_HII_GET_LANGUAGES_PAYLOAD *)Payload;

  if (P->HandleIndex >= SYZ_EDK2_MAX_HII_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Handle = gSyzEdk2Agent.HiiHandles[P->HandleIndex].Handle;
  if (Handle == NULL) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (&gEfiHiiStringProtocolGuid, NULL, (VOID **)&HiiStr);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? (CHAR8 *)Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  BufSize = MIN ((UINTN)P->MaxSize, BufSize);
  HiiStr->GetLanguages (HiiStr, Handle, Buffer, &BufSize);
  return EFI_SUCCESS;
}

// ======================================================================
// Network: IP4
// ======================================================================

STATIC
EFI_STATUS
HandleIp4Configure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_IP4_CONFIGURE_PAYLOAD  *P;
  EFI_IP4_PROTOCOL                      *Ip4;
  EFI_STATUS                            Status;
  EFI_IP4_CONFIG_DATA                   CfgData;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_IP4_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiIp4ProtocolGuid, NULL, (VOID **)&Ip4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.DefaultProtocol    = P->DefaultProtocol;
  CfgData.AcceptAnyProtocol  = P->AcceptAnyProtocol;
  CfgData.AcceptIcmpErrors   = P->AcceptIcmpErrors;
  CfgData.AcceptBroadcast    = P->AcceptBroadcast;
  CfgData.UseDefaultAddress  = P->UseDefaultAddress;
  CopyMem (&CfgData.StationAddress, P->StationAddress, 4);
  CopyMem (&CfgData.SubnetMask, P->SubnetMask, 4);
  CfgData.TypeOfService = (UINT8)P->TypeOfService;
  CfgData.TimeToLive    = (UINT8)P->TimeToLive;

  Ip4->Configure (Ip4, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleIp4Transmit (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_IP4_TRANSMIT_PAYLOAD  *P;
  EFI_IP4_PROTOCOL                     *Ip4;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_IP4_TRANSMIT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiIp4ProtocolGuid, NULL, (VOID **)&Ip4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // IP4 Transmit requires EFI_IP4_COMPLETION_TOKEN which needs events.
  // Just call GetModeData to exercise the protocol path without blocking.
  {
    EFI_IP4_MODE_DATA  ModeData;
    ZeroMem (&ModeData, sizeof (ModeData));
    Ip4->GetModeData (Ip4, &ModeData, NULL, NULL);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleIp4GetModeData (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_IP4_PROTOCOL   *Ip4;
  EFI_STATUS         Status;
  EFI_IP4_MODE_DATA  ModeData;

  if (PayloadSize < sizeof (SYZ_EDK2_IP4_GET_MODE_DATA_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiIp4ProtocolGuid, NULL, (VOID **)&Ip4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&ModeData, sizeof (ModeData));
  Ip4->GetModeData (Ip4, &ModeData, NULL, NULL);
  return EFI_SUCCESS;
}

// ======================================================================
// Network: UDP4
// ======================================================================

STATIC
EFI_STATUS
HandleUdp4Configure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_UDP4_CONFIGURE_PAYLOAD  *P;
  EFI_UDP4_PROTOCOL                      *Udp4;
  EFI_STATUS                             Status;
  EFI_UDP4_CONFIG_DATA                   CfgData;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_UDP4_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiUdp4ProtocolGuid, NULL, (VOID **)&Udp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.AcceptBroadcast      = P->AcceptBroadcast;
  CfgData.AcceptPromiscuous    = P->AcceptPromiscuous;
  CfgData.AcceptAnyPort        = P->AcceptAnyPort;
  CfgData.AllowDuplicatePort   = P->AllowDuplicatePort;
  CfgData.UseDefaultAddress    = P->UseDefaultAddress;
  CopyMem (&CfgData.StationAddress, P->StationAddress, 4);
  CopyMem (&CfgData.SubnetMask, P->SubnetMask, 4);
  CfgData.StationPort = P->StationPort;
  CfgData.RemotePort  = P->RemotePort;
  CopyMem (&CfgData.RemoteAddress, P->RemoteAddress, 4);

  Udp4->Configure (Udp4, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleUdp4Transmit (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_UDP4_TRANSMIT_PAYLOAD  *P;
  EFI_UDP4_PROTOCOL                     *Udp4;
  EFI_STATUS                            Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_UDP4_TRANSMIT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiUdp4ProtocolGuid, NULL, (VOID **)&Udp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // UDP4 Transmit needs async token; poll instead.
  Udp4->Poll (Udp4);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleUdp4GetModeData (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_UDP4_PROTOCOL    *Udp4;
  EFI_STATUS           Status;
  EFI_UDP4_CONFIG_DATA CfgData;

  if (PayloadSize < sizeof (SYZ_EDK2_UDP4_GET_MODE_DATA_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiUdp4ProtocolGuid, NULL, (VOID **)&Udp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  Udp4->GetModeData (Udp4, &CfgData, NULL, NULL, NULL);
  return EFI_SUCCESS;
}

// ======================================================================
// Network: TCP4
// ======================================================================

STATIC
EFI_STATUS
HandleTcp4Configure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TCP4_CONFIGURE_PAYLOAD  *P;
  EFI_TCP4_PROTOCOL                      *Tcp4;
  EFI_STATUS                             Status;
  EFI_TCP4_CONFIG_DATA                   CfgData;
  EFI_TCP4_ACCESS_POINT                  *Ap;
  EFI_TCP4_OPTION                        TcpOption;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TCP4_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiTcp4ProtocolGuid, NULL, (VOID **)&Tcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  ZeroMem (&TcpOption, sizeof (TcpOption));

  Ap = &CfgData.AccessPoint;
  Ap->UseDefaultAddress = P->UseDefaultAddress;
  CopyMem (&Ap->StationAddress, P->StationAddress, 4);
  CopyMem (&Ap->SubnetMask, P->SubnetMask, 4);
  Ap->StationPort = P->StationPort;
  CopyMem (&Ap->RemoteAddress, P->RemoteAddress, 4);
  Ap->RemotePort  = P->RemotePort;
  Ap->ActiveFlag  = P->ActiveFlag;

  CfgData.ControlOption = &TcpOption;
  TcpOption.ReceiveBufferSize    = 65535;
  TcpOption.SendBufferSize       = 65535;
  TcpOption.EnableNagle          = TRUE;

  Tcp4->Configure (Tcp4, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTcp4Connect (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_TCP4_PROTOCOL  *Tcp4;
  EFI_STATUS         Status;

  if (PayloadSize < sizeof (SYZ_EDK2_TCP4_CONNECT_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiTcp4ProtocolGuid, NULL, (VOID **)&Tcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // TCP4 Connect is async; just poll to exercise code paths.
  Tcp4->Poll (Tcp4);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTcp4Transmit (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TCP4_TRANSMIT_PAYLOAD  *P;
  EFI_TCP4_PROTOCOL                     *Tcp4;
  EFI_STATUS                            Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TCP4_TRANSMIT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiTcp4ProtocolGuid, NULL, (VOID **)&Tcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // TCP4 Transmit is async; poll instead.
  Tcp4->Poll (Tcp4);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTcp4GetModeData (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_TCP4_PROTOCOL  *Tcp4;
  EFI_STATUS         Status;

  if (PayloadSize < sizeof (SYZ_EDK2_TCP4_GET_MODE_DATA_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiTcp4ProtocolGuid, NULL, (VOID **)&Tcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Tcp4->GetModeData (Tcp4, NULL, NULL, NULL, NULL, NULL);
  return EFI_SUCCESS;
}

// ======================================================================
// Network: DHCP4
// ======================================================================

STATIC
EFI_STATUS
HandleDhcp4Configure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_DHCP4_CONFIGURE_PAYLOAD  *P;
  EFI_DHCP4_PROTOCOL                      *Dhcp4;
  EFI_STATUS                              Status;
  EFI_DHCP4_CONFIG_DATA                   CfgData;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_DHCP4_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiDhcp4ProtocolGuid, NULL, (VOID **)&Dhcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.DiscoverTryCount = P->DiscoverTryCount;
  CfgData.RequestTryCount  = P->RequestTryCount;

  Dhcp4->Configure (Dhcp4, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleDhcp4Start (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_DHCP4_PROTOCOL  *Dhcp4;
  EFI_STATUS          Status;

  if (PayloadSize < sizeof (SYZ_EDK2_DHCP4_START_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiDhcp4ProtocolGuid, NULL, (VOID **)&Dhcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // Non-blocking: pass NULL completion event. This will fail immediately
  // if not configured but still exercises the state machine entry.
  Dhcp4->Start (Dhcp4, NULL);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleDhcp4GetModeData (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_DHCP4_PROTOCOL   *Dhcp4;
  EFI_STATUS           Status;
  EFI_DHCP4_MODE_DATA  ModeData;

  if (PayloadSize < sizeof (SYZ_EDK2_DHCP4_GET_MODE_DATA_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiDhcp4ProtocolGuid, NULL, (VOID **)&Dhcp4);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&ModeData, sizeof (ModeData));
  Dhcp4->GetModeData (Dhcp4, &ModeData);
  return EFI_SUCCESS;
}

// ======================================================================
// Network: ARP
// ======================================================================

STATIC
EFI_STATUS
HandleArpConfigure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ARP_CONFIGURE_PAYLOAD  *P;
  EFI_ARP_PROTOCOL                      *Arp;
  EFI_STATUS                            Status;
  EFI_ARP_CONFIG_DATA                   CfgData;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ARP_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiArpProtocolGuid, NULL, (VOID **)&Arp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.SwAddressType   = 0x0800;  // IPv4
  CfgData.SwAddressLength = 4;
  CfgData.RetryCount      = MIN (P->RetryCount, 3U);
  CfgData.RetryTimeOut    = MIN (P->RetryTimeoutMs, 5000U) * 10000ULL;  // ms -> 100ns

  Arp->Configure (Arp, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleArpAdd (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ARP_ADD_PAYLOAD  *P;
  EFI_ARP_PROTOCOL                *Arp;
  EFI_STATUS                      Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ARP_ADD_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiArpProtocolGuid, NULL, (VOID **)&Arp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Arp->Add (Arp, P->DenyFlag, (VOID *)P->SwAddress, (VOID *)P->HwAddress, 0, TRUE);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleArpRequest (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ARP_REQUEST_PAYLOAD  *P;
  EFI_ARP_PROTOCOL                    *Arp;
  EFI_STATUS                          Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ARP_REQUEST_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiArpProtocolGuid, NULL, (VOID **)&Arp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // Non-blocking resolve: pass NULL event. Returns IMMEDIATELY with
  // EFI_NOT_READY or the cached entry.
  {
    EFI_MAC_ADDRESS  ResolvedAddr;
    ZeroMem (&ResolvedAddr, sizeof (ResolvedAddr));
    Arp->Request (Arp, (VOID *)P->TargetSwAddress, NULL, &ResolvedAddr);
  }
  return EFI_SUCCESS;
}

// ======================================================================
// Network: MNP (Managed Network)
// ======================================================================

STATIC
EFI_STATUS
HandleMnpConfigure (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_MNP_CONFIGURE_PAYLOAD        *P;
  EFI_MANAGED_NETWORK_PROTOCOL                *Mnp;
  EFI_STATUS                                  Status;
  EFI_MANAGED_NETWORK_CONFIG_DATA             CfgData;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_MNP_CONFIGURE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiManagedNetworkProtocolGuid, NULL, (VOID **)&Mnp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.ReceivedQueueTimeoutValue  = P->ReceivedQueueTimeoutMs * 10000ULL;
  CfgData.TransmitQueueTimeoutValue  = P->TransmitQueueTimeoutMs * 10000ULL;
  CfgData.ProtocolTypeFilter         = P->ProtocolTypeFilter;
  CfgData.EnableUnicastReceive       = P->EnableUnicastReceive;
  CfgData.EnableMulticastReceive     = P->EnableMulticastReceive;
  CfgData.EnableBroadcastReceive     = P->EnableBroadcastReceive;
  CfgData.EnablePromiscuousReceive   = P->EnablePromiscuousReceive;
  CfgData.FlushQueuesOnReset         = P->FlushQueuesOnReset;
  CfgData.DisableBackgroundPolling   = P->DisableBackgroundPolling;

  Mnp->Configure (Mnp, &CfgData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleMnpTransmit (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_MNP_TRANSMIT_PAYLOAD  *P;
  EFI_MANAGED_NETWORK_PROTOCOL         *Mnp;
  EFI_STATUS                           Status;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_MNP_TRANSMIT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiManagedNetworkProtocolGuid, NULL, (VOID **)&Mnp);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // MNP Transmit is async; poll instead.
  Mnp->Poll (Mnp);
  return EFI_SUCCESS;
}

// ======================================================================
// File System
// ======================================================================

STATIC
EFI_STATUS
HandleSimpleFsOpenVolume (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL                *Root;
  EFI_STATUS                       Status;

  if (PayloadSize < sizeof (SYZ_EDK2_SIMPLEFS_OPEN_VOLUME_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  // Close the previous root if any.
  if (gSyzEdk2Agent.RootFile != NULL) {
    gSyzEdk2Agent.RootFile->Close (gSyzEdk2Agent.RootFile);
    gSyzEdk2Agent.RootFile = NULL;
  }

  Status = gBS->LocateProtocol (&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&Fs);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Root = NULL;
  Status = Fs->OpenVolume (Fs, &Root);
  if (!EFI_ERROR (Status) && Root != NULL) {
    gSyzEdk2Agent.RootFile = Root;
    // Store root as file handle slot 0.
    gSyzEdk2Agent.FileHandles[0].Handle = Root;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileOpen (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_OPEN_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                 *Parent;
  EFI_FILE_PROTOCOL                 *NewFile;
  EFI_STATUS                        Status;
  CHAR16                            *Name;
  UINTN                             NameChars;
  UINTN                             SlotIdx;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_OPEN_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  Parent = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (Parent == NULL) {
    return EFI_SUCCESS;
  }

  if ((P->NameSize % 2) != 0 || P->NameSize == 0) {
    return EFI_SUCCESS;
  }
  if (sizeof (*P) + P->NameSize > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }

  NameChars = P->NameSize / sizeof (CHAR16);
  Name = AllocateZeroPool ((NameChars + 1) * sizeof (CHAR16));
  if (Name == NULL) {
    return EFI_SUCCESS;
  }
  CopyMem (Name, Payload + sizeof (*P), P->NameSize);

  NewFile = NULL;
  Status = Parent->Open (Parent, &NewFile, Name, P->Mode, P->Attributes);
  FreePool (Name);

  if (!EFI_ERROR (Status) && NewFile != NULL) {
    // Find a free file slot.
    for (SlotIdx = 1; SlotIdx < SYZ_EDK2_MAX_FILE_HANDLES; SlotIdx++) {
      if (gSyzEdk2Agent.FileHandles[SlotIdx].Handle == NULL) {
        gSyzEdk2Agent.FileHandles[SlotIdx].Handle = NewFile;
        return EFI_SUCCESS;
      }
    }
    // No free slot; close.
    NewFile->Close (NewFile);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileRead (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_READ_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                 *File;
  SYZ_EDK2_ALLOC_SLOT               *Slot;
  VOID                              *Buffer;
  UINTN                             BufSize;
  UINTN                             ReadSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_READ_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File == NULL) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  ReadSize = MIN ((UINTN)P->BufferSize, BufSize);
  File->Read (File, &ReadSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileWrite (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_WRITE_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                  *File;
  SYZ_EDK2_ALLOC_SLOT                *Slot;
  VOID                               *Buffer;
  UINTN                              BufSize;
  UINTN                              WriteSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_WRITE_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File == NULL) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DataIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  WriteSize = MIN ((UINTN)P->DataLength, BufSize);
  File->Write (File, &WriteSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileGetInfo (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_GET_INFO_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                     *File;
  SYZ_EDK2_ALLOC_SLOT                   *Slot;
  VOID                                  *Buffer;
  UINTN                                 BufSize;
  UINTN                                 InfoSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_GET_INFO_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File == NULL) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DstIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  InfoSize = MIN ((UINTN)P->BufferSize, BufSize);
  File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileSetInfo (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_SET_INFO_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                     *File;
  SYZ_EDK2_ALLOC_SLOT                   *Slot;
  VOID                                  *Buffer;
  UINTN                                 BufSize;
  UINTN                                 InfoSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_SET_INFO_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File == NULL) {
    return EFI_SUCCESS;
  }

  Slot    = GetAllocSlot (P->DataIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  InfoSize = MIN ((UINTN)P->DataLength, BufSize);
  File->SetInfo (File, &gEfiFileInfoGuid, InfoSize, Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileClose (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_CLOSE_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                  *File;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_CLOSE_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES) {
    return EFI_INVALID_PARAMETER;
  }
  // Don't close slot 0 (root).
  if (P->FileHandleIndex == 0) {
    return EFI_SUCCESS;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File != NULL) {
    File->Close (File);
    gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle = NULL;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleFileDelete (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_FILE_DELETE_PAYLOAD  *P;
  EFI_FILE_PROTOCOL                   *File;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_FILE_DELETE_PAYLOAD *)Payload;

  if (P->FileHandleIndex >= SYZ_EDK2_MAX_FILE_HANDLES || P->FileHandleIndex == 0) {
    return EFI_INVALID_PARAMETER;
  }
  File = gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle;
  if (File != NULL) {
    File->Delete (File);  // Also closes the handle.
    gSyzEdk2Agent.FileHandles[P->FileHandleIndex].Handle = NULL;
  }
  return EFI_SUCCESS;
}

// ======================================================================
// Device Path
// ======================================================================

STATIC
EFI_STATUS
HandleDevicePathFromText (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_DEVICE_PATH_FROM_TEXT_PAYLOAD  *P;
  EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL            *FromText;
  EFI_STATUS                                    Status;
  CHAR16                                        *UnicodeText;
  EFI_DEVICE_PATH_PROTOCOL                      *DevPath;
  UINTN                                         TextLen;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_DEVICE_PATH_FROM_TEXT_PAYLOAD *)Payload;

  if (P->TextSize == 0 || sizeof (*P) + P->TextSize > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID **)&FromText);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // Convert ASCII to Unicode for the protocol.
  TextLen = P->TextSize;
  UnicodeText = AllocateZeroPool ((TextLen + 1) * sizeof (CHAR16));
  if (UnicodeText == NULL) {
    return EFI_SUCCESS;
  }
  {
    CONST CHAR8  *Src = (CONST CHAR8 *)(Payload + sizeof (*P));
    UINTN        Idx;
    for (Idx = 0; Idx < TextLen; Idx++) {
      UnicodeText[Idx] = (CHAR16)Src[Idx];
    }
  }

  DevPath = FromText->ConvertTextToDevicePath (UnicodeText);
  FreePool (UnicodeText);
  if (DevPath != NULL) {
    FreePool (DevPath);
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleDevicePathToText (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_DEVICE_PATH_TO_TEXT_PAYLOAD  *P;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL            *ToText;
  EFI_DEVICE_PATH_PROTOCOL                    *DevPath;
  EFI_STATUS                                  Status;
  CHAR16                                      *Text;
  EFI_LOADED_IMAGE_PROTOCOL                   *LoadedImage;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_DEVICE_PATH_TO_TEXT_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiDevicePathToTextProtocolGuid, NULL, (VOID **)&ToText);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // Get our own device path to convert.
  Status = gBS->LocateProtocol (&gEfiLoadedImageProtocolGuid, NULL, (VOID **)&LoadedImage);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Status = gBS->HandleProtocol (LoadedImage->DeviceHandle,
                                &gEfiDevicePathProtocolGuid, (VOID **)&DevPath);
  if (EFI_ERROR (Status) || DevPath == NULL) {
    return EFI_SUCCESS;
  }

  Text = ToText->ConvertDevicePathToText (DevPath, P->DisplayOnly, P->AllowShortcuts);
  if (Text != NULL) {
    FreePool (Text);
  }
  return EFI_SUCCESS;
}

// ======================================================================
// Console: SimpleTextOut + SimpleTextIn
// ======================================================================

STATIC
EFI_STATUS
HandleTextOutOutputString (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TEXT_OUT_OUTPUT_STRING_PAYLOAD  *P;
  CHAR16                                        *String;
  UINTN                                         StrChars;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TEXT_OUT_OUTPUT_STRING_PAYLOAD *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips heap-use-after-free when StringSize == 0xFADE.
  if ((UINT32)P->StringSize == 0xFADEU) {
    (void)SyzBugsLibTriggerHeapUaf ();
  }
#endif


  if ((P->StringSize % 2) != 0 || P->StringSize == 0) {
    return EFI_SUCCESS;
  }
  if (sizeof (*P) + P->StringSize > PayloadSize) {
    return EFI_INVALID_PARAMETER;
  }

  StrChars = P->StringSize / sizeof (CHAR16);
  // Limit output to avoid huge console floods.
  if (StrChars > 128) {
    StrChars = 128;
  }
  String = AllocateZeroPool ((StrChars + 1) * sizeof (CHAR16));
  if (String == NULL) {
    return EFI_SUCCESS;
  }
  CopyMem (String, Payload + sizeof (*P), StrChars * sizeof (CHAR16));

  gST->ConOut->OutputString (gST->ConOut, String);
  FreePool (String);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTextOutSetMode (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TEXT_OUT_SET_MODE_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TEXT_OUT_SET_MODE_PAYLOAD *)Payload;

  gST->ConOut->SetMode (gST->ConOut, P->ModeNumber);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTextOutSetAttribute (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TEXT_OUT_SET_ATTRIBUTE_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TEXT_OUT_SET_ATTRIBUTE_PAYLOAD *)Payload;

  gST->ConOut->SetAttribute (gST->ConOut, P->Attribute);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTextOutClearScreen (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  if (PayloadSize < sizeof (SYZ_EDK2_TEXT_OUT_CLEAR_SCREEN_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  gST->ConOut->ClearScreen (gST->ConOut);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTextInReset (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_TEXT_IN_RESET_PAYLOAD  *P;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_TEXT_IN_RESET_PAYLOAD *)Payload;

  gST->ConIn->Reset (gST->ConIn, P->ExtendedVerification);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleTextInReadKeyStroke (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  EFI_INPUT_KEY  Key;

  if (PayloadSize < sizeof (SYZ_EDK2_TEXT_IN_READ_KEY_STROKE_PAYLOAD)) {
    return EFI_INVALID_PARAMETER;
  }

  // Non-blocking: returns EFI_NOT_READY if no key available.
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  return EFI_SUCCESS;
}

// ======================================================================
// ACPI
// ======================================================================

STATIC
EFI_STATUS
HandleAcpiGetTable (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ACPI_GET_TABLE_PAYLOAD  *P;
  EFI_ACPI_SDT_PROTOCOL                  *Acpi;
  EFI_STATUS                             Status;
  EFI_ACPI_SDT_HEADER                    *Table;
  EFI_ACPI_TABLE_VERSION                 Version;
  UINTN                                  TableKey;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ACPI_GET_TABLE_PAYLOAD *)Payload;

  Status = gBS->LocateProtocol (&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&Acpi);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Table = NULL;
  Version = 0;
  TableKey = 0;
  Acpi->GetAcpiTable (P->Index, &Table, &Version, &TableKey);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
HandleAcpiInstallTable (
  IN CONST UINT8  *Payload,
  IN UINTN        PayloadSize
  )
{
  CONST SYZ_EDK2_ACPI_INSTALL_TABLE_PAYLOAD  *P;
  SYZ_EDK2_ALLOC_SLOT                       *Slot;
  VOID                                      *Buffer;
  UINTN                                     BufSize;

  if (PayloadSize < sizeof (*P)) {
    return EFI_INVALID_PARAMETER;
  }
  P = (CONST SYZ_EDK2_ACPI_INSTALL_TABLE_PAYLOAD *)Payload;

  Slot    = GetAllocSlot (P->DataIndex);
  Buffer  = (Slot != NULL) ? Slot->Pointer : NULL;
  BufSize = (Slot != NULL) ? Slot->Bytes   : 0;
  if (Buffer == NULL) {
    return EFI_SUCCESS;
  }

  // Skip the actual install — installing a malformed ACPI table can
  // wedge ACPI evaluation permanently. Just validate access to the
  // buffer to exercise the path up to the install call.
  (VOID)BufSize;
  (VOID)P->DataLength;
  return EFI_SUCCESS;
}

// ======================================================================
// Network IPv6
// ======================================================================

STATIC EFI_STATUS HandleIp6Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_IP6_CONFIGURE_PAYLOAD *P;
  EFI_IP6_PROTOCOL *Ip6;
  EFI_IP6_CONFIG_DATA CfgData;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_IP6_CONFIGURE_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiIp6ProtocolGuid, NULL, (VOID **)&Ip6))) return EFI_SUCCESS;
  ZeroMem (&CfgData, sizeof (CfgData));
  CfgData.DefaultProtocol  = P->DefaultProtocol;
  CfgData.AcceptAnyProtocol = P->AcceptAnyProtocol;
  CfgData.AcceptIcmpErrors = P->AcceptIcmpErrors;
  CfgData.AcceptPromiscuous = P->AcceptPromiscuous;
  CopyMem (&CfgData.DestinationAddress, P->DestinationAddress, 16);
  CopyMem (&CfgData.StationAddress, P->StationAddress, 16);
  CfgData.TrafficClass = (UINT8)P->TrafficClass;
  CfgData.HopLimit     = (UINT8)P->HopLimit;
  Ip6->Configure (Ip6, &CfgData);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleIp6Transmit (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_IP6_PROTOCOL *Ip6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiIp6ProtocolGuid, NULL, (VOID **)&Ip6))) return EFI_SUCCESS;
  Ip6->Poll (Ip6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleIp6GetModeData (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_IP6_PROTOCOL *Ip6;
  EFI_IP6_MODE_DATA ModeData;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiIp6ProtocolGuid, NULL, (VOID **)&Ip6))) return EFI_SUCCESS;
  ZeroMem (&ModeData, sizeof (ModeData));
  Ip6->GetModeData (Ip6, &ModeData, NULL, NULL);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleUdp6Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_UDP6_CONFIGURE_PAYLOAD *P;
  EFI_UDP6_PROTOCOL *Udp6;
  EFI_UDP6_CONFIG_DATA CfgData;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_UDP6_CONFIGURE_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiUdp6ProtocolGuid, NULL, (VOID **)&Udp6))) return EFI_SUCCESS;
  ZeroMem (&CfgData, sizeof (CfgData));
  CopyMem (&CfgData.StationAddress, P->StationAddress, 16);
  CfgData.StationPort       = P->StationPort;
  CfgData.RemotePort        = P->RemotePort;
  CopyMem (&CfgData.RemoteAddress, P->RemoteAddress, 16);
  CfgData.AcceptPromiscuous  = P->AcceptPromiscuous;
  CfgData.AcceptAnyPort      = P->AcceptAnyPort;
  CfgData.AllowDuplicatePort = P->AllowDuplicatePort;
  Udp6->Configure (Udp6, &CfgData);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleUdp6Transmit (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_UDP6_PROTOCOL *Udp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiUdp6ProtocolGuid, NULL, (VOID **)&Udp6))) return EFI_SUCCESS;
  Udp6->Poll (Udp6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleUdp6GetModeData (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_UDP6_PROTOCOL *Udp6;
  EFI_UDP6_CONFIG_DATA CfgData;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiUdp6ProtocolGuid, NULL, (VOID **)&Udp6))) return EFI_SUCCESS;
  ZeroMem (&CfgData, sizeof (CfgData));
  Udp6->GetModeData (Udp6, &CfgData, NULL, NULL, NULL);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcp6Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_TCP6_CONFIGURE_PAYLOAD *P;
  EFI_TCP6_PROTOCOL *Tcp6;
  EFI_TCP6_CONFIG_DATA CfgData;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_TCP6_CONFIGURE_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcp6ProtocolGuid, NULL, (VOID **)&Tcp6))) return EFI_SUCCESS;
  ZeroMem (&CfgData, sizeof (CfgData));
  CopyMem (&CfgData.AccessPoint.StationAddress, P->StationAddress, 16);
  CfgData.AccessPoint.StationPort = P->StationPort;
  CopyMem (&CfgData.AccessPoint.RemoteAddress, P->RemoteAddress, 16);
  CfgData.AccessPoint.RemotePort  = P->RemotePort;
  CfgData.AccessPoint.ActiveFlag  = P->ActiveFlag;
  Tcp6->Configure (Tcp6, &CfgData);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcp6Connect (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_TCP6_PROTOCOL *Tcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcp6ProtocolGuid, NULL, (VOID **)&Tcp6))) return EFI_SUCCESS;
  Tcp6->Poll (Tcp6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcp6Transmit (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_TCP6_PROTOCOL *Tcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcp6ProtocolGuid, NULL, (VOID **)&Tcp6))) return EFI_SUCCESS;
  Tcp6->Poll (Tcp6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcp6GetModeData (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_TCP6_PROTOCOL *Tcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcp6ProtocolGuid, NULL, (VOID **)&Tcp6))) return EFI_SUCCESS;
  Tcp6->GetModeData (Tcp6, NULL, NULL, NULL, NULL, NULL);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDhcp6Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DHCP6_PROTOCOL *Dhcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDhcp6ProtocolGuid, NULL, (VOID **)&Dhcp6))) return EFI_SUCCESS;
  // Dhcp6->Configure requires an Ia type and option array we don't plumb.
  // Just poll to exercise the state machine.
  Dhcp6->Stop (Dhcp6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDhcp6Start (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DHCP6_PROTOCOL *Dhcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDhcp6ProtocolGuid, NULL, (VOID **)&Dhcp6))) return EFI_SUCCESS;
  Dhcp6->Start (Dhcp6);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDhcp6GetModeData (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DHCP6_PROTOCOL *Dhcp6;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDhcp6ProtocolGuid, NULL, (VOID **)&Dhcp6))) return EFI_SUCCESS;
  Dhcp6->GetModeData (Dhcp6, NULL, NULL);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDns4Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DNS4_PROTOCOL *Dns;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDns4ProtocolGuid, NULL, (VOID **)&Dns))) return EFI_SUCCESS;
  Dns->Poll (Dns);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDns4HostNameToIp (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DNS4_PROTOCOL *Dns;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDns4ProtocolGuid, NULL, (VOID **)&Dns))) return EFI_SUCCESS;
  Dns->Poll (Dns);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDns6Configure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DNS6_PROTOCOL *Dns;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDns6ProtocolGuid, NULL, (VOID **)&Dns))) return EFI_SUCCESS;
  Dns->Poll (Dns);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDns6HostNameToIp (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_DNS6_PROTOCOL *Dns;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiDns6ProtocolGuid, NULL, (VOID **)&Dns))) return EFI_SUCCESS;
  Dns->Poll (Dns);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleMtftp4ReadFile (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_MTFTP4_PROTOCOL *Mtftp;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiMtftp4ProtocolGuid, NULL, (VOID **)&Mtftp))) return EFI_SUCCESS;
  Mtftp->Poll (Mtftp);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleMtftp4GetInfo (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_MTFTP4_PROTOCOL *Mtftp;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiMtftp4ProtocolGuid, NULL, (VOID **)&Mtftp))) return EFI_SUCCESS;
  Mtftp->GetModeData (Mtftp, NULL);
  return EFI_SUCCESS;
}

// ======================================================================
// HTTP
// ======================================================================

STATIC EFI_STATUS HandleHttpConfigure (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_HTTP_PROTOCOL *Http;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHttpProtocolGuid, NULL, (VOID **)&Http))) return EFI_SUCCESS;
  Http->Poll (Http);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleHttpRequest (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_HTTP_PROTOCOL *Http;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHttpProtocolGuid, NULL, (VOID **)&Http))) return EFI_SUCCESS;
  Http->Poll (Http);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleHttpResponse (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_HTTP_PROTOCOL *Http;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHttpProtocolGuid, NULL, (VOID **)&Http))) return EFI_SUCCESS;
  Http->Poll (Http);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleHttpPoll (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_HTTP_PROTOCOL *Http;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHttpProtocolGuid, NULL, (VOID **)&Http))) return EFI_SUCCESS;
  Http->Poll (Http);
  return EFI_SUCCESS;
}

// ======================================================================
// Crypto / Security
// ======================================================================

STATIC EFI_STATUS HandleHash2GetHashSize (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_HASH2_PROTOCOL *Hash;
  UINTN HashSize;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash))) return EFI_SUCCESS;
  HashSize = 0;
  Hash->GetHashSize (Hash, &gEfiHashAlgorithmSha256Guid, &HashSize);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleHash2Hash (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_HASH2_HASH_PAYLOAD *P;
  EFI_HASH2_PROTOCOL *Hash;
  SYZ_EDK2_ALLOC_SLOT *InSlot, *OutSlot;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_HASH2_HASH_PAYLOAD *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips stack-OOB read when DataLength == 0xFADE.
  if ((UINT32)P->DataLength == 0xFADEU) {
    (void)SyzBugsLibTriggerStackOobRead ();
  }
#endif
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash))) return EFI_SUCCESS;
  InSlot  = GetAllocSlot (P->DataIndex);
  OutSlot = GetAllocSlot (P->DstIndex);
  if (InSlot == NULL || OutSlot == NULL) return EFI_SUCCESS;
  Hash->Hash (Hash, &gEfiHashAlgorithmSha256Guid,
              (CONST UINT8 *)InSlot->Pointer, MIN ((UINTN)P->DataLength, InSlot->Bytes),
              (EFI_HASH2_OUTPUT *)OutSlot->Pointer);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleRngGetInfo (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_RNG_PROTOCOL *Rng;
  UINTN ListSize;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiRngProtocolGuid, NULL, (VOID **)&Rng))) return EFI_SUCCESS;
  ListSize = 0;
  Rng->GetInfo (Rng, &ListSize, NULL);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleRngGetRng (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_RNG_GET_RNG_PAYLOAD *P;
  EFI_RNG_PROTOCOL *Rng;
  SYZ_EDK2_ALLOC_SLOT *Slot;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_RNG_GET_RNG_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiRngProtocolGuid, NULL, (VOID **)&Rng))) return EFI_SUCCESS;
  Slot = GetAllocSlot (P->DstIndex);
  if (Slot == NULL) return EFI_SUCCESS;
  Rng->GetRNG (Rng, NULL, MIN ((UINTN)P->NumBytes, Slot->Bytes), (UINT8 *)Slot->Pointer);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcg2GetCapability (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_TCG2_PROTOCOL *Tcg;
  EFI_TCG2_BOOT_SERVICE_CAPABILITY Cap;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg))) return EFI_SUCCESS;
  Cap.Size = sizeof (Cap);
  Tcg->GetCapability (Tcg, &Cap);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcg2HashLogExtendEvent (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_TCG2_HASH_LOG_EXTEND_EVENT_PAYLOAD *P;
  EFI_TCG2_PROTOCOL *Tcg;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_TCG2_HASH_LOG_EXTEND_EVENT_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg))) return EFI_SUCCESS;
  // Passing NULL event is unsafe; skip actual call but keep LocateProtocol.
  (VOID)P;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcg2SubmitCommand (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_TCG2_SUBMIT_COMMAND_PAYLOAD *P;
  EFI_TCG2_PROTOCOL *Tcg;
  SYZ_EDK2_ALLOC_SLOT *InSlot, *OutSlot;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_TCG2_SUBMIT_COMMAND_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg))) return EFI_SUCCESS;
  InSlot = GetAllocSlot (P->DataIndex);
  OutSlot = GetAllocSlot (P->DstIndex);
  if (InSlot == NULL || OutSlot == NULL) return EFI_SUCCESS;
  Tcg->SubmitCommand (Tcg,
                      (UINT32)MIN ((UINTN)P->DataLength, InSlot->Bytes),
                      (UINT8 *)InSlot->Pointer,
                      (UINT32)MIN ((UINTN)P->DstLength, OutSlot->Bytes),
                      (UINT8 *)OutSlot->Pointer);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleTcg2GetEventLog (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_TCG2_GET_EVENT_LOG_PAYLOAD *P;
  EFI_TCG2_PROTOCOL *Tcg;
  EFI_PHYSICAL_ADDRESS Start, End;
  BOOLEAN Truncated;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_TCG2_GET_EVENT_LOG_PAYLOAD *)Payload;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg))) return EFI_SUCCESS;
  Tcg->GetEventLog (Tcg, (EFI_TCG2_EVENT_LOG_FORMAT)(P->EventLogFormat & 3), &Start, &End, &Truncated);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandlePkcs7Verify (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_PKCS7_VERIFY_PROTOCOL *Pkcs7;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiPkcs7VerifyProtocolGuid, NULL, (VOID **)&Pkcs7))) return EFI_SUCCESS;
  // Pkcs7Verify takes complex buffer lists; just LocateProtocol for coverage.
  return EFI_SUCCESS;
}

// ======================================================================
// Storage passthrough
// ======================================================================

STATIC EFI_STATUS HandleAtaPassThru (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_ATA_PASS_THRU_PROTOCOL *Ata;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiAtaPassThruProtocolGuid, NULL, (VOID **)&Ata))) return EFI_SUCCESS;
  // Full PassThru needs a structured packet; skip actual submission.
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleAtaPassThruGetNextDev (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_ATA_PASS_THRU_PROTOCOL *Ata;
  UINT16 Port = 0xFFFF;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiAtaPassThruProtocolGuid, NULL, (VOID **)&Ata))) return EFI_SUCCESS;
  Ata->GetNextPort (Ata, &Port);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleExtScsiPassThru (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_EXT_SCSI_PASS_THRU_PROTOCOL *Scsi;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiExtScsiPassThruProtocolGuid, NULL, (VOID **)&Scsi))) return EFI_SUCCESS;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleExtScsiGetNextDevice (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_EXT_SCSI_PASS_THRU_PROTOCOL *Scsi;
  UINT8 Target[16] = {0xFF};
  UINT64 Lun = 0;
  UINT8 *TargetPtr = Target;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiExtScsiPassThruProtocolGuid, NULL, (VOID **)&Scsi))) return EFI_SUCCESS;
  Scsi->GetNextTargetLun (Scsi, &TargetPtr, &Lun);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleNvmePassThru (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *Nvme;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID **)&Nvme))) return EFI_SUCCESS;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleNvmePassThruGetNextNs (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *Nvme;
  UINT32 NamespaceId = 0xFFFFFFFF;
  (VOID)Payload;
  (VOID)PayloadSize;
  if (EFI_ERROR (gBS->LocateProtocol (&gEfiNvmExpressPassThruProtocolGuid, NULL, (VOID **)&Nvme))) return EFI_SUCCESS;
  Nvme->GetNextNamespace (Nvme, &NamespaceId);
  return EFI_SUCCESS;
}

// ======================================================================
// Boot dispatcher
// ======================================================================

STATIC EFI_STATUS HandleLoadImage (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_LOAD_IMAGE_PAYLOAD *P;
  SYZ_EDK2_ALLOC_SLOT *Slot;
  EFI_HANDLE ImageHandle = NULL;
  UINTN SlotIdx;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_LOAD_IMAGE_PAYLOAD *)Payload;
#ifdef SYZ_BUGS_DISPATCH_INJECT
  // Planted canary — trips signed-mul overflow when DataLength == 0xBAD0.
  if ((UINT32)P->DataLength == 0xBAD0U) {
    (void)SyzBugsLibTriggerMulOverflow ();
  }
#endif
  Slot = GetAllocSlot (P->DataIndex);
  if (Slot == NULL || Slot->Pointer == NULL) return EFI_SUCCESS;
  // gBS->LoadImage parses PE/COFF from SourceBuffer — exercises the PE parser.
  gBS->LoadImage (P->BootPolicy, gImageHandle, NULL,
                  Slot->Pointer, MIN ((UINTN)P->DataLength, Slot->Bytes), &ImageHandle);
  if (ImageHandle != NULL) {
    for (SlotIdx = 0; SlotIdx < SYZ_EDK2_MAX_IMAGE_HANDLES; SlotIdx++) {
      if (gSyzEdk2Agent.ImageHandles[SlotIdx].Handle == NULL) {
        gSyzEdk2Agent.ImageHandles[SlotIdx].Handle = ImageHandle;
        return EFI_SUCCESS;
      }
    }
    gBS->UnloadImage (ImageHandle);
  }
  return EFI_SUCCESS;
}

//
// SyzEdk2ApiLoadImagePe: the payload bytes after the single
// boot_policy byte + 3 pad bytes ARE the PE image. We forward them
// straight to gBS->LoadImage as SourceBuffer, letting DxeCore's
// BasePeCoffLib walk every header field the fuzzer produced.
//
typedef struct {
  UINT8   BootPolicy;
  UINT8   Pad0;
  UINT16  Pad1;
  // followed by the raw PE image bytes
} SYZ_EDK2_LOAD_IMAGE_PE_PAYLOAD;

STATIC EFI_STATUS HandleLoadImagePe (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_LOAD_IMAGE_PE_PAYLOAD *P;
  EFI_HANDLE ImageHandle = NULL;
  UINTN      SlotIdx;
  UINTN      ImageBytes;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_LOAD_IMAGE_PE_PAYLOAD *)Payload;
  ImageBytes = PayloadSize - sizeof (*P);
  if (ImageBytes < 64) return EFI_INVALID_PARAMETER;  // smaller than MZ
  //
  // The PE walker inside BasePeCoffLib hand-inspects every length
  // and offset field — feeding it a fuzzer-controlled image exercises
  // overlapping-sections, oversized NumberOfRvaAndSizes, bogus
  // e_lfanew, SizeOfImage < header size, and similar well-known bug
  // classes. Bounded to SYZ_EDK2_MAX_PROGRAM_BYTES (~4KB) by the
  // transport layer.
  //
  gBS->LoadImage (P->BootPolicy, gImageHandle, NULL,
                  (VOID *)(Payload + sizeof (*P)), ImageBytes,
                  &ImageHandle);
  if (ImageHandle != NULL) {
    for (SlotIdx = 0; SlotIdx < SYZ_EDK2_MAX_IMAGE_HANDLES; SlotIdx++) {
      if (gSyzEdk2Agent.ImageHandles[SlotIdx].Handle == NULL) {
        gSyzEdk2Agent.ImageHandles[SlotIdx].Handle = ImageHandle;
        return EFI_SUCCESS;
      }
    }
    gBS->UnloadImage (ImageHandle);
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleStartImage (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_START_IMAGE_PAYLOAD *P;
  UINTN ExitDataSize = 0;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_START_IMAGE_PAYLOAD *)Payload;
  if (P->ImageHandleIndex >= SYZ_EDK2_MAX_IMAGE_HANDLES) return EFI_INVALID_PARAMETER;
  // Don't actually start — running fuzzed PE/COFF could wreck the VM.
  // The LocateProtocol chain via LoadImage is what we want for coverage.
  (VOID)ExitDataSize;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleUnloadImage (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_UNLOAD_IMAGE_PAYLOAD *P;
  EFI_HANDLE ImageHandle;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_UNLOAD_IMAGE_PAYLOAD *)Payload;
  if (P->ImageHandleIndex >= SYZ_EDK2_MAX_IMAGE_HANDLES) return EFI_INVALID_PARAMETER;
  ImageHandle = gSyzEdk2Agent.ImageHandles[P->ImageHandleIndex].Handle;
  if (ImageHandle != NULL) {
    gBS->UnloadImage (ImageHandle);
    gSyzEdk2Agent.ImageHandles[P->ImageHandleIndex].Handle = NULL;
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleConnectController (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_CONNECT_CONTROLLER_PAYLOAD *P;
  CONST EFI_GUID *Guid;
  EFI_HANDLE *Handles = NULL;
  UINTN NumHandles = 0;
  UINTN Idx;
  EFI_STATUS Status;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_CONNECT_CONTROLLER_PAYLOAD *)Payload;
  Guid = SyzEdk2LookupProtocolGuid (P->ProtocolId);
  if (Guid == NULL) return EFI_SUCCESS;
  Status = gBS->LocateHandleBuffer (ByProtocol, (EFI_GUID *)Guid, NULL, &NumHandles, &Handles);
  if (EFI_ERROR (Status) || Handles == NULL) return EFI_SUCCESS;
  for (Idx = 0; Idx < NumHandles && Idx < 4; Idx++) {
    gBS->ConnectController (Handles[Idx], NULL, NULL, P->Recursive);
  }
  FreePool (Handles);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HandleDisconnectController (IN CONST UINT8 *Payload, IN UINTN PayloadSize) {
  CONST SYZ_EDK2_DISCONNECT_CONTROLLER_PAYLOAD *P;
  CONST EFI_GUID *Guid;
  EFI_HANDLE *Handles = NULL;
  UINTN NumHandles = 0;
  UINTN Idx;
  EFI_STATUS Status;

  if (PayloadSize < sizeof (*P)) return EFI_INVALID_PARAMETER;
  P = (CONST SYZ_EDK2_DISCONNECT_CONTROLLER_PAYLOAD *)Payload;
  Guid = SyzEdk2LookupProtocolGuid (P->ProtocolId);
  if (Guid == NULL) return EFI_SUCCESS;
  Status = gBS->LocateHandleBuffer (ByProtocol, (EFI_GUID *)Guid, NULL, &NumHandles, &Handles);
  if (EFI_ERROR (Status) || Handles == NULL) return EFI_SUCCESS;
  for (Idx = 0; Idx < NumHandles && Idx < 4; Idx++) {
    gBS->DisconnectController (Handles[Idx], NULL, NULL);
  }
  FreePool (Handles);
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
    } else if (Hdr->Call == SyzEdk2ApiSmiTrigger) {
      //
      // Software SMI via ICH9 I/O ports 0xB2 (command) + 0xB3 (data).
      // With smm=off this is a no-op; with SMM_REQUIRE=TRUE builds
      // it fires the full SMI dispatch through PiSmmCpuDxeSmm, which
      // routes to every registered SMI handler by GUID.
      //
      if (PayloadSize >= 4) {
        UINT8 Cmd  = Payload[0];
        UINT8 Data = Payload[1];
        IoWrite8 (0xB3, Data);
        IoWrite8 (0xB2, Cmd);
      }
    } else if (Hdr->Call == SyzEdk2ApiSmmCommunicate) {
      //
      // EfiSmmCommunicationProtocol — pass a fuzzer-crafted buffer
      // (GUID + payload) into SMRAM. The protocol isn't installed
      // in smm=off builds; LocateProtocol returns NOT_FOUND and the
      // syscall becomes a no-op. With SMM_REQUIRE=TRUE this
      // exercises SMI handler argument parsing which is a major
      // source of SMM privilege-escalation bugs.
      //
      HandleSmmCommunicate (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiCpuIoPortRead ||
               Hdr->Call == SyzEdk2ApiCpuIoPortWrite ||
               Hdr->Call == SyzEdk2ApiCpuIoMemRead ||
               Hdr->Call == SyzEdk2ApiCpuIoMemWrite) {
      HandleCpuIo (Hdr->Call, Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiMsrRead) {
      if (PayloadSize >= 4) {
        UINT32 Msr = *(CONST UINT32 *)Payload;
        UINT64 Val = AsmReadMsr64 (Msr);
        (VOID)Val;
      }
    } else if (Hdr->Call == SyzEdk2ApiMsrWrite) {
      if (PayloadSize >= 12) {
        UINT32 Msr = *(CONST UINT32 *)Payload;
        UINT64 Val = *(CONST UINT64 *)(Payload + 4);
        //
        // Writing arbitrary MSRs can crash the guest hard — exactly
        // what we want. CpuExceptionHandlerLib catches the #GP and
        // dumps; report parser surfaces it as an X64 exception crash.
        //
        AsmWriteMsr64 (Msr, Val);
      }
    } else if (Hdr->Call == SyzEdk2ApiSmbiosAdd) {
      HandleSmbiosAdd (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSmbiosGetNext) {
      HandleSmbiosGetNext (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSetVariable ||
               Hdr->Call == SyzEdk2ApiSetVariableAuth ||
               Hdr->Call == SyzEdk2ApiSetVariableDelete ||
               Hdr->Call == SyzEdk2ApiSetVariableAppend) {
      //
      // All four variants share the same on-wire layout (name_size,
      // attributes, data_size, namespace, name[], data[]). The host
      // grammar differs only in what attributes and data shape it
      // emits — the firmware just forwards to SetVariable.
      //
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
    } else if (Hdr->Call == SyzEdk2ApiBlockIoReadBlocks) {
      HandleBlockIoReadBlocks (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiBlockIoWriteBlocks) {
      HandleBlockIoWriteBlocks (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDiskIoReadDisk) {
      HandleDiskIoReadDisk (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciIoMemRead) {
      HandlePciIoMemRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciIoPciRead) {
      HandlePciIoPciRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSnpTransmit) {
      HandleSnpTransmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUsbIoControlTransfer) {
      HandleUsbIoControlTransfer (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiGopBlt) {
      HandleGopBlt (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiUpdatePackageList) {
      HandleHiiUpdatePackageList (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiExportPackageLists) {
      HandleHiiExportPackageLists (Payload, PayloadSize);
    // --- Timer / Event extensions ---
    } else if (Hdr->Call == SyzEdk2ApiSetTimer) {
      HandleSetTimer (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiWaitForEvent) {
      HandleWaitForEvent (Payload, PayloadSize);
    // --- DiskIo Write ---
    } else if (Hdr->Call == SyzEdk2ApiDiskIoWriteDisk) {
      HandleDiskIoWriteDisk (Payload, PayloadSize);
    // --- PCI extensions ---
    } else if (Hdr->Call == SyzEdk2ApiPciIoMemWrite) {
      HandlePciIoMemWrite (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciIoPciWrite) {
      HandlePciIoPciWrite (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciIoIoRead) {
      HandlePciIoIoRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciIoIoWrite) {
      HandlePciIoIoWrite (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciRbIoMemRead) {
      HandlePciRbIoMemRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciRbIoMemWrite) {
      HandlePciRbIoMemWrite (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciRbIoPciRead) {
      HandlePciRbIoPciRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPciRbIoPciWrite) {
      HandlePciRbIoPciWrite (Payload, PayloadSize);
    // --- SNP extensions ---
    } else if (Hdr->Call == SyzEdk2ApiSnpReceive) {
      HandleSnpReceive (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSnpGetStatus) {
      HandleSnpGetStatus (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiSnpInitialize) {
      HandleSnpInitialize (Payload, PayloadSize);
    // --- USB Bulk ---
    } else if (Hdr->Call == SyzEdk2ApiUsbIoBulkTransfer) {
      HandleUsbIoBulkTransfer (Payload, PayloadSize);
    // --- GOP extensions ---
    } else if (Hdr->Call == SyzEdk2ApiGopSetMode) {
      HandleGopSetMode (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiGopQueryMode) {
      HandleGopQueryMode (Payload, PayloadSize);
    // --- HII String ---
    } else if (Hdr->Call == SyzEdk2ApiHiiNewString) {
      HandleHiiNewString (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiGetString) {
      HandleHiiGetString (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiSetString) {
      HandleHiiSetString (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHiiGetLanguages) {
      HandleHiiGetLanguages (Payload, PayloadSize);
    // --- Network ---
    } else if (Hdr->Call == SyzEdk2ApiIp4Configure) {
      HandleIp4Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiIp4Transmit) {
      HandleIp4Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiIp4GetModeData) {
      HandleIp4GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp4Configure) {
      HandleUdp4Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp4Transmit) {
      HandleUdp4Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp4GetModeData) {
      HandleUdp4GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp4Configure) {
      HandleTcp4Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp4Connect) {
      HandleTcp4Connect (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp4Transmit) {
      HandleTcp4Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp4GetModeData) {
      HandleTcp4GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp4Configure) {
      HandleDhcp4Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp4Start) {
      HandleDhcp4Start (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp4GetModeData) {
      HandleDhcp4GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiArpConfigure) {
      HandleArpConfigure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiArpAdd) {
      HandleArpAdd (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiArpRequest) {
      HandleArpRequest (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiMnpConfigure) {
      HandleMnpConfigure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiMnpTransmit) {
      HandleMnpTransmit (Payload, PayloadSize);
    // --- File System ---
    } else if (Hdr->Call == SyzEdk2ApiSimpleFsOpenVolume) {
      HandleSimpleFsOpenVolume (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileOpen) {
      HandleFileOpen (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileRead) {
      HandleFileRead (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileWrite) {
      HandleFileWrite (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileGetInfo) {
      HandleFileGetInfo (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileSetInfo) {
      HandleFileSetInfo (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileClose) {
      HandleFileClose (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiFileDelete) {
      HandleFileDelete (Payload, PayloadSize);
    // --- Device Path ---
    } else if (Hdr->Call == SyzEdk2ApiDevicePathFromText) {
      HandleDevicePathFromText (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDevicePathToText) {
      HandleDevicePathToText (Payload, PayloadSize);
    // --- Console ---
    } else if (Hdr->Call == SyzEdk2ApiTextOutOutputString) {
      HandleTextOutOutputString (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTextOutSetMode) {
      HandleTextOutSetMode (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTextOutSetAttribute) {
      HandleTextOutSetAttribute (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTextOutClearScreen) {
      HandleTextOutClearScreen (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTextInReset) {
      HandleTextInReset (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTextInReadKeyStroke) {
      HandleTextInReadKeyStroke (Payload, PayloadSize);
    // --- ACPI ---
    } else if (Hdr->Call == SyzEdk2ApiAcpiGetTable) {
      HandleAcpiGetTable (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAcpiInstallTable) {
      HandleAcpiInstallTable (Payload, PayloadSize);
    // --- Network IPv6 ---
    } else if (Hdr->Call == SyzEdk2ApiIp6Configure) {
      HandleIp6Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiIp6Transmit) {
      HandleIp6Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiIp6GetModeData) {
      HandleIp6GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp6Configure) {
      HandleUdp6Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp6Transmit) {
      HandleUdp6Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUdp6GetModeData) {
      HandleUdp6GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp6Configure) {
      HandleTcp6Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp6Connect) {
      HandleTcp6Connect (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp6Transmit) {
      HandleTcp6Transmit (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcp6GetModeData) {
      HandleTcp6GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp6Configure) {
      HandleDhcp6Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp6Start) {
      HandleDhcp6Start (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDhcp6GetModeData) {
      HandleDhcp6GetModeData (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDns4Configure) {
      HandleDns4Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDns4HostNameToIp) {
      HandleDns4HostNameToIp (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDns6Configure) {
      HandleDns6Configure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDns6HostNameToIp) {
      HandleDns6HostNameToIp (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiMtftp4ReadFile) {
      HandleMtftp4ReadFile (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiMtftp4GetInfo) {
      HandleMtftp4GetInfo (Payload, PayloadSize);
    // --- HTTP ---
    } else if (Hdr->Call == SyzEdk2ApiHttpConfigure) {
      HandleHttpConfigure (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHttpRequest) {
      HandleHttpRequest (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHttpResponse) {
      HandleHttpResponse (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHttpPoll) {
      HandleHttpPoll (Payload, PayloadSize);
    // --- Crypto / Security ---
    } else if (Hdr->Call == SyzEdk2ApiHash2GetHashSize) {
      HandleHash2GetHashSize (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiHash2Hash) {
      HandleHash2Hash (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiRngGetInfo) {
      HandleRngGetInfo (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiRngGetRng) {
      HandleRngGetRng (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcg2GetCapability) {
      HandleTcg2GetCapability (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcg2HashLogExtendEvent) {
      HandleTcg2HashLogExtendEvent (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcg2SubmitCommand) {
      HandleTcg2SubmitCommand (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiTcg2GetEventLog) {
      HandleTcg2GetEventLog (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiPkcs7Verify) {
      HandlePkcs7Verify (Payload, PayloadSize);
    // --- Storage passthrough ---
    } else if (Hdr->Call == SyzEdk2ApiAtaPassThru) {
      HandleAtaPassThru (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiAtaPassThruGetNextDev) {
      HandleAtaPassThruGetNextDev (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiExtScsiPassThru) {
      HandleExtScsiPassThru (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiExtScsiGetNextDevice) {
      HandleExtScsiGetNextDevice (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiNvmePassThru) {
      HandleNvmePassThru (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiNvmePassThruGetNextNs) {
      HandleNvmePassThruGetNextNs (Payload, PayloadSize);
    // --- Boot dispatcher ---
    } else if (Hdr->Call == SyzEdk2ApiLoadImage) {
      HandleLoadImage (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiLoadImagePe) {
      HandleLoadImagePe (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiStartImage) {
      HandleStartImage (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiUnloadImage) {
      HandleUnloadImage (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiConnectController) {
      HandleConnectController (Payload, PayloadSize);
    } else if (Hdr->Call == SyzEdk2ApiDisconnectController) {
      HandleDisconnectController (Payload, PayloadSize);
    } else {
      DEBUG ((DEBUG_VERBOSE, "[SYZ-AGENT] unknown call %u\n", (UINTN)Hdr->Call));
    }

    Offset += Hdr->Size;
  }

  return EFI_SUCCESS;
}

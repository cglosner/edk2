/** @file
  A sanitizer for the faults that are about firmware rather than about allocations.

  ASan models allocations, so it sees a read that leaves a buffer and nothing else. The
  faults that matter in firmware are mostly in bounds of something: a pointer into SMRAM
  that the caller was not entitled to hand over, a boot service used after the table it
  lives in has been reclaimed, a size learned from memory an operating system can still
  write. Every one of those is a correct access to the wrong thing, and no shadow byte
  changes.

  This hooks the two service tables once, from a driver, rather than asking every module
  to link something. A module calls through gBS and gRT by pointer, so replacing entries
  in the tables reaches callers that were compiled long before this existed -- including
  the ones that captured the table pointer at their own entry.

  Reports go out through AsanLib's serial path and escalate through the same solution
  signal, so a finding here reaches the fuzzer by the route findings already take and
  needs nothing new downstream.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// AsanLib's reporting path. Declared rather than included so this driver does not
// depend on the sanitizer's private header layout.
//
VOID SerialOutput (IN CONST CHAR8 *String);
VOID AsanSignalSolution (VOID);
VOID AsanRegisterProtectedRegion (IN UINT64 Base, IN UINT64 Size, IN CONST CHAR8 *Name);
UINTN AsanPoisonStaleInterface (IN VOID *Interface);

#define FWSAN_VARIABLE_SLOTS  8

typedef struct {
  VOID   *Data;          // the destination the caller offered
  UINTN  Offered;        // how much it said the destination held
  UINTN  Required;       // how much the variable actually needs
  CHAR16 Name[32];
} FWSAN_VARIABLE_CALL;

STATIC EFI_ALLOCATE_POOL      mRealAllocatePool = NULL;
STATIC EFI_FREE_POOL          mRealFreePool     = NULL;
STATIC EFI_GET_VARIABLE       mRealGetVariable  = NULL;
STATIC EFI_UNINSTALL_PROTOCOL_INTERFACE  mRealUninstall = NULL;
STATIC BOOLEAN                mAfterExitBoot    = FALSE;
STATIC EFI_EVENT              mExitBootEvent    = NULL;
STATIC FWSAN_VARIABLE_CALL    mVariableCalls[FWSAN_VARIABLE_SLOTS];
STATIC UINTN                  mVariableNext     = 0;

VOID
AsanReportFirmwareClass (
  IN CONST CHAR8  *BugDescr,
  IN UINTN        Addr,
  IN UINTN        Size,
  IN UINTN        IsWrite,
  IN UINTN        Ip
  );

/**
  Say what happened and, inside the fuzzing window, make it a finding.

  Outside the window this only logs. A plain boot raises these legitimately -- firmware
  reads its own volumes constantly -- and ending an iteration for one of those would stop
  every campaign before its harness ran.
**/
STATIC
VOID
FwSanReport (
  IN CONST CHAR8  *Class,
  IN CONST CHAR8  *Detail,
  IN UINT64       Address
  )
{
  CHAR8  Line[192];

  AsciiSPrint (
    Line,
    sizeof (Line),
    "FWSAN: %a -- %a at 0x%016lx\n",
    Class,
    Detail,
    Address
    );
  SerialOutput (Line);
  //
  // The same text again in the shape scripts/firness.py turns into a crashes.csv row: an
  // "[ASan] ERROR: ... ip 0x..." line and a "bug_descr=..." line. Without it a FWSAN class
  // is narration only -- 3283 double-fetch detections in one campaign produced zero report
  // rows, and bugs.md read as though the firmware sanitizer had found nothing.
  //
  AsanReportFirmwareClass (Class, (UINTN)Address, 0, 0,
                           (UINTN)__builtin_return_address (0));
  AsanSignalSolution ();
}

/**
  A boot service used after ExitBootServices.

  The table and the code it points at may have been reclaimed the moment the OS took
  over. Nothing was freed in the allocator's sense, so ASan has nothing to say; the
  lifetime that ended belongs to the boot phase, not to an allocation.
**/
STATIC
EFI_STATUS
EFIAPI
FwSanAllocatePool (
  IN  EFI_MEMORY_TYPE  PoolType,
  IN  UINTN            Size,
  OUT VOID             **Buffer
  )
{
  if (mAfterExitBoot) {
    FwSanReport (
      "boot-service-after-exit",
      "AllocatePool called after ExitBootServices",
      (UINT64)(UINTN)RETURN_ADDRESS (0)
      );
  }

  return mRealAllocatePool (PoolType, Size, Buffer);
}

STATIC
EFI_STATUS
EFIAPI
FwSanFreePool (
  IN VOID  *Buffer
  )
{
  if (mAfterExitBoot) {
    FwSanReport (
      "boot-service-after-exit",
      "FreePool called after ExitBootServices",
      (UINT64)(UINTN)RETURN_ADDRESS (0)
      );
  }

  return mRealFreePool (Buffer);
}

/**
  A caller that believes the size a variable reports.

  The two-call idiom is correct: ask with a small buffer, get EFI_BUFFER_TOO_SMALL and
  the required size, allocate that, ask again. The defect is asking again with the SAME
  destination -- the one already known to be too small -- and the size the variable
  named. That is visible from the call sequence alone, without knowing how large the
  destination really is, which matters because the destination is usually on the stack
  and no shadow describes it.
**/
STATIC
EFI_STATUS
EFIAPI
FwSanGetVariable (
  IN     CHAR16    *VariableName,
  IN     EFI_GUID  *VendorGuid,
  OUT    UINT32    *Attributes  OPTIONAL,
  IN OUT UINTN     *DataSize,
  OUT    VOID      *Data        OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       Offered;
  UINTN       Index;

  Offered = (DataSize != NULL) ? *DataSize : 0;

  //
  // Did this exact destination already learn that it is too small?
  //
  if ((Data != NULL) && (DataSize != NULL)) {
    for (Index = 0; Index < FWSAN_VARIABLE_SLOTS; Index++) {
      if ((mVariableCalls[Index].Data == Data) &&
          (mVariableCalls[Index].Required > mVariableCalls[Index].Offered) &&
          (Offered >= mVariableCalls[Index].Required))
      {
        FwSanReport (
          "variable-size-trusted",
          "GetVariable reissued into a destination already known to be too small",
          (UINT64)(UINTN)Data
          );
        break;
      }
    }
  }

  Status = mRealGetVariable (VariableName, VendorGuid, Attributes, DataSize, Data);

  //
  // Remember the refusal so the reissue above can be recognised. Only the buffer-too-
  // small answer is interesting; everything else tells the caller nothing it could
  // misuse.
  //
  if ((Status == EFI_BUFFER_TOO_SMALL) && (Data != NULL) && (DataSize != NULL)) {
    mVariableCalls[mVariableNext].Data     = Data;
    mVariableCalls[mVariableNext].Offered  = Offered;
    mVariableCalls[mVariableNext].Required = *DataSize;
    if (VariableName != NULL) {
      StrnCpyS (
        mVariableCalls[mVariableNext].Name,
        ARRAY_SIZE (mVariableCalls[mVariableNext].Name),
        VariableName,
        ARRAY_SIZE (mVariableCalls[mVariableNext].Name) - 1
        );
    }

    mVariableNext = (mVariableNext + 1) % FWSAN_VARIABLE_SLOTS;
  }

  return Status;
}

/**
  An interface whose protocol has just been uninstalled.

  The handle database no longer lists it and the storage is still allocated, still
  mapped and still full of plausible function pointers, so a caller that cached the
  interface keeps working until the memory is reused and then does something else
  entirely. ASan has nothing to say: no allocation ended.

  Poisoning the allocation makes the next read through the stale pointer a report
  instead of a mystery. The extent comes from the shadow, so this does not need to know
  how large the interface was, and a protocol whose interface is a global is left alone
  because a global has no redzone to measure against.

  Reuse is safe without any bookkeeping here: CoreAllocatePoolI unpoisons what it hands
  out, so a later allocation over this memory clears the poison on its way to the caller.
  A free is safe too -- the pool poisons with its own free magic, and a use-after-free is
  the report the caller then deserves.
**/
STATIC
EFI_STATUS
EFIAPI
FwSanUninstallProtocolInterface (
  IN EFI_HANDLE  Handle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  )
{
  EFI_STATUS  Status;
  UINTN       Poisoned;

  Status = mRealUninstall (Handle, Protocol, Interface);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Poisoned = AsanPoisonStaleInterface (Interface);
  if (Poisoned != 0) {
    SerialOutput ("FWSAN: interface uninstalled, storage poisoned\n");
  }

  return Status;
}

STATIC
VOID
EFIAPI
FwSanExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  mAfterExitBoot = TRUE;
}

/**
  Put the hooks in and repair the table's checksum.

  EFI_TABLE_HEADER carries a CRC32 over the table. Replacing entries without recomputing
  it leaves a table that anything checking will reject, and the failure surfaces far from
  here.
**/
STATIC
VOID
FwSanHookTables (
  VOID
  )
{
  EFI_TPL  Tpl;

  Tpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  mRealAllocatePool = gBS->AllocatePool;
  mRealFreePool     = gBS->FreePool;
  gBS->AllocatePool = FwSanAllocatePool;
  gBS->FreePool     = FwSanFreePool;
  gBS->Hdr.CRC32    = 0;
  gBS->CalculateCrc32 (gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  mRealUninstall                     = gBS->UninstallProtocolInterface;
  gBS->UninstallProtocolInterface    = FwSanUninstallProtocolInterface;

  mRealGetVariable  = gRT->GetVariable;
  gRT->GetVariable  = FwSanGetVariable;
  gRT->Hdr.CRC32    = 0;
  gBS->CalculateCrc32 (gRT, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);

  gBS->RestoreTPL (Tpl);
}

EFI_STATUS
EFIAPI
FwSanDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  //
  // Which memory a driver has no business reading. AsanLib holds the list and answers
  // the question from inside the memory interceptors; deciding what belongs on it is
  // policy, and policy belongs here.
  //
  // The flash the firmware itself came out of is the clearest case: a protocol member
  // handed a pointer into it by its caller, and dereferencing that pointer, is the shape
  // of an SMM callout. A 4 MB window below 4 GB covers the SPI mapping on this platform.
  // The legacy BIOS window at 0xC0000 is the other one an input can plausibly aim at.
  //
  AsanRegisterProtectedRegion (0xFFC00000ULL, SIZE_4MB, "flash");
  AsanRegisterProtectedRegion (0x000C0000ULL, SIZE_256KB, "legacy BIOS window");

  ZeroMem (mVariableCalls, sizeof (mVariableCalls));
  FwSanHookTables ();

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  FwSanExitBootServices,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &mExitBootEvent
                  );
  ASSERT_EFI_ERROR (Status);

  SerialOutput ("FWSAN: firmware sanitizer armed\n");
  return EFI_SUCCESS;
}

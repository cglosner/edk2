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
STATIC BOOLEAN                mAfterExitBoot    = FALSE;
STATIC EFI_EVENT              mExitBootEvent    = NULL;
STATIC FWSAN_VARIABLE_CALL    mVariableCalls[FWSAN_VARIABLE_SLOTS];
STATIC UINTN                  mVariableNext     = 0;

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

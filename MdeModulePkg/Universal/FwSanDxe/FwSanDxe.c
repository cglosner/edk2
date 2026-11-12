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
#include <Library/Asan.h>

//
// AsanLib's reporting path comes from its header now. This block used to hand-write
// the declarations "so this driver does not depend on the sanitizer's private header
// layout", and the cost of that independence was a six-parameter function called
// with five arguments for as long as this driver has existed: Detail was missing, so
// the address arrived where a CONST CHAR8 * was expected, Addr and Size arrived as 0,
// IsWrite got the return address, and Ip -- the dedup key and the ip in the
// crashes.csv row -- was never passed. Nothing could have caught it here; the
// definition is in another package and no header named it.
//

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
  // Detail is passed, not omitted. The definition in AsanLib takes it SECOND, and
  // this prototype used to leave it out -- so every argument shifted by one: the
  // address arrived where a CONST CHAR8 *Detail was expected and the banner walked
  // it as a NUL-terminated string, Addr and Size arrived as 0, IsWrite got the
  // return address, and Ip was never passed at all -- which is the dedup key and
  // the ip in the crashes.csv row. It survived because a byte near the destination
  // happened to be zero. AsanReportFirmwareClass has no declaration in any header,
  // so each caller writes its own prototype and nothing made them agree; the two
  // AsanHelper.c copies got it right and this one did not.
  AsanReportFirmwareClass (Class, Detail, (UINTN)Address, 0, 0,
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

  Status = mRealUninstall (Handle, Protocol, Interface);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // OFF unless asked for, because the class it produces is UNSOUND and this is
  // measured, not suspected. On 2026-11-12 the detection benchmark scored its `control`
  // row FAIL -- the row whose whole job is to report NOTHING on correct code -- against
  // three consecutive eight-byte accesses at 0x7AE18098 carrying
  // bug_descr=stale-protocol-interface. The same reports appear at the same addresses in
  // every case's log, so they are raised by the BOOT and not by any case.
  //
  // The reason is in the UEFI spec rather than in this code. UninstallProtocolInterface
  // removes the association between a handle and an interface; it says nothing about the
  // STORAGE, which stays the owner's. A driver may keep using that struct, reinstall it,
  // or hold it as a field of a context it goes on using, and all three are correct. So a
  // read after uninstall is not a defect, and poisoning on uninstall reports correct
  // firmware.
  //
  // Nor does the class add anything sound: if the storage is later FREED, every use of
  // it is already a heap use-after-free that the pool poisoning catches with the right
  // class and the right address.
  //
  // Kept rather than deleted, behind -D ASAN_STALE_INTERFACE, because a campaign hunting
  // a suspected stale-interface bug in ONE driver is a reasonable thing to want, and the
  // benchmark keeps scoring the class so this stays measured rather than assumed. It must
  // not be the default: a detector that fires on every boot costs the control row, and
  // the control row is worth more than the class.
  //
 #ifdef ASAN_STALE_INTERFACE
  {
    UINTN  Poisoned;

    Poisoned = AsanPoisonStaleInterface (Interface);
    if (Poisoned != 0) {
      SerialOutput ("FWSAN: interface uninstalled, storage poisoned\n");
    }
  }
 #endif

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

  //
  // Every entry this function replaces must be in place BEFORE the header CRC is
  // recomputed. UninstallProtocolInterface was installed after it, which left gBS
  // carrying a checksum for a table it no longer was -- the same mistake this
  // function's own contract warns about, and which the gRT block below gets right.
  //
  mRealUninstall                  = gBS->UninstallProtocolInterface;
  gBS->UninstallProtocolInterface = FwSanUninstallProtocolInterface;

  gBS->Hdr.CRC32 = 0;
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

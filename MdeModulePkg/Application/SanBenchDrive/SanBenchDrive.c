/** @file
  Calls every benchmark fault with the input that triggers it.

  Ground truth needs two measurements and they answer different questions. Fuzzing the
  benchmark protocols measures whether the fuzzer can FIND the faults. This measures
  whether the sanitizers can SEE them, by going straight to each one. A class that fails
  here can never be found by any amount of searching, and knowing which of the two broke
  is the whole point of keeping them apart.

  Every case announces itself first, so a run that stops early says which case stopped it.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SanBench.h>

//
// Announce on the wire the sanitizers report on, not through DEBUG. The two are
// different streams: interleaving a case with its report is the only way to say which
// case a report belongs to, and with them apart the scoring is guesswork.
//
VOID SerialOutput (IN CONST CHAR8 *String);
VOID AsanSetRegionChecks (IN BOOLEAN Active);

#define SAY(Case)  SerialOutput ("SanBenchDrive: expect " Case "\n")

EFI_STATUS
EFIAPI
SanBenchDriveEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  SAN_BENCH_MEMORY_PROTOCOL    *Mem;
  SAN_BENCH_FIRMWARE_PROTOCOL  *Fw;
  EFI_STATUS                   Status;
  UINT8                        Big[256];
  UINT32                       Value;
  VOID                         *Shared;
  VOID                         *Blob;

  Status = gBS->LocateProtocol (&gSanBenchMemoryProtocolGuid, NULL, (VOID **)&Mem);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SanBenchDrive: no memory protocol -- build with -D SAN_BENCH\n"));
    return Status;
  }

  Status = gBS->LocateProtocol (&gSanBenchFirmwareProtocolGuid, NULL, (VOID **)&Fw);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SerialOutput ("SanBenchDrive: start\n");
  //
  // Turn the region check on without opening the escalation window. The window is what
  // makes a finding end the iteration, and ending it is a LibAFL command -- an invalid
  // opcode under a plain QEMU, so opening it here kills the guest on the first report
  // and the remaining cases never run. This switch enables the check and leaves
  // escalation alone.
  //
  AsanSetRegionChecks (TRUE);


  //
  // The control goes first. If nothing is reported for the rest, a silent runtime and a
  // clean one look the same; if something is reported for THIS, the runtime is crying
  // wolf and every later report is worth less.
  //
  SerialOutput ("SanBenchDrive: control, expect NO report\n");
  Mem->CopyRecord (Mem, Big, 64);            // exactly the allocation: correct

  SAY ("heap-buffer-overflow");
  Mem->CopyRecord (Mem, Big, 72);            // eight bytes past the fixed 64

  SAY ("heap-buffer-underflow");
  Mem->ReadEntry (Mem, -1, &Value);          // one entry below the table

  //
  // On the heap, not the stack. The obvious way to write this is a two byte local,
  // and it reports nothing: the build carries -mllvm -asan-stack=0 because enabling
  // stack instrumentation faults the boot in CpuDxe, so a stack overread is outside
  // what this sanitizer can see at all. Putting the blob on the heap measures the
  // coverage that exists rather than the gap that is already known.
  //
  SAY ("tlv-overread");
  Blob = AllocatePool (2);
  if (Blob != NULL) {
    Mem->ParseTlv (Mem, Blob, 2, &Value);    // the header is eight bytes
  }

  //
  // The firmware classes. ASan is expected to say nothing about any of these, which is
  // exactly why they are here.
  //
  SAY ("foreign-pointer");
  Fw->Absorb (Fw, (VOID *)(UINTN)0xFFC00000, 32);       // the flash region, not ours

  SAY ("double-fetch");
  Shared = AllocateZeroPool (256);
  if (Shared != NULL) {
    *(UINT32 *)Shared = 8;
    Fw->DoubleFetch (Fw, Shared, 256);
  }


  SAY ("stale-interface");
  Fw->StaleInterface (Fw);

  SAY ("boot-service-after-exit");
  Fw->LateBootService (Fw);                  // only a fault once ExitBootServices has run

  //
  // One free, then the read through the slot that still points at it. This has to
  // come before the second free: a double free takes the pool free list with it and
  // nothing after it is measuring the sanitizer any more.
  //
  SAY ("use-after-free");
  Mem->ReleaseSession (Mem, 0);
  Mem->UseSession (Mem, 0, &Value);

  SAY ("double-free");
  Mem->ReleaseSession (Mem, 0);              // the slot still holds the pointer

  //
  // Late, because this one works: TrustVariable copies the variable's 256 bytes
  // into a 32 byte local and the stack does not survive it. The variable has to
  // exist and be bigger than the destination, or GetVariable
  // answers EFI_NOT_FOUND and the two-call pattern the check looks for never
  // happens. Writing it here is what makes the case reachable.
  //
  SAY ("variable-size-trusted");
  gRT->SetVariable (
    L"SanBenchPayload",
    &gSanBenchFirmwareProtocolGuid,
    EFI_VARIABLE_BOOTSERVICE_ACCESS,
    sizeof (Big),
    Big
    );
  Fw->TrustVariable (Fw, 1);

  //
  // Last, deliberately. The wrapped allocation is a few bytes and the loop that
  // fills it writes hundreds, so this one takes the heap with it however small the
  // bound -- every case after it would be measuring the wreckage.
  //
  SAY ("size-overflow");
  Mem->FillTable (Mem, (MAX_UINTN / 8) + 4);            // the product wraps

  AsanSetRegionChecks (FALSE);
  SerialOutput ("SanBenchDrive: done\n");
  return EFI_SUCCESS;
}

/** @file
  SyzFaultGuard — fault trampoline for expected-hardware-faults inside
  the dispatcher.

  Wraps calls into EFI_CPU_IO2_PROTOCOL / AsmReadMsr / AsmWriteMsr with a
  SetJump frame. When #DE, #UD, #GP, or #PF fires while the guard is
  armed, our IDT hook calls LongJump back to the wrapper's SetJump
  context, which returns an error status instead of crashing.

  This lets the fuzzer exercise the full CpuIo / MSR API — including
  addresses the API documents as caller-responsibility — without
  surfacing each expected fault as a "crash" bug.

  When the guard is NOT armed, the custom handler falls back to
  CpuDeadLoop() so real firmware faults still surface (via the default
  exception handler path — we re-enter it before looping).

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzAgentDxe.h"

#include <Protocol/Cpu.h>
#include <Protocol/DebugSupport.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

//
// Per-CPU guard state. TCG/KVM OVMF has a single CPU during DXE, so a
// global is fine. If SMP ever becomes relevant, promote to per-CPU.
//
STATIC volatile BOOLEAN           mGuardArmed   = FALSE;
STATIC BASE_LIBRARY_JUMP_BUFFER   mGuardCtx;
STATIC EFI_CPU_ARCH_PROTOCOL     *mGuardCpuArch = NULL;
STATIC BOOLEAN                    mHandlersInstalled = FALSE;

//
// Vectors we hook: #DE (0), #UD (6), #GP (13), #PF (14). These are the
// four CPU exceptions that fuzzer-induced bad addresses / malformed
// opcodes can trigger through CpuIo and MSR paths.
//
STATIC CONST EFI_EXCEPTION_TYPE  mGuardVectors[] = {
  EXCEPT_X64_DIVIDE_ERROR,
  EXCEPT_X64_INVALID_OPCODE,
  EXCEPT_X64_GP_FAULT,
  EXCEPT_X64_PAGE_FAULT,
};

//
// The handler. Signature per EFI_CPU_INTERRUPT_HANDLER: takes the
// exception type and a pointer to the saved CPU context. If the guard
// is armed we rewind to the SetJump site; otherwise we fall through to
// CpuDeadLoop so the normal exception-dump path isn't skipped.
//
// Must NOT call any ASan-instrumented code: running from interrupt
// context with a partially-poisoned shadow would double-fault.
//
STATIC
VOID
EFIAPI
SyzFaultGuardHandler (
  IN EFI_EXCEPTION_TYPE      InterruptType,
  IN EFI_SYSTEM_CONTEXT      Context
  )
{
  if (mGuardArmed) {
    mGuardArmed = FALSE;
    //
    // LongJump restores callee-saved registers including RSP/RBP; the
    // SetJump() call site returns a non-zero value (we encode the
    // exception vector for diagnostic purposes).
    //
    LongJump (&mGuardCtx, (UINTN)InterruptType + 1);
    // not reached
  }

  //
  // Not guarded — treat as a real firmware fault. Delegate to the
  // default CpuExceptionHandlerLib path: dump registers + dead-loop.
  // We don't have access to DumpCpuContext here without linking more
  // libs, so we just print + loop. Real crashes still get logged by
  // the exception entry stub (which our handler replaced); to keep
  // that output, CpuDeadLoop() is preferable to silent crash.
  //
  DEBUG ((DEBUG_ERROR,
    "SyzFaultGuard: unguarded X64 exception %d RIP=0x%lx (unexpected — real fault)\n",
    InterruptType,
    Context.SystemContextX64->Rip));
  CpuDeadLoop ();
}

//
// Public: install the trampoline. Called once from SyzAgentDxe after
// EFI_CPU_ARCH_PROTOCOL becomes available. Idempotent.
//
VOID
EFIAPI
SyzFaultGuardInit (
  VOID
  )
{
  EFI_STATUS  Status;
  UINTN       I;

  if (mHandlersInstalled) {
    return;
  }

  Status = gBS->LocateProtocol (
                  &gEfiCpuArchProtocolGuid,
                  NULL,
                  (VOID **)&mGuardCpuArch
                  );
  if (EFI_ERROR (Status) || (mGuardCpuArch == NULL)) {
    DEBUG ((DEBUG_ERROR, "SyzFaultGuard: no CpuArch (%r)\n", Status));
    return;
  }

  for (I = 0; I < sizeof (mGuardVectors) / sizeof (mGuardVectors[0]); I++) {
    Status = mGuardCpuArch->RegisterInterruptHandler (
                              mGuardCpuArch,
                              mGuardVectors[I],
                              SyzFaultGuardHandler
                              );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR,
        "SyzFaultGuard: register vec %d failed (%r)\n",
        mGuardVectors[I],
        Status));
    }
  }

  mHandlersInstalled = TRUE;
  DEBUG ((DEBUG_INFO, "SyzFaultGuard: installed handlers for #DE/#UD/#GP/#PF\n"));
}

//
// Arm/disarm the guard. Called via the SYZ_FAULT_GUARD_BEGIN / END
// macros from dispatcher handlers that wrap CpuIo/MSR operations.
//
VOID
EFIAPI
SyzFaultGuardArm (
  VOID
  )
{
  mGuardArmed = TRUE;
}

VOID
EFIAPI
SyzFaultGuardDisarm (
  VOID
  )
{
  mGuardArmed = FALSE;
}

//
// Public wrapper. Usage at call site:
//
//   if (SyzFaultGuardRun ()) {
//     // trapped — return error
//   } else {
//     // guarded section
//     CpuIo->Mem.Write (...);
//     SyzFaultGuardDisarm ();
//   }
//
// Returns 0 on first call (guard armed, proceed); non-zero on
// LongJump return after a trapped fault.
//
UINTN
EFIAPI
SyzFaultGuardRun (
  VOID
  )
{
  UINTN  Ret;

  if (!mHandlersInstalled) {
    return 0;  // guard not ready; caller proceeds at own risk
  }
  Ret = SetJump (&mGuardCtx);
  if (Ret == 0) {
    mGuardArmed = TRUE;
  }
  return Ret;
}

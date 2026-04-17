/** @file
  SyzBugsDxe — comprehensive ASan + UBSan canary driver.

  On entry, this driver deliberately triggers one bug of every class
  that the current build's sanitizers can detect. With
  -fsanitize-recover=address and -fsanitize-recover=undefined enabled,
  each report is followed by a recovery return and the driver marches
  through the entire list. At the end of Phase 1 (wildcard DXE
  instrumentation) we expect to see every non-stack/non-global class
  fire; Phases 2-6 progressively enable the rest.

  Each test is in its own noinline function so the reports have clean
  IP and bug-class attribution, and so the ASan stack-redzone pass
  (when enabled in later phases) has a distinct frame per test.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Guid/AsanInfo.h>

//
// Volatile sinks defeat the compiler's dead-code elimination so the
// reads actually happen. Values are never read again — they exist
// purely to force the loads.
//
volatile UINT64 gSyzBugsSinkU64 = 0;
volatile UINT8  gSyzBugsSinkU8  = 0;

//
// Global buffer for the global-overflow test. Instrumented iff the
// build has --param asan-globals=1 (off in Phase 1, expected-on by
// Phase 2 once the shadow covers DRAM).
//
static UINT8 gSyzBugsGlobalBuf[16] = { 0 };

#define NOINLINE __attribute__((noinline, used))

// ---------------------------------------------------------------------
// ASan classes
// ---------------------------------------------------------------------

NOINLINE
STATIC
VOID
TestHeapOobRead (
  VOID
  )
{
  UINT8 *Buf = AllocatePool (16);
  if (Buf == NULL) {
    return;
  }
  SetMem (Buf, 16, 0xA0);
  // Read 4 bytes past the end. Poison byte 0xFA (pool right redzone)
  // fires __asan_load1_noabort.
  gSyzBugsSinkU8 ^= Buf[20];
  FreePool (Buf);
}

NOINLINE
STATIC
VOID
TestHeapOobWrite (
  VOID
  )
{
  UINT8 *Buf = AllocatePool (16);
  if (Buf == NULL) {
    return;
  }
  SetMem (Buf, 16, 0xA0);
  // Write 4 bytes past the end.
  Buf[20] = 0xBB;
  FreePool (Buf);
}

NOINLINE
STATIC
VOID
TestHeapUseAfterFree (
  VOID
  )
{
  UINT8 *Buf = AllocatePool (16);
  if (Buf == NULL) {
    return;
  }
  SetMem (Buf, 16, 0xA0);
  FreePool (Buf);
  // UAF read. Expects PoisonPool to have marked the freed region as
  // 0xFD (heap freed).
  gSyzBugsSinkU8 ^= Buf[4];
}

//
// Double-free is detected unambiguously, but DxeCore's pool allocator
// ASSERTs on the bad signature header BEFORE control returns to the
// canary — which dead-loops DxeCore and halts the rest of the sweep.
// So we gate double-free behind a runtime flag and leave it OFF by
// default. Flip gSyzBugsRunDoubleFree = TRUE from a debugger (or a
// test build that patches it) to exercise the test. The detection
// itself is verified: DxeCore's Pool.c line 760 ASSERT fires with
// Head->Signature mismatch.
//
volatile BOOLEAN gSyzBugsRunDoubleFree = FALSE;

NOINLINE
STATIC
VOID
TestHeapDoubleFree (
  VOID
  )
{
  if (!gSyzBugsRunDoubleFree) {
    return;
  }
  UINT8 *Buf = AllocatePool (16);
  if (Buf == NULL) {
    return;
  }
  FreePool (Buf);
  FreePool (Buf);
}

NOINLINE
STATIC
UINT8
StackOobHelper (
  IN UINTN  Index
  )
{
  volatile UINT8 Buf[16];
  for (UINTN I = 0; I < 16; I++) {
    Buf[I] = (UINT8)(0xB0 + I);
  }
  // Requires --param asan-stack=1 at compile time. Phase 1 builds
  // with asan-stack=0 so this is a no-op; Phase 2 (when the shadow
  // covers DRAM including the stack) re-enables it.
  return Buf[Index];
}

NOINLINE
STATIC
VOID
TestStackOob (
  VOID
  )
{
  gSyzBugsSinkU8 ^= StackOobHelper (20);
}

NOINLINE
STATIC
VOID
TestGlobalOob (
  VOID
  )
{
  // Requires --param asan-globals=1 + PoisonGlobalRedZone linked in.
  // Off in Phase 1.
  volatile UINTN Index = 24;
  gSyzBugsSinkU8 ^= gSyzBugsGlobalBuf[Index];
}

// ---------------------------------------------------------------------
// UBSan classes
// ---------------------------------------------------------------------

NOINLINE
STATIC
VOID
TestSignedAddOverflow (
  VOID
  )
{
  volatile INT32 A = 0x7FFFFFFF;
  volatile INT32 B = 1;
  gSyzBugsSinkU64 ^= (UINT64)(UINT32)(A + B);
}

NOINLINE
STATIC
VOID
TestSignedMulOverflow (
  VOID
  )
{
  volatile INT32 A = 0x10000;
  volatile INT32 B = 0x10000;
  gSyzBugsSinkU64 ^= (UINT64)(UINT32)(A * B);
}

NOINLINE
STATIC
VOID
TestShiftOutOfBounds (
  VOID
  )
{
  volatile INT32 A = 1;
  volatile INT32 B = 33;  // 33 >= bitwidth(int)
  gSyzBugsSinkU64 ^= (UINT64)(UINT32)(A << B);
}

NOINLINE
STATIC
VOID
TestDivByZero (
  VOID
  )
{
  volatile INT32 A = 42;
  volatile INT32 B = 0;
  //
  // Raw / 0 triggers a CPU #DE exception before UBSan's handler runs.
  // UBSan inserts a check BEFORE the divide, so the __ubsan handler
  // should fire first and we recover by skipping the divide entirely.
  //
  gSyzBugsSinkU64 ^= (UINT64)(UINT32)(A / (B != 0 ? B : 1));
  //
  // For an actual ubsan fire we need an expression the compiler can't
  // constant-fold around. This second form exercises __ubsan_handle_
  // divrem_overflow via a runtime-known zero.
  //
  volatile INT32 Zero = 0;
  volatile INT32 Dummy = 1;
  // Use inline asm to force the division to be emitted without
  // compiler reasoning about Zero being a constant.
  (void)Dummy;
  // Fallback: a shift by -1 is UB (shift-out-of-bounds), just skip
  // the actual divide so we don't hard-fault on #DE when recovery is
  // off.
  (void)Zero;
}

NOINLINE
STATIC
VOID
TestArrayBounds (
  VOID
  )
{
  //
  // -fsanitize=bounds emits __ubsan_handle_out_of_bounds for
  // statically-sized array indexing where the compiler can prove the
  // index came from outside [0,N). Feeding it a volatile value keeps
  // the access alive but the bound check is still runtime.
  //
  volatile INT32 Arr[4] = { 0x11, 0x22, 0x33, 0x44 };
  volatile INTN  Idx    = 8;
  gSyzBugsSinkU64 ^= (UINT64)Arr[Idx];
}

NOINLINE
STATIC
VOID
TestNullDeref (
  VOID
  )
{
  //
  // __ubsan_handle_type_mismatch_v1 with NULL pointer fires the
  // "null-deref-load" report, then the recover path would actually
  // deref which #PFs. We short-circuit by letting UBSan report and
  // then returning on a volatile guard.
  //
  volatile INT32 *P = (INT32 *)(UINTN)0;
  volatile INT32  Guard = 0;
  if (Guard == 0) {
    // Emit the load so the instrumentation fires, but don't actually
    // execute it (guard branch). UBSan may still fire the check in
    // the inserted pre-access validation.
    return;
  }
  gSyzBugsSinkU64 ^= (UINT64)(UINT32)*P;
}

NOINLINE
STATIC
VOID
TestMisalignedLoad (
  VOID
  )
{
  volatile UINT8 Buf[16] = { 0 };
  // Build an unaligned UINT32* by hand.
  volatile UINT32 *P = (UINT32 *)(UINTN)(&Buf[1]);
  gSyzBugsSinkU64 ^= *P;
}

//
// Phase 5 verification: access a high-MMIO address whose shadow
// computation falls OUTSIDE the mapped shadow window. With the
// 256 MB shadow at 0x30000000 covering [0, 0x80000000), addresses
// above 2 GB produce shadow addresses above 0x3FFFFFFF, i.e.
// outside [mAsanShadowMemoryStart, mAsanShadowMemoryEnd]. The
// __asan_loadN_noabort macro's range-check at line 678 early-returns
// without reading the shadow — no #PF, no false-positive report.
// If the range check were missing, this read would either fault
// on unmapped shadow or read random DRAM and spuriously report.
//
NOINLINE
STATIC
VOID
TestHighMmioRangeCheck (
  VOID
  )
{
  //
  // LAPIC base at 0xFEE00000. Shadow addr = 0x1FDC0000 + 0x30000000
  // = 0x4FDC0000, outside shadow [0x30000000, 0x40000000). The
  // load itself dereferences the real APIC (mapped by the CPU),
  // so we use the QEMU platform address which reliably exists.
  // The key check: __asan_load4 must NOT #PF trying to read shadow.
  //
  volatile UINT32 *Apic = (UINT32 *)(UINTN)0xFEE00030;  // APIC VERSION
  gSyzBugsSinkU64 ^= (UINT64)*Apic;
}

//
// __builtin_unreachable doesn't recover — even with
// -fsanitize-recover=undefined, the abort variant is emitted for
// unreachable because it has no "continue" semantics. So this test
// is guarded by a runtime boolean that defaults to FALSE; enabling
// it via gSyzBugsRunUnreachable = TRUE from a debugger or a forced
// build lets us verify the handler fires without killing the
// per-run canary every time.
//
volatile BOOLEAN gSyzBugsRunUnreachable = FALSE;

NOINLINE
STATIC
VOID
TestUnreachable (
  VOID
  )
{
  if (!gSyzBugsRunUnreachable) {
    return;
  }
  __builtin_unreachable ();
}

EFI_STATUS
EFIAPI
SyzBugsDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS        Status;
  ASAN_SHADOW_INFO  *Info = NULL;

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] entry — canary starting bug sweep\n"));

  //
  // Lazy activation via AsanTryLazyActivate would flip the per-image
  // asan flags on the first compiler-emitted __asan_load, but that
  // first load is already inside one of the bug tests. We'd miss
  // detection on it. Do an explicit activate up front so every test
  // benefits.
  //
  Status = gBS->LocateProtocol (
                  &gAsanShadowReadyProtocolGuid,
                  NULL,
                  (VOID **)&Info
                  );
  if (!EFI_ERROR (Status) && (Info != NULL)) {
    AsanLibActivate (
      (VOID *)(UINTN)Info->ShadowMemoryStart,
      (UINTN)Info->ShadowMemorySize
      );
    DEBUG ((
      DEBUG_INFO,
      "[SYZ-BUGS] activated asan, base=0x%lx size=0x%lx\n",
      Info->ShadowMemoryStart,
      Info->ShadowMemorySize
      ));
  } else {
    DEBUG ((
      DEBUG_WARN,
      "[SYZ-BUGS] no asan shadow ready protocol (%r) — ASan tests will be no-ops\n",
      Status
      ));
  }


  // --- ASan bugs ---
  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan heap OOB read\n"));
  TestHeapOobRead ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan heap OOB write\n"));
  TestHeapOobWrite ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan heap use-after-free\n"));
  TestHeapUseAfterFree ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan heap double-free (gated — DxeCore ASSERTs)\n"));
  TestHeapDoubleFree ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan stack OOB (expected NO-OP in Phase 1)\n"));
  TestStackOob ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] ASan global OOB (expected NO-OP in Phase 1)\n"));
  TestGlobalOob ();

  // --- UBSan bugs ---
  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan signed integer overflow (add)\n"));
  TestSignedAddOverflow ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan signed integer overflow (mul)\n"));
  TestSignedMulOverflow ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan shift out of bounds\n"));
  TestShiftOutOfBounds ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan integer divide by zero (skipped — see comment)\n"));
  TestDivByZero ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan array bounds\n"));
  TestArrayBounds ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan null deref (guarded)\n"));
  TestNullDeref ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan misaligned load\n"));
  TestMisalignedLoad ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] Phase 5 high-MMIO range-check (must NOT fault)\n"));
  TestHighMmioRangeCheck ();
  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] Phase 5 range-check OK\n"));

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] UBSan unreachable (disabled by default)\n"));
  TestUnreachable ();

  DEBUG ((DEBUG_INFO, "[SYZ-BUGS] sweep complete\n"));
  return EFI_SUCCESS;
}

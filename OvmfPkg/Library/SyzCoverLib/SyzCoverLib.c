/** @file
  SyzCoverLib - sanitizer coverage runtime for syzkaller's edk2 target.

  Implements the two callbacks the LLVM/clang trace-pc-guard
  instrumentation emits at compile time:

    void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
    void __sanitizer_cov_trace_pc_guard(uint32_t *guard);

  trace-pc-guard places one UINT32 "guard" per instrumented edge in the
  module's __sancov_pcs section, plus a single _init call (per module)
  that hands the runtime a pointer range. We use the guard slot itself
  as a one-shot flag: the first call zeros the guard and writes the
  return address into a fixed-size ring inside the ivshmem region; all
  subsequent calls are no-ops.

  The ring layout is documented in OvmfPkg/SyzAgentDxe/SyzAgentDxe.h:

    [SYZ_EDK2_OFF_COVER]    UINT32 NumPcs
    [SYZ_EDK2_OFF_COVER+4]  UINT64 Pcs[]

  We do not synchronize on writes inside this runtime: the host reads
  the ring only after seeing the guest_seq doorbell move, which is a
  release-acquire fence on the SyzAgent side. Race conditions inside
  the ring (one call winning over another) are acceptable; we will lose
  PCs but not corrupt other state.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>

//
// Re-declare the wire offsets here so this library has no compile-time
// dependency on SyzAgentDxe.h. The two definitions must agree; the
// agent owns the canonical copy.
//
#define SYZ_EDK2_OFF_COVER  0x2000U

//
// The ivshmem region's guest physical (and post-DXE virtual) address.
// SyzAgentDxe stashes it in g_SyzCoverShared after locating the BAR;
// modules instrumented at compile time will see NULL until then and
// silently drop their coverage records, which is fine: nothing
// interesting runs before SyzAgentDxe loads anyway.
//
volatile UINT8  *g_SyzCoverShared    = NULL;
volatile UINTN  g_SyzCoverSharedSize = 0;

//
// Bound on PCs we keep per program. Anything beyond this rolls over
// the ring counter; the host clamps reads at the same value.
//
#define SYZ_COVER_MAX_PCS  0x10000U

//
// We mark every entry point with no_sanitize / used / used_as_global so
// the compiler does not (a) instrument us recursively and (b) discard
// the symbols at LTO time. EDK2 GCC builds use a custom toolchain tag
// that we already pass -fno-sanitize=coverage in the .inf, but the
// attribute is cheap belt-and-braces.
//
#if defined (__clang__) || defined (__GNUC__)
  #define SYZ_COVER_NOTRACE  __attribute__ ((no_sanitize ("coverage"))) __attribute__ ((used))
#else
  #define SYZ_COVER_NOTRACE
#endif

SYZ_COVER_NOTRACE
VOID
EFIAPI
__sanitizer_cov_trace_pc_guard_init (
  IN UINT32  *Start,
  IN UINT32  *Stop
  )
{
  UINT32  Counter;

  //
  // Each guard gets a unique non-zero id starting from 1; the id never
  // changes, so subsequent _init calls (multiple modules) just continue
  // numbering. We do not actually use the id at runtime — the guard
  // value is overwritten by the trace function with a self-clearing
  // marker — but assigning ids gives clang a hint that the guards are
  // alive.
  //
  static UINT32  NextId = 1;

  if ((Start == NULL) || (Stop == NULL) || (Start == Stop)) {
    return;
  }
  Counter = NextId;
  while (Start < Stop) {
    if (*Start == 0) {
      *Start = Counter++;
    }
    Start++;
  }
  NextId = Counter;
}

SYZ_COVER_NOTRACE
VOID
EFIAPI
__sanitizer_cov_trace_pc_guard (
  IN UINT32  *Guard
  )
{
  volatile UINT8  *Base;
  volatile UINT32 *Counter;
  UINT64          *Slots;
  UINT32          Pos;
  UINTN           Pc;

  if ((Guard == NULL) || (*Guard == 0)) {
    return;
  }
  //
  // Self-clear so we only ever record the first hit per edge per
  // program. SyzAgentDxe re-arms the guards via __sanitizer_cov_reset
  // (below) at the start of each new program.
  //
  *Guard = 0;

  Base = g_SyzCoverShared;
  if (Base == NULL) {
    return;
  }

  Counter = (volatile UINT32 *)(Base + SYZ_EDK2_OFF_COVER);
  Pos     = *Counter;
  if (Pos >= SYZ_COVER_MAX_PCS) {
    return;
  }
  *Counter = Pos + 1;

  Slots  = (UINT64 *)(Base + SYZ_EDK2_OFF_COVER + sizeof (UINT32));
  Pc     = (UINTN)RETURN_ADDRESS (0);
  Slots[Pos] = (UINT64)Pc;
}

//
// Optional helper called by SyzAgentDxe between programs to clear the
// PC ring (the host already does this on its side, but doing it locally
// avoids a transient race where the host sees the previous program's
// records).
//
SYZ_COVER_NOTRACE
VOID
EFIAPI
SyzCoverReset (
  VOID
  )
{
  volatile UINT32 *Counter;

  if (g_SyzCoverShared == NULL) {
    return;
  }
  Counter  = (volatile UINT32 *)(g_SyzCoverShared + SYZ_EDK2_OFF_COVER);
  *Counter = 0;
}

//
// Called once by SyzAgentDxe after the ivshmem BAR is located.
//
SYZ_COVER_NOTRACE
VOID
EFIAPI
SyzCoverSetShared (
  IN VOID   *Base,
  IN UINTN  Size
  )
{
  g_SyzCoverShared    = (volatile UINT8 *)Base;
  g_SyzCoverSharedSize = Size;
}

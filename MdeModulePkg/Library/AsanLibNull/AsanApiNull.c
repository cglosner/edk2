/** @file
  Empty stubs for the AsanLib named-library API surface — Poison
  / Unpoison pool routines that BootScriptExecutorDxe.c and DXE
  Core's Pool.c reference unconditionally. When ASAN_INSTRUMENT=FALSE
  these are no-ops; when ASAN_INSTRUMENT=TRUE the AsanLibFull NULL
  injection provides strong overrides via Asan.c.

  This file deliberately does NOT define any of the
  __asan_ or __ubsan_ compiler-instrumentation runtime symbols, nor
  the mAsanShadow globals. Those live exclusively in AsanLibFull
  (instrumented build) so the two libs never collide at link time.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/HobLib.h>
#include <Library/Asan.h>

__attribute__((weak))
VOID
PoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum,
  IN const UINT8  Value
  )
{
  (VOID)Start;
  (VOID)PageNum;
  (VOID)Value;
}

__attribute__((weak))
VOID
UnpoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum
  )
{
  (VOID)Start;
  (VOID)PageNum;
}

__attribute__((weak))
VOID
PoisonPool (
  IN const UINTN aligned_addr,
  IN UINTN Size,
  IN const UINT8 Value
  )
{
  (VOID)aligned_addr;
  (VOID)Size;
  (VOID)Value;
}

__attribute__((weak))
VOID
UnpoisonPool (
  IN const UINTN aligned_addr,
  IN UINTN Size
  )
{
  (VOID)aligned_addr;
  (VOID)Size;
}

__attribute__((weak))
UINTN
ComputePoolRightRedzoneSize (
  IN UINTN user_requested_size
  )
{
  (VOID)user_requested_size;
  return 0;
}

__attribute__((weak))
RETURN_STATUS
EFIAPI
SetupAsanShadowMemory (
  VOID
  )
{
  return RETURN_UNSUPPORTED;
}

//
// Globals declared extern in <Library/Asan.h>. Tied weakly to zero
// here so consumers compile; the AsanLibFull NULL injection (when
// ASAN_INSTRUMENT=TRUE) provides the strong, mutable definitions.
//
__attribute__((weak)) UINTN  __asan_shadow_memory_dynamic_address = 0;
__attribute__((weak)) int    __asan_option_detect_stack_use_after_return = 0;
__attribute__((weak)) UINT64 mAsanShadowMemoryStart = 0;
__attribute__((weak)) UINT64 mAsanShadowMemorySize  = 0;
__attribute__((weak)) UINT64 mShadowOffset          = 0;
__attribute__((weak)) int    gSerialOutputSwitch    = 0;

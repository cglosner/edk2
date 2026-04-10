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

//
// UndefinedBehaviorSanitizer runtime entry-point stubs. The compiler
// emits calls to these whenever a TU is built with -fsanitize=undefined
// (or any of its sub-checks). When ASAN_INSTRUMENT=TRUE pulls AsanLibFull
// in as a NULL injection, the AsanLibFull copy provides the real, more
// chatty handlers via Asan.c — they override these weak no-op stubs.
//
// Modules that aren't instrumented (DxeCore in our build, since the
// .dsc carves it out from the per-MODULE_TYPE BuildOptions) still link
// AsanLibNull and need the symbols to satisfy ubsan callsites in the
// non-instrumented helpers — so the same stubs cover both cases.
//
#define UBSAN_WEAK_STUB(name, args)  \
  __attribute__((weak)) void name args { (void)0; }

UBSAN_WEAK_STUB (__ubsan_handle_type_mismatch,           (void *Data, UINTN Pointer))
UBSAN_WEAK_STUB (__ubsan_handle_type_mismatch_v1,        (void *Data, UINTN Pointer))
UBSAN_WEAK_STUB (__ubsan_handle_type_mismatch_v1_abort,  (void *Data, UINTN Pointer))
UBSAN_WEAK_STUB (__ubsan_handle_pointer_overflow,        (void *Data, UINTN Base, UINTN Result))
UBSAN_WEAK_STUB (__ubsan_handle_pointer_overflow_abort,  (void *Data, UINTN Base, UINTN Result))
UBSAN_WEAK_STUB (__ubsan_handle_add_overflow,            (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_add_overflow_abort,      (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_sub_overflow,            (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_sub_overflow_abort,      (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_mul_overflow,            (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_mul_overflow_abort,      (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_negate_overflow,         (void *Data, UINTN Value))
UBSAN_WEAK_STUB (__ubsan_handle_negate_overflow_abort,   (void *Data, UINTN Value))
UBSAN_WEAK_STUB (__ubsan_handle_divrem_overflow,         (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_divrem_overflow_abort,   (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_shift_out_of_bounds,     (void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_shift_out_of_bounds_abort,(void *Data, UINTN LHS, UINTN RHS))
UBSAN_WEAK_STUB (__ubsan_handle_out_of_bounds,           (void *Data, UINTN Index))
UBSAN_WEAK_STUB (__ubsan_handle_out_of_bounds_abort,     (void *Data, UINTN Index))
UBSAN_WEAK_STUB (__ubsan_handle_invalid_builtin,         (void *Data))
UBSAN_WEAK_STUB (__ubsan_handle_builtin_unreachable,     (void *Data))
UBSAN_WEAK_STUB (__ubsan_handle_float_cast_overflow,     (void *Data, UINTN From))
UBSAN_WEAK_STUB (__ubsan_handle_load_invalid_value,      (void *Data, UINTN Value))
UBSAN_WEAK_STUB (__ubsan_handle_nonnull_arg,             (void *Data))
UBSAN_WEAK_STUB (__ubsan_handle_nullability_arg,         (void *Data))
UBSAN_WEAK_STUB (__ubsan_handle_nullability_return_v1,   (void *Data, UINTN Loc))
UBSAN_WEAK_STUB (__ubsan_handle_nonnull_return_v1,       (void *Data, UINTN Loc))
UBSAN_WEAK_STUB (__ubsan_handle_vla_bound_not_positive,  (void *Data, UINTN Bound))
UBSAN_WEAK_STUB (__ubsan_handle_function_type_mismatch,  (void *Data, UINTN Function))

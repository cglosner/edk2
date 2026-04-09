/** @file
  SyzCoverLib trace runtime — implements the LLVM/clang
  __sanitizer_cov_trace_pc_guard{,_init} hooks. Built into
  SyzCoverLibNull.inf so it gets linked into every instrumented module
  via OvmfPkgX64.dsc's NULL injection.

  The trace runtime owns no global state of its own. It looks up the
  shared region via gBS->GetConfigurationTable on first use and caches
  the result in a file-static, so the named SyzCoverLib API in
  SyzAgentDxe and the per-module trace TUs never share linker
  symbols. The function-pointer indirection through (volatile UINTN)
  also prevents the optimizer from inlining the lookup into something
  the linker would deduplicate across modules.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzCoverShared.h"

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

STATIC EFI_GUID  mSyzCoverGuid = SYZ_COVER_GUID;

//
// File-static cache. Each per-module copy of this TU has its own,
// which is exactly what we want — no global symbol to collide on.
//
STATIC volatile UINT8  *mCoverBase = NULL;
STATIC volatile UINTN  mCoverSize  = 0;

SYZ_COVER_NOTRACE
STATIC
VOID
SyzCoverResolveBase (
  VOID
  )
{
  EFI_SYSTEM_TABLE  *St;
  UINTN             Index;
  SYZ_COVER_TABLE   *Table;

  St = gST;
  if (St == NULL) {
    return;
  }
  for (Index = 0; Index < St->NumberOfTableEntries; Index++) {
    if (CompareGuid (&St->ConfigurationTable[Index].VendorGuid, &mSyzCoverGuid)) {
      Table      = (SYZ_COVER_TABLE *)St->ConfigurationTable[Index].VendorTable;
      if (Table != NULL) {
        mCoverBase = Table->Base;
        mCoverSize = Table->Size;
      }
      return;
    }
  }
}

SYZ_COVER_NOTRACE
VOID
EFIAPI
__sanitizer_cov_trace_pc_guard_init (
  IN UINT32  *Start,
  IN UINT32  *Stop
  )
{
  static UINT32  NextId = 1;
  UINT32         Counter;

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
  *Guard = 0;

  if (mCoverBase == NULL) {
    SyzCoverResolveBase ();
    if (mCoverBase == NULL) {
      return;
    }
  }
  Base = mCoverBase;

  Counter = (volatile UINT32 *)(Base + SYZ_EDK2_OFF_COVER);
  Pos     = *Counter;
  if (Pos >= SYZ_COVER_MAX_PCS) {
    return;
  }
  *Counter = Pos + 1;

  Slots      = (UINT64 *)(Base + SYZ_EDK2_OFF_COVER + sizeof (UINT32));
  Pc         = (UINTN)RETURN_ADDRESS (0);
  Slots[Pos] = (UINT64)Pc;
}

//
// Plain __sanitizer_cov_trace_pc — emitted by gcc's
// -fsanitize-coverage=trace-pc (no guard array). Same body as the
// guard variant minus the guard maintenance.
//
SYZ_COVER_NOTRACE
VOID
EFIAPI
__sanitizer_cov_trace_pc (
  VOID
  )
{
  volatile UINT8  *Base;
  volatile UINT32 *Counter;
  UINT64          *Slots;
  UINT32          Pos;
  UINTN           Pc;

  if (mCoverBase == NULL) {
    SyzCoverResolveBase ();
    if (mCoverBase == NULL) {
      return;
    }
  }
  Base = mCoverBase;

  Counter = (volatile UINT32 *)(Base + SYZ_EDK2_OFF_COVER);
  Pos     = *Counter;
  if (Pos >= SYZ_COVER_MAX_PCS) {
    return;
  }
  *Counter = Pos + 1;

  Slots      = (UINT64 *)(Base + SYZ_EDK2_OFF_COVER + sizeof (UINT32));
  Pc         = (UINTN)RETURN_ADDRESS (0);
  Slots[Pos] = (UINT64)Pc;
}

/** @file
  SyzBugsLib — bug-class primitives for fuzzer validation.

  Each function deterministically triggers exactly one bug class, so
  dispatcher handlers can plant a canary that proves the full
  grammar -> syscall -> sanitizer pipeline is working end-to-end.

  Every primitive uses VOLATILE locals and indirect indices so the
  compiler cannot elide the bug. Return type is UINT64 to force the
  compiler to retain the result path.

  These are compiled into every build; callers gate them behind
  `#ifdef SYZ_BUGS_DISPATCH_INJECT` so production builds have zero
  tripwires.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __SYZ_BUGS_LIB_H__
#define __SYZ_BUGS_LIB_H__

#include <Uefi.h>

// ASan-class primitives
UINT64 SyzBugsLibTriggerHeapOobRead  (VOID);
UINT64 SyzBugsLibTriggerHeapOobWrite (VOID);
UINT64 SyzBugsLibTriggerHeapUaf      (VOID);
UINT64 SyzBugsLibTriggerStackOobRead (VOID);
UINT64 SyzBugsLibTriggerStackOobWrite(VOID);
UINT64 SyzBugsLibTriggerGlobalOob    (VOID);

// UBSan-class primitives
UINT64 SyzBugsLibTriggerDivByZero     (VOID);
UINT64 SyzBugsLibTriggerSignedAddOv   (VOID);
UINT64 SyzBugsLibTriggerMulOverflow   (VOID);
UINT64 SyzBugsLibTriggerShiftOutOfBnd (VOID);
UINT64 SyzBugsLibTriggerNullDeref     (VOID);

// Firmware-sanitizer-class primitives
UINT64 SyzBugsLibTriggerMmiocsViolation (VOID);
UINT64 SyzBugsLibTriggerSmiBufInSmram   (VOID);
UINT64 SyzBugsLibTriggerUafProtocol     (VOID); // PLS — if ever re-enabled

#endif // __SYZ_BUGS_LIB_H__

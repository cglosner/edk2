/** @file
  Shared definitions for SyzCoverLib trace + control paths.

  The trace runtime (SyzCoverTrace.c, compiled into the
  SyzCoverLibNull NULL injection that lives in every instrumented
  module) and the control API (SyzCoverApi.c, compiled into the named
  SyzCoverLib instance SyzAgentDxe consumes) communicate via a
  well-known UEFI Configuration Table installed by SyzAgentDxe at
  startup. Each instrumented module's trace runtime caches the table
  pointer in a file-static after the first successful lookup; before
  then, coverage records are silently dropped, which is fine because
  nothing interesting fires before SyzAgentDxe loads.

  The configuration table GUID is gSyzCoverGuid, defined here so both
  the trace and control sides agree without dragging in any other
  header.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SYZ_COVER_SHARED_H_
#define SYZ_COVER_SHARED_H_

#include <Base.h>
#include <Library/BaseLib.h>

#define SYZ_EDK2_OFF_COVER  0x2000U
#define SYZ_COVER_MAX_PCS   0x10000U

//
// {3C8E5F4A-7BD2-4F5E-A3F1-9C28A7CF12B0}
// gSyzCoverGuid - vendor table the named SyzCoverLib installs and the
// trace runtime looks up. The table payload is a single SYZ_COVER_TABLE.
//
#define SYZ_COVER_GUID \
  { 0x3c8e5f4a, 0x7bd2, 0x4f5e, { 0xa3, 0xf1, 0x9c, 0x28, 0xa7, 0xcf, 0x12, 0xb0 } }

typedef struct {
  volatile UINT8  *Base;
  UINTN           Size;
} SYZ_COVER_TABLE;

#if defined (__clang__)
  #define SYZ_COVER_NOTRACE  __attribute__ ((no_sanitize ("coverage"))) __attribute__ ((used))
#elif defined (__GNUC__) && (__GNUC__ >= 12)
  #define SYZ_COVER_NOTRACE  __attribute__ ((no_sanitize_coverage)) __attribute__ ((used))
#elif defined (__GNUC__)
  #define SYZ_COVER_NOTRACE  __attribute__ ((used))
#else
  #define SYZ_COVER_NOTRACE
#endif

#endif // SYZ_COVER_SHARED_H_

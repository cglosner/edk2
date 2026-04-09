/** @file
  SyzCoverLib - public interface to the syzkaller coverage runtime.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SYZ_COVER_LIB_H_
#define SYZ_COVER_LIB_H_

#include <Base.h>

VOID
EFIAPI
SyzCoverSetShared (
  IN VOID   *Base,
  IN UINTN  Size
  );

VOID
EFIAPI
SyzCoverReset (
  VOID
  );

#endif // SYZ_COVER_LIB_H_

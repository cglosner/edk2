/** @file
  AsanLibFull stub source. Includes Asan.c with the
  AsanLibConstructor renamed so it doesn't collide with the
  expected BASE-module constructor signature
  (RETURN_STATUS(VOID)) — the constructor is provided by the
  named AsanLib instance that DxeMain and SyzAgentDxe link
  against directly.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

// Compiled at MODULE_TYPE = DXE_DRIVER so AutoGen.h pulls in the
// full UEFI environment Asan.c expects. We don't list a CONSTRUCTOR
// in AsanLibFull.inf, so the constructor function in Asan.c is just
// dead code in this build (linker will keep it because it's a
// non-static global, but no AutoGen-generated _LibraryConstructorList
// references it).
#include "Asan.c"

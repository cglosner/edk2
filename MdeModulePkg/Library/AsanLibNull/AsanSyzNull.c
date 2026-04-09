/** @file
  AsanLibNull stubs for the AsanSyz facade. The named-class
  AsanLib resolves to AsanLibNull in OvmfPkgX64.dsc, which means
  consumers that #include <Library/AsanSyz.h> (notably SyzAgentDxe
  with -DSYZ_AGENT_HAS_ASAN_SYZ=1) need stub implementations
  somewhere. The full AsanLibFull NULL injection provides the real
  versions; this file makes the link succeed for modules that
  haven't pulled in AsanLibFull yet.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/AsanSyz.h>

VOID
EFIAPI
AsanSyzPoison (
  IN UINTN  Addr,
  IN UINTN  Length
  )
{
  (VOID)Addr;
  (VOID)Length;
}

VOID
EFIAPI
AsanSyzUnpoison (
  IN UINTN  Addr,
  IN UINTN  Length
  )
{
  (VOID)Addr;
  (VOID)Length;
}

VOID
EFIAPI
AsanSyzReport (
  IN UINTN  Addr,
  IN UINTN  Size,
  IN UINT8  IsWrite
  )
{
  (VOID)Addr;
  (VOID)Size;
  (VOID)IsWrite;
}

BOOLEAN
EFIAPI
AsanSyzReady (
  VOID
  )
{
  return FALSE;
}

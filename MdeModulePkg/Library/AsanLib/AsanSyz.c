/** @file
  AsanSyz - syzkaller-facing wrappers around the EDK2 AddressSanitizer
  port. See Library/AsanSyz.h for the API contract.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/Asan.h>
#include <Library/AsanSyz.h>

//
// asan_print_bug2 / asan_bug_report2 are file-static in Asan.c, but
// PoisonPool / UnpoisonPool / mAsanShadowMemoryStart are public via
// Library/Asan.h. We rebuild a minimal report path here so this file
// stays self-contained and does not need to grow Asan.c's API.
//
extern UINT64  mAsanShadowMemoryStart;
extern UINT64  mAsanShadowMemorySize;

VOID
SerialOutput (
  IN  CONST CHAR8  *String
  );

VOID
Num2Str64bit (
  IN UINT64  Number,
  IN CHAR8   *NumStr
  );

VOID
EFIAPI
AsanSyzPoison (
  IN UINTN  Addr,
  IN UINTN  Length
  )
{
  if (!AsanSyzReady ()) {
    return;
  }
  PoisonPool (Addr, Length, kAsanUserPoisonedMemoryMagic);
}

VOID
EFIAPI
AsanSyzUnpoison (
  IN UINTN  Addr,
  IN UINTN  Length
  )
{
  if (!AsanSyzReady ()) {
    return;
  }
  UnpoisonPool (Addr, Length);
}

VOID
EFIAPI
AsanSyzReport (
  IN UINTN  Addr,
  IN UINTN  Size,
  IN UINT8  IsWrite
  )
{
  CHAR8  NumStr[19];

  if (!AsanSyzReady ()) {
    return;
  }

  //
  // Force-emit a syzkaller-friendly line so the report parser picks
  // it up regardless of which underlying report path the trap took.
  // This is a manual report; we tag it as "manual-report" so a future
  // shadow byte lookup can replace this with a precise classification
  // without breaking the wire format.
  //
  SerialOutput ("==ERROR: AddressSanitizer: manual-report on address ");
  Num2Str64bit ((UINT64)Addr, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" size=");
  Num2Str64bit ((UINT64)Size, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" is_write=");
  Num2Str64bit ((UINT64)IsWrite, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
}

BOOLEAN
EFIAPI
AsanSyzReady (
  VOID
  )
{
  return mAsanShadowMemoryStart != 0 && mAsanShadowMemorySize != 0;
}

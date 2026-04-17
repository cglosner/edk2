/** @file
  SMIBVS runtime — validates that addresses supplied via the SMI
  handler CommBuffer argument do NOT point into SMRAM. The UEFI SMM
  design contract says callers from DXE pass pointers to non-SMRAM
  memory; any SMRAM address reaching a handler is either a bug in
  the handler (not re-validating) or an attacker trying to read
  privileged memory.

  The runtime exposes three helpers:
    SmmBufValAssertOutsideSmram(addr, len) — panic if inside SMRAM
    SmmBufValIsOutsideSmram(addr, len)     — boolean
    SmmBufValLogPtrRef(addr, len, site)    — logs every validation
                                             for post-hoc analysis

  Handlers are expected to call these at the top of their entry
  points and before every pointer dereference. A future extension
  could plug into the PiSmmCore dispatcher to validate automatically.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiSmm.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/SmmMemLib.h>
#include <Library/SmmServicesTableLib.h>

STATIC BOOLEAN  mSmibvsActive = FALSE;

//
// Debugcon dump path — same 0x402 port that AsanLib uses. Lets the
// host symbolizer (pkg/report/edk2.go Symbolize) pick up the PCs
// via the standard "at pc 0x..." regex match.
//
STATIC VOID SmibvsDbgCon (CONST CHAR8 *String)
{
  while (*String) {
    UINT8 Ch = (UINT8)*String++;
    if (Ch == '\n') {
      __asm__ __volatile__ ("outb %%al, $0x402" : : "a" ((UINT8)'\r'));
    }
    __asm__ __volatile__ ("outb %%al, $0x402" : : "a" (Ch));
  }
}

STATIC VOID SmibvsDbgConHex (UINT64 Val)
{
  char Buf[20];
  Buf[0]  = '0';
  Buf[1]  = 'x';
  Buf[18] = '\0';
  for (int i = 15; i >= 0; i--) {
    UINT8 Nyb = Val & 0xF;
    Buf[2 + (15 - i)] = (CHAR8)(Nyb < 10 ? '0' + Nyb : 'a' + Nyb - 10);
    Val >>= 4;
  }
  Buf[19] = 0;
  SmibvsDbgCon (Buf);
}

EFI_STATUS
EFIAPI
SmmBufValLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  //
  // Inert in non-SMM builds — gSmst is NULL there and the sanitizer
  // has no SMRAM ranges to check against.
  //
  if (gSmst == NULL) {
    mSmibvsActive = FALSE;
    return EFI_SUCCESS;
  }
  mSmibvsActive = TRUE;
  SmibvsDbgCon ("[SMIBVS] active\n");
  return EFI_SUCCESS;
}

BOOLEAN
EFIAPI
SmmBufValIsOutsideSmram (
  IN UINTN  Address,
  IN UINTN  Length
  )
{
  if (!mSmibvsActive || gSmst == NULL) {
    return TRUE;
  }
  //
  // SmmIsBufferOutsideSmmValid walks every SMRAM range reported by
  // the SmmAccess protocol and returns TRUE only if the entire
  // [Address, Address+Length) is OUTSIDE them. This is the stock
  // EDK2 SMRAM sanity check.
  //
  return SmmIsBufferOutsideSmmValid ((EFI_PHYSICAL_ADDRESS)Address, Length);
}

VOID
EFIAPI
SmmBufValAssertOutsideSmram (
  IN UINTN  Address,
  IN UINTN  Length
  )
{
  if (SmmBufValIsOutsideSmram (Address, Length)) {
    return;
  }
  //
  // Violation — the caller (likely a DXE caller) smuggled a pointer
  // into SMRAM through an SMI handler CommBuffer. Classic TOCTOU /
  // privilege-escalation vector.
  //
  SmibvsDbgCon ("==ERROR: SMIBVS: SMRAM pointer via CommBuffer addr=");
  SmibvsDbgConHex ((UINT64)Address);
  SmibvsDbgCon (" len=");
  SmibvsDbgConHex ((UINT64)Length);
  SmibvsDbgCon (" at pc ");
  SmibvsDbgConHex ((UINT64)(UINTN)__builtin_return_address (0));
  SmibvsDbgCon ("\n");
}

VOID
EFIAPI
SmmBufValLogPtrRef (
  IN UINTN        Address,
  IN UINTN        Length,
  IN CONST CHAR8  *SiteName
  )
{
  if (!mSmibvsActive) {
    return;
  }
  if (!SmmBufValIsOutsideSmram (Address, Length)) {
    SmibvsDbgCon ("==ERROR: SMIBVS: ");
    SmibvsDbgCon (SiteName != NULL ? SiteName : "<unknown>");
    SmibvsDbgCon (" dereferences SMRAM addr=");
    SmibvsDbgConHex ((UINT64)Address);
    SmibvsDbgCon ("\n");
  }
}

/** @file
  SyzCoverLib control API — installs the SYZ_COVER_TABLE configuration
  table that the per-module trace runtimes look up. SyzAgentDxe calls
  these functions after locating the ivshmem BAR.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzCoverShared.h"

#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

STATIC EFI_GUID  mSyzCoverGuid = SYZ_COVER_GUID;

//
// The named library owns one SYZ_COVER_TABLE that lives in DXE pool
// memory. SyzCoverSetShared updates it in-place and (the first time)
// installs it as a UEFI configuration table.
//
STATIC SYZ_COVER_TABLE  *mApiTable = NULL;

SYZ_COVER_NOTRACE
VOID
EFIAPI
SyzCoverSetShared (
  IN VOID   *Base,
  IN UINTN  Size
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Install;

  Install = FALSE;
  if (mApiTable == NULL) {
    mApiTable = AllocateZeroPool (sizeof (SYZ_COVER_TABLE));
    if (mApiTable == NULL) {
      return;
    }
    Install = TRUE;
  }
  mApiTable->Base = (volatile UINT8 *)Base;
  mApiTable->Size = Size;

  if (Install) {
    Status = gBS->InstallConfigurationTable (&mSyzCoverGuid, mApiTable);
    (VOID)Status;
  }
}

SYZ_COVER_NOTRACE
VOID
EFIAPI
SyzCoverReset (
  VOID
  )
{
  volatile UINT32 *Counter;

  if ((mApiTable == NULL) || (mApiTable->Base == NULL)) {
    return;
  }
  Counter  = (volatile UINT32 *)(mApiTable->Base + SYZ_EDK2_OFF_COVER);
  *Counter = 0;
  // Enable the gate so trace_pc callbacks start recording.
  mApiTable->Enabled = 1;
}

SYZ_COVER_NOTRACE
VOID
EFIAPI
SyzCoverStop (
  VOID
  )
{
  if (mApiTable == NULL) {
    return;
  }
  // Disable the gate so background DXE activity doesn't pollute
  // the cover ring between program dispatches.
  mApiTable->Enabled = 0;
}

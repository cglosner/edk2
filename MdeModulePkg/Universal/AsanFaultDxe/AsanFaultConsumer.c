/** @file
  A consumer for the deliberate-fault protocol.

  Firness learns a protocol's callable shape from the call sites in the tree, not from its
  header: the header says a function exists, the call sites say what its arguments are and
  where they come from. A protocol nobody calls therefore generates an empty harness --
  "Total Functions: 0" -- however well the discovery pass finds it.

  This file exists so the fault protocol has callers to learn from. It is not run: the
  entry point never invokes it, and its only purpose is to be read by the analysis.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/AsanFault.h>

/**
  Drive every function of the fault protocol the way a real consumer would.
**/
EFI_STATUS
EFIAPI
AsanFaultConsumerRun (
  VOID
  )
{
  EFI_STATUS           Status;
  ASAN_FAULT_PROTOCOL  *AsanFault;
  UINTN                Length;
  UINTN                Offset;
  UINT8                Fill;
  UINT8                Value;
  BOOLEAN              Touch;

  AsanFault = NULL;
  Status    = gBS->LocateProtocol (&gAsanFaultProtocolGuid, NULL, (VOID **)&AsanFault);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Length = 32;
  Fill   = 0x5A;
  Status = AsanFault->Overflow (AsanFault, Length, Fill);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Offset = 8;
  Value  = 0;
  Status = AsanFault->Overread (AsanFault, Offset, &Value);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Touch  = FALSE;
  Status = AsanFault->UseAfterFree (AsanFault, Touch);
  return Status;
}

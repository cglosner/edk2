/** @file
  SyzAgentDxe entry point and main loop.

  The driver is loaded late in DXE (after variable services are up; see
  the [Depex] in SyzAgentDxe.inf), discovers the ivshmem region exposed
  by the syzkaller-launched QEMU instance, and runs a forever loop:

    while (TRUE) {
      WaitForDoorbell();
      Dispatch(Program);
      Ack();
    }

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzAgentDxe.h"

#include <Library/SyzCoverLib.h>

SYZ_EDK2_AGENT  gSyzEdk2Agent;

//
// A unique vendor GUID we use for SetVariable calls so the fuzzer can
// freely scribble on the variable store without colliding with any
// production GUID. Generated once.
//
STATIC CONST EFI_GUID  mSyzEdk2VendorGuid = {
  0x4f7d5d3a, 0x9b2c, 0x4d4f, { 0x88, 0x21, 0x6c, 0x55, 0x9e, 0x4b, 0x12, 0x88 }
};

STATIC
VOID
SyzAgentLog (
  IN CONST CHAR8  *Message
  )
{
  DEBUG ((DEBUG_INFO, "[SYZ-AGENT] %a\n", Message));
}

EFI_STATUS
EFIAPI
SyzAgentDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *SharedBase;
  UINTN       SharedSize;

  ZeroMem (&gSyzEdk2Agent, sizeof (gSyzEdk2Agent));
  CopyMem (&gSyzEdk2Agent.SyzEdk2VendorGuid, &mSyzEdk2VendorGuid, sizeof (EFI_GUID));

  SyzAgentLog ("starting");

  Status = SyzEdk2TransportInit (&SharedBase, &SharedSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SYZ-AGENT] panic: transport init failed (%r)\n", Status));
    //
    // Without a transport channel we are useless; return EFI_SUCCESS so
    // the rest of the firmware can still boot for diagnostic purposes
    // and the absence will be visible on the host as a missing ack.
    //
    return EFI_SUCCESS;
  }

  gSyzEdk2Agent.SharedBase = SharedBase;
  gSyzEdk2Agent.SharedSize = SharedSize;
  gSyzEdk2Agent.LastSeq    = 0;

  //
  // Hand the ivshmem region to SyzCoverLib so the per-edge runtime
  // hooks (compiled into every instrumented module via the NULL
  // library injection in OvmfPkgX64.dsc) can start writing PCs into
  // the coverage ring.
  //
  SyzCoverSetShared (SharedBase, SharedSize);

  SyzAgentLog ("starting dispatch loop");

  for ( ; ;) {
    UINT32  HostSeq;

    if (!SyzEdk2TransportPoll (&HostSeq)) {
      //
      // No new program. Yield. We deliberately spin instead of using a
      // timer event because the host is faster than the guest and any
      // sleep here directly inflates iteration latency.
      //
      gBS->Stall (200);
      continue;
    }

    if (HostSeq == gSyzEdk2Agent.LastSeq) {
      continue;
    }

    gSyzEdk2Agent.LastSeq = HostSeq;

    CONST UINT8  *Base    = (CONST UINT8 *)gSyzEdk2Agent.SharedBase;
    UINT32       Magic    = *(CONST UINT32 *)(Base + SYZ_EDK2_OFF_MAGIC);
    UINT32       NumCalls = *(CONST UINT32 *)(Base + SYZ_EDK2_OFF_NCALLS);
    EFI_STATUS   DispatchStatus;
    UINT32       AckStatus;

    if (Magic != SYZ_EDK2_PROGRAM_MAGIC) {
      DEBUG ((
        DEBUG_ERROR,
        "[SYZ-AGENT] panic: program magic mismatch (got 0x%08x want 0x%08x)\n",
        (UINTN)Magic,
        (UINTN)SYZ_EDK2_PROGRAM_MAGIC
        ));
      SyzEdk2TransportAck (1);
      continue;
    }

    if ((NumCalls == 0) || (NumCalls > SYZ_EDK2_MAX_CALLS)) {
      DEBUG ((DEBUG_ERROR, "[SYZ-AGENT] panic: bad NumCalls=%u\n", (UINTN)NumCalls));
      SyzEdk2TransportAck (2);
      continue;
    }

    SyzCoverReset ();
    DispatchStatus = SyzEdk2Dispatch (
                       Base + SYZ_EDK2_OFF_CALLS,
                       SYZ_EDK2_MAX_PROGRAM_BYTES
                       );

    AckStatus = (UINT32)((DispatchStatus == EFI_SUCCESS) ? 0 : 3);
    SyzEdk2TransportAck (AckStatus);
  }

  // Unreachable.
  // return EFI_SUCCESS;
}

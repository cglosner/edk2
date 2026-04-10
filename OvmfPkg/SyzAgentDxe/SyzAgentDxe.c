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
#include <Library/BaseMemoryLib.h>
#include <Guid/AsanInfo.h>

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

STATIC EFI_EVENT  mPciIoNotifyEvent;
STATIC VOID       *mPciIoRegistration;
STATIC EFI_EVENT  mTickEvent;

STATIC
VOID
EFIAPI
SyzAgentDispatchOne (
  VOID
  );

STATIC
VOID
EFIAPI
SyzAgentTick (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  if (gSyzEdk2Agent.SharedBase == NULL) {
    return;
  }
  SyzAgentDispatchOne ();
}

STATIC
VOID
EFIAPI
SyzAgentOnPciIo (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  VOID        *SharedBase;
  UINTN       SharedSize;

  //
  // Re-entrancy guard: the protocol-notify callback can fire repeatedly
  // as new PCI handles arrive; we only want to claim the ivshmem device
  // once and then start polling.
  //
  if (gSyzEdk2Agent.SharedBase != NULL) {
    return;
  }

  Status = SyzEdk2TransportInit (&SharedBase, &SharedSize);
  if (EFI_ERROR (Status)) {
    return;
  }

  gSyzEdk2Agent.SharedBase = SharedBase;
  gSyzEdk2Agent.SharedSize = SharedSize;
  gSyzEdk2Agent.LastSeq    = 0;

  SyzCoverSetShared (SharedBase, SharedSize);

  //
  // Late-bind the AddressSanitizer shadow region. The tail of the
  // ivshmem BAR (everything past SYZ_EDK2_OFF_SHADOW) is the shadow
  // window. We allocate one ASAN_SHADOW_INFO and install the
  // gAsanShadowReadyProtocolGuid; this fans out to every loaded
  // instrumented module via the per-module RegisterProtocolNotify
  // that AsanLib's constructor put in place.
  //
  // The static lifetime is intentional: every per-module notify call
  // back keeps reading this struct via LocateProtocol, and we don't
  // want it to disappear when this function returns.
  //
  {
    STATIC ASAN_SHADOW_INFO  mShadowInfo;
    STATIC EFI_HANDLE        mShadowHandle = NULL;
    VOID                     *ShadowBase = NULL;
    UINTN                    ShadowSize = 0;
    EFI_STATUS               ShadowStatus;

    ShadowStatus = SyzEdk2TransportGetShadowRegion (&ShadowBase, &ShadowSize);
    if (!EFI_ERROR (ShadowStatus) && (ShadowBase != NULL) && (ShadowSize >= SIZE_8MB)) {
      //
      // Don't ZeroMem the entire 254 MiB shadow region — the host
      // already pre-zeros the backing file when it allocates it, and
      // a 254 MiB MMIO memset here adds many seconds to boot. The
      // host-side mmap of the same file is the source of truth.
      //
      mShadowInfo.ShadowMemoryStart = (UINT64)(UINTN)ShadowBase;
      mShadowInfo.ShadowMemorySize  = (UINT64)ShadowSize;
      ShadowStatus = gBS->InstallProtocolInterface (
                            &mShadowHandle,
                            &gAsanShadowReadyProtocolGuid,
                            EFI_NATIVE_INTERFACE,
                            &mShadowInfo
                            );
      DEBUG ((
        DEBUG_INFO,
        "[SYZ-AGENT] asan shadow at 0x%lx size 0x%lx (%r)\n",
        mShadowInfo.ShadowMemoryStart,
        mShadowInfo.ShadowMemorySize,
        ShadowStatus
        ));
    } else {
      DEBUG ((
        DEBUG_INFO,
        "[SYZ-AGENT] asan shadow unavailable (%r, base=%p size=0x%lx)\n",
        ShadowStatus,
        ShadowBase,
        (UINT64)ShadowSize
        ));
    }
  }

  //
  // Arm a 1 ms periodic timer that drives the dispatch loop. We
  // intentionally do NOT block here so the rest of the firmware can
  // finish booting.
  //
  Status = gBS->CreateEvent (
                  EVT_TIMER | EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  SyzAgentTick,
                  NULL,
                  &mTickEvent
                  );
  if (!EFI_ERROR (Status)) {
    gBS->SetTimer (mTickEvent, TimerPeriodic, 10000); // 1 ms in 100ns units
  }
  SyzAgentLog ("transport ready, dispatch timer armed");
}

EFI_STATUS
EFIAPI
SyzAgentDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  ZeroMem (&gSyzEdk2Agent, sizeof (gSyzEdk2Agent));
  CopyMem (&gSyzEdk2Agent.SyzEdk2VendorGuid, &mSyzEdk2VendorGuid, sizeof (EFI_GUID));

  SyzAgentLog ("starting (waiting for PciIo)");

  //
  // Defer the actual transport init until PciBusDxe has enumerated the
  // ivshmem device and installed PciIoProtocol. The notify fires for
  // every new PciIo handle; SyzAgentOnPciIo only claims the ivshmem one.
  //
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  SyzAgentOnPciIo,
                  NULL,
                  &mPciIoNotifyEvent
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SYZ-AGENT] panic: CreateEvent failed (%r)\n", Status));
    return EFI_SUCCESS;
  }
  Status = gBS->RegisterProtocolNotify (
                  &gEfiPciIoProtocolGuid,
                  mPciIoNotifyEvent,
                  &mPciIoRegistration
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SYZ-AGENT] panic: RegisterProtocolNotify failed (%r)\n", Status));
    return EFI_SUCCESS;
  }

  return EFI_SUCCESS;
}

//
// Local mirror of the program region. We always copy into this buffer
// (via PciIo->Mem.Read or a memcpy depending on transport mode) so the
// dispatch path can use a normal CPU-side pointer without worrying
// about whether the BAR window is identity-mapped.
//
STATIC UINT8  mProgramBuffer[SYZ_EDK2_OFF_HOST_SEQ];

STATIC
VOID
EFIAPI
SyzAgentDispatchOne (
  VOID
  )
{
  UINT32       HostSeq;
  UINT32       Magic;
  UINT32       NumCalls;
  EFI_STATUS   DispatchStatus;
  UINT32       AckStatus;

  if (!SyzEdk2TransportPoll (&HostSeq)) {
    return;
  }
  if (HostSeq == gSyzEdk2Agent.LastSeq) {
    return;
  }
  gSyzEdk2Agent.LastSeq = HostSeq;

  //
  // Pull the entire program record into a local buffer so the rest of
  // the dispatch path can use plain pointer arithmetic.
  //
  SyzEdk2TransportReadBytes (0, mProgramBuffer, sizeof (mProgramBuffer));
  Magic    = *(CONST UINT32 *)(mProgramBuffer + SYZ_EDK2_OFF_MAGIC);
  NumCalls = *(CONST UINT32 *)(mProgramBuffer + SYZ_EDK2_OFF_NCALLS);

  if (Magic != SYZ_EDK2_PROGRAM_MAGIC) {
    DEBUG ((
      DEBUG_ERROR,
      "[SYZ-AGENT] panic: program magic mismatch (got 0x%08x want 0x%08x)\n",
      (UINTN)Magic,
      (UINTN)SYZ_EDK2_PROGRAM_MAGIC
      ));
    SyzEdk2TransportAck (1);
    return;
  }

  if ((NumCalls == 0) || (NumCalls > SYZ_EDK2_MAX_CALLS)) {
    DEBUG ((DEBUG_ERROR, "[SYZ-AGENT] panic: bad NumCalls=%u\n", (UINTN)NumCalls));
    SyzEdk2TransportAck (2);
    return;
  }

  SyzCoverReset ();
  DispatchStatus = SyzEdk2Dispatch (
                     mProgramBuffer + SYZ_EDK2_OFF_CALLS,
                     SYZ_EDK2_MAX_PROGRAM_BYTES,
                     NumCalls
                     );

  AckStatus = (UINT32)((DispatchStatus == EFI_SUCCESS) ? 0 : 3);
  SyzEdk2TransportAck (AckStatus);
}

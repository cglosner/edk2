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
  // Discover the BAR-backed asan shadow region and install
  // gAsanShadowReadyProtocolGuid so consumers (SyzAsanTestDxe and
  // any other module that explicitly references AsanLib in its inf
  // and calls AsanLibActivate from its entry point) can locate it.
  // We do NOT use the protocol-notify fan-out pattern here — that
  // attempted to flip every loaded module's per-instance asan flags
  // at once and cascaded into a boot hang. Instead, modules opt in
  // explicitly via AsanLibActivate.
  //
  {
    STATIC ASAN_SHADOW_INFO  mShadowInfo;
    STATIC EFI_HANDLE        mShadowHandle = NULL;
    VOID                     *ShadowBase = NULL;
    UINTN                    ShadowSize  = 0;
    EFI_STATUS               ShadowStatus = EFI_NOT_FOUND;

    //
    // Phase 2: prefer the PlatformPei-reserved DRAM shadow over the
    // ivshmem BAR. PlatformPei produces a gAsanInfoGuid HOB at entry
    // that points to a 256 MB region at a fixed compile-time offset
    // (0x30000000). Match on that first; fall back to the BAR-based
    // path only if the HOB isn't present (legacy builds).
    //
    {
      EFI_HOB_GUID_TYPE  *GuidHob;
      ASAN_INFO          *Info;

      GuidHob = GetFirstGuidHob (&gAsanInfoGuid);
      if (GuidHob != NULL) {
        Info       = (ASAN_INFO *)GET_GUID_HOB_DATA (GuidHob);
        ShadowBase = (VOID *)(UINTN)Info->AsanShadowMemoryStart;
        ShadowSize = (UINTN)Info->AsanShadowMemorySize;
        ShadowStatus = EFI_SUCCESS;
        DEBUG ((
          DEBUG_INFO,
          "[SYZ-AGENT] asan shadow from HOB at 0x%lx size 0x%lx\n",
          (UINT64)(UINTN)ShadowBase,
          (UINT64)ShadowSize
          ));
      }
    }

    if (EFI_ERROR (ShadowStatus)) {
      ShadowStatus = SyzEdk2TransportGetShadowRegion (&ShadowBase, &ShadowSize);
    }

    if (!EFI_ERROR (ShadowStatus) && (ShadowBase != NULL) && (ShadowSize >= SIZE_8MB)) {
      gSyzEdk2Agent.AsanShadowBase = ShadowBase;
      gSyzEdk2Agent.AsanShadowSize = ShadowSize;
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
        "[SYZ-AGENT] asan shadow ready protocol at 0x%lx size 0x%lx (%r)\n",
        (UINT64)(UINTN)ShadowBase,
        (UINT64)ShadowSize,
        ShadowStatus
        ));

      {
        STATIC ASAN_INFO mConfigTableAsanInfo;
        mConfigTableAsanInfo.AsanShadowMemoryStart = (UINT64)(UINTN)ShadowBase;
        mConfigTableAsanInfo.AsanShadowMemorySize  = (UINT64)ShadowSize;
        mConfigTableAsanInfo.AsanInited             = 1;
        mConfigTableAsanInfo.AsanActivated          = 1;
        gBS->InstallConfigurationTable (&gAsanInfoGuid, &mConfigTableAsanInfo);
        DEBUG ((DEBUG_INFO, "[SYZ-AGENT] asan config table installed\n"));
      }
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
    gBS->SetTimer (mTickEvent, TimerPeriodic, 10000);
  }
  SyzAgentLog ("transport ready, dispatch timer armed");
  //
  // Install the fault trampoline (#DE/#UD/#GP/#PF handler) so
  // fuzzer-provoked CpuIo/MSR faults at bad addresses don't surface
  // as firmware "crashes". Requires EFI_CPU_ARCH_PROTOCOL, which is
  // installed before SyzAgent's PciIo callback runs.
  //
  SyzFaultGuardInit ();
  //
  // ProtocolLifetimeSan is disabled for now — poisoning the interface
  // struct with 0xFD breaks modules that use static/global protocol
  // interfaces (every subsequent legitimate method call looks like
  // heap-use-after-free to ASan). A tombstone-log-based variant that
  // doesn't mutate memory is the right fix; until then, keep PLS off.
  //
  // extern VOID SyzPlsInit (VOID);
  // SyzPlsInit ();
  // Register the fwfuzz trigger shim so qemu-fwfuzz can locate the
  // input buffer and trigger/exit PCs at runtime.
  SyzFwfuzzRegister ();
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

  //
  // With the new DEPEX on gEfiPciIoProtocolGuid, PciBusDxe has already
  // published PciIo handles by the time we get here, but the protocol-
  // notify event only fires for handles installed AFTER registration.
  // Signal the event explicitly so DxeCore runs SyzAgentOnPciIo at
  // TPL_CALLBACK (the notify's expected TPL). We can't just call
  // SyzAgentOnPciIo directly from the entry point — that runs at
  // TPL_APPLICATION and the internal CreateEvent/SetTimer ops
  // trigger Lock->Lock == EfiLockReleased asserts + RaiseTpl
  // OldTpl > NewTpl fatal errors.
  //
  // SignalEvent queues the notify for execution on the next
  // DispatchEventNotifies() call, which happens inside
  // gBS->RaiseTPL/RestoreTPL. We force it here by bumping TPL
  // and restoring it — the event fires during the restore.
  //
  {
    EFI_TPL OldTpl;
    gBS->SignalEvent (mPciIoNotifyEvent);
    OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
    gBS->RestoreTPL (OldTpl);
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

  SyzCoverReset ();   // zeros ring + enables gate
  DispatchStatus = SyzEdk2Dispatch (
                     mProgramBuffer + SYZ_EDK2_OFF_CALLS,
                     SYZ_EDK2_MAX_PROGRAM_BYTES,
                     NumCalls
                     );
  SyzCoverStop ();    // disables gate before ack

  AckStatus = (UINT32)((DispatchStatus == EFI_SUCCESS) ? 0 : 3);
  SyzEdk2TransportAck (AckStatus);
}

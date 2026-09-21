/** @file
  Installs the two benchmark protocols.

  Ground truth for measuring the fuzzer and the sanitizers against each other: one
  protocol of ordinary memory-safety faults, one of faults that are about firmware rather
  than about allocations. Both are gated behind SAN_BENCH and must never ship.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Protocol/SanBench.h>

extern SAN_BENCH_MEMORY_PROTOCOL    gSanBenchMemory;
extern SAN_BENCH_FIRMWARE_PROTOCOL  gSanBenchFirmware;

VOID SanBenchFirmwareInit (VOID);
VOID SanBenchNoteExitBootServices (VOID);

STATIC EFI_EVENT  mExitBootEvent = NULL;

STATIC
VOID
EFIAPI
SanBenchExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  SanBenchNoteExitBootServices ();
}

EFI_STATUS
EFIAPI
SanBenchDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  SanBenchFirmwareInit ();

  //
  // Notified rather than acted on: the point of LateBootService is that it keeps going
  // after this fires, so the flag only records that the transition happened.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  SanBenchExitBootServices,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &mExitBootEvent
                  );
  ASSERT_EFI_ERROR (Status);

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSanBenchMemoryProtocolGuid,
                  &gSanBenchMemory,
                  &gSanBenchFirmwareProtocolGuid,
                  &gSanBenchFirmware,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_ERROR, "SanBenchDxe: benchmark protocols installed -- NOT FOR PRODUCTION\n"));
  return Status;
}

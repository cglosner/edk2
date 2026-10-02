/** @file
  A DXE driver that is wrong on purpose, so a campaign that finds nothing can be told
  apart from a detector that sees nothing.

  Every fault here is on memory this driver allocated, in this driver's own image, reached
  through a protocol call. That is the path a fuzzing campaign actually exercises and the
  one the self-test application cannot cover: a UEFI application proving ASan works on its
  own heap says nothing about whether a separately built and separately instrumented driver
  reports.

  Built only when ASAN_FAULT_PROTOCOL is defined. Never ship it.

  Superseded by SanBenchDxe, which covers the same path -- faults in a separately
  built and separately instrumented driver, reached through protocol calls from
  SanBenchDrive -- across eleven classes instead of this one, and is scored by the
  pipeline's detects stage. Kept because it is the smaller test and useful when the
  benchmark itself is what is suspect.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Protocol/AsanFault.h>

#define ASAN_FAULT_ALLOCATION  64

STATIC ASAN_FAULT_PROTOCOL  mAsanFault;

STATIC
EFI_STATUS
EFIAPI
FaultOverflow (
  IN ASAN_FAULT_PROTOCOL  *This,
  IN UINTN                Length,
  IN UINT8                Fill
  )
{
  UINT8  *Buffer;

  Buffer = AllocatePool (ASAN_FAULT_ALLOCATION);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Length is the caller's, the allocation is 64. Above that this runs off the end,
  // which is the write ASan exists to catch.
  //
  SetMem (Buffer, Length, Fill);
  FreePool (Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
FaultOverread (
  IN  ASAN_FAULT_PROTOCOL  *This,
  IN  UINTN                Offset,
  OUT UINT8                *Value
  )
{
  UINT8  *Buffer;

  if (Value == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Buffer = AllocateZeroPool (ASAN_FAULT_ALLOCATION);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Value = Buffer[Offset];
  FreePool (Buffer);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
FaultUseAfterFree (
  IN ASAN_FAULT_PROTOCOL  *This,
  IN BOOLEAN              Touch
  )
{
  UINT8  *Buffer;

  Buffer = AllocatePool (ASAN_FAULT_ALLOCATION);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  FreePool (Buffer);
  if (Touch) {
    Buffer[0] = 0xA5;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
AsanFaultDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE  Handle;

  mAsanFault.Overflow     = FaultOverflow;
  mAsanFault.Overread     = FaultOverread;
  mAsanFault.UseAfterFree = FaultUseAfterFree;

  Handle = NULL;
  DEBUG ((DEBUG_ERROR, "AsanFaultDxe: installing the deliberate-fault protocol\n"));
  return gBS->InstallProtocolInterface (
                &Handle,
                &gAsanFaultProtocolGuid,
                EFI_NATIVE_INTERFACE,
                &mAsanFault
                );
}

/** @file
  SyzAgentDxe transport: discover the QEMU ivshmem-plain BAR and provide
  the host<->guest sequence-number doorbell.

  We rely on the simplest QEMU ivshmem mode (memory-backend-file +
  -device ivshmem-plain). The PCI vendor/device IDs are 0x1AF4/0x1110;
  BAR2 is the shared memory window. We do not implement the irqfd
  variant — polling is fast enough for the host->guest direction and the
  host already polls the result page on its end.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzAgentDxe.h"

#include <IndustryStandard/Pci22.h>
#include <Protocol/PciIo.h>

#define IVSHMEM_VENDOR_ID  0x1AF4
#define IVSHMEM_DEVICE_ID  0x1110

//
// Cached transport state.
//
STATIC UINT8   *mShared    = NULL;
STATIC UINTN   mSharedSize = 0;

STATIC
EFI_STATUS
LocateIvshmemBar (
  OUT VOID   **BarBase,
  OUT UINTN  *BarSize
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  UINTN                HandleCount;
  UINTN                Index;
  EFI_PCI_IO_PROTOCOL  *PciIo;
  PCI_TYPE00           Pci;

  *BarBase = NULL;
  *BarSize = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiPciIoProtocolGuid,
                    (VOID **)&PciIo
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }
    Status = PciIo->Pci.Read (
                          PciIo,
                          EfiPciIoWidthUint32,
                          0,
                          sizeof (Pci) / sizeof (UINT32),
                          &Pci
                          );
    if (EFI_ERROR (Status)) {
      continue;
    }
    if ((Pci.Hdr.VendorId != IVSHMEM_VENDOR_ID) ||
        (Pci.Hdr.DeviceId != IVSHMEM_DEVICE_ID))
    {
      continue;
    }

    //
    // Get the BAR2 (shared memory) attributes.
    //
    UINT64                            BarOffset;
    UINT64                            BarSize64;
    VOID                              *Resources;
    EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *Descriptor;

    Status = PciIo->GetBarAttributes (PciIo, 2, NULL, &Resources);
    if (EFI_ERROR (Status)) {
      continue;
    }
    Descriptor = (EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *)Resources;
    BarOffset  = Descriptor->AddrRangeMin;
    BarSize64  = Descriptor->AddrLen;
    FreePool (Resources);

    *BarBase = (VOID *)(UINTN)BarOffset;
    *BarSize = (UINTN)BarSize64;
    DEBUG ((
      DEBUG_INFO,
      "[SYZ-AGENT] ivshmem BAR2 at 0x%lx size 0x%lx\n",
      BarOffset,
      BarSize64
      ));
    FreePool (Handles);
    return EFI_SUCCESS;
  }

  FreePool (Handles);
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
SyzEdk2TransportInit (
  OUT VOID   **SharedBase,
  OUT UINTN  *SharedSize
  )
{
  EFI_STATUS  Status;

  Status = LocateIvshmemBar ((VOID **)&mShared, &mSharedSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (mSharedSize < (SYZ_EDK2_OFF_COVER + 4096)) {
    DEBUG ((
      DEBUG_ERROR,
      "[SYZ-AGENT] panic: ivshmem region too small (%u bytes)\n",
      (UINTN)mSharedSize
      ));
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Reset the host_seq / guest_seq pair to a known state.
  //
  *(volatile UINT32 *)(mShared + SYZ_EDK2_OFF_GUEST_SEQ)    = 0;
  *(volatile UINT32 *)(mShared + SYZ_EDK2_OFF_GUEST_STATUS) = 0;

  *SharedBase = mShared;
  *SharedSize = mSharedSize;
  return EFI_SUCCESS;
}

BOOLEAN
EFIAPI
SyzEdk2TransportPoll (
  OUT UINT32  *HostSeq
  )
{
  if (mShared == NULL) {
    return FALSE;
  }

  *HostSeq = *(volatile UINT32 *)(mShared + SYZ_EDK2_OFF_HOST_SEQ);
  return *HostSeq != gSyzEdk2Agent.LastSeq;
}

VOID
EFIAPI
SyzEdk2TransportAck (
  IN UINT32  Status
  )
{
  if (mShared == NULL) {
    return;
  }
  //
  // Publish the status first, then bump the sequence number so the host
  // never observes a stale status with a fresh sequence.
  //
  *(volatile UINT32 *)(mShared + SYZ_EDK2_OFF_GUEST_STATUS) = Status;
  MemoryFence ();
  *(volatile UINT32 *)(mShared + SYZ_EDK2_OFF_GUEST_SEQ) = gSyzEdk2Agent.LastSeq;
}

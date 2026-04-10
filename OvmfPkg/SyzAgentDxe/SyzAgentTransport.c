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
#define IVSHMEM_BAR_INDEX  2

//
// Cached transport state. We keep both:
//
//  * mShared / mSharedSize: a CPU-virtual pointer mirror of the BAR,
//    obtained from Descriptor->AddrRangeMin. This is fast (one MOV
//    per access) but only works if the firmware page tables actually
//    identity-map the 64-bit MMIO window the host bridge advertised.
//    On QEMU q35 with PhysMemAddressWidth=46, the BAR sits at
//    0x380000000000 and we observed reads/writes silently going to
//    /dev/null when the page tables didn't reach that far.
//
//  * mPciIo + mUseBarIo: fall back to PciIo->Mem.{Read,Write} which
//    goes through the host bridge's MMIO window translation and
//    therefore always works. Slower (a virtual call per byte access)
//    but correct on every config we have hands on.
//
// We sniff the mapping at init time by writing a magic word via
// PciIo->Mem.Write and seeing whether the direct mShared pointer
// reads it back. If not, we set mUseBarIo = TRUE and stop touching
// mShared at all.
//
STATIC UINT8                *mShared    = NULL;
STATIC UINTN                mSharedSize = 0;
STATIC EFI_PCI_IO_PROTOCOL  *mPciIo     = NULL;
STATIC BOOLEAN              mUseBarIo   = FALSE;

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

    Status = PciIo->GetBarAttributes (PciIo, IVSHMEM_BAR_INDEX, NULL, &Resources);
    if (EFI_ERROR (Status)) {
      continue;
    }
    Descriptor = (EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *)Resources;
    BarOffset  = Descriptor->AddrRangeMin;
    BarSize64  = Descriptor->AddrLen;
    FreePool (Resources);

    //
    // Make sure the BAR is enabled for memory access. Without this,
    // PciIo->Mem.Read/Write at offsets within the BAR refuse the
    // transaction (the device's command-register Memory Space bit
    // would otherwise be off until some driver explicitly enables it).
    //
    PciIo->Attributes (
             PciIo,
             EfiPciIoAttributeOperationEnable,
             EFI_PCI_IO_ATTRIBUTE_MEMORY,
             NULL
             );

    mPciIo   = PciIo;
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

//
// Direct accessors that route through PciIo when the direct CPU
// mapping is not usable.
//
STATIC
UINT32
SyzBarRead32 (
  IN UINT32  Offset
  )
{
  if (mUseBarIo && mPciIo != NULL) {
    UINT32 Value = 0;
    mPciIo->Mem.Read (
                  mPciIo,
                  EfiPciIoWidthUint32,
                  IVSHMEM_BAR_INDEX,
                  Offset,
                  1,
                  &Value
                  );
    return Value;
  }
  return *(volatile UINT32 *)(mShared + Offset);
}

STATIC
VOID
SyzBarWrite32 (
  IN UINT32  Offset,
  IN UINT32  Value
  )
{
  if (mUseBarIo && mPciIo != NULL) {
    mPciIo->Mem.Write (
                  mPciIo,
                  EfiPciIoWidthUint32,
                  IVSHMEM_BAR_INDEX,
                  Offset,
                  1,
                  &Value
                  );
    return;
  }
  *(volatile UINT32 *)(mShared + Offset) = Value;
}

STATIC
VOID
SyzBarReadBytes (
  IN UINT32  Offset,
  OUT VOID   *Dest,
  IN UINT32  Length
  )
{
  if (mUseBarIo && mPciIo != NULL) {
    mPciIo->Mem.Read (
                  mPciIo,
                  EfiPciIoWidthUint8,
                  IVSHMEM_BAR_INDEX,
                  Offset,
                  Length,
                  Dest
                  );
    return;
  }
  CopyMem (Dest, mShared + Offset, Length);
}

VOID
EFIAPI
SyzEdk2TransportReadBytes (
  IN UINT32  Offset,
  OUT VOID   *Dest,
  IN UINT32  Length
  )
{
  SyzBarReadBytes (Offset, Dest, Length);
}

//
// Return the directly-mapped CPU view of the asan shadow region
// hosted at the tail of the ivshmem BAR. The first
// SYZ_EDK2_OFF_SHADOW bytes of the BAR are reserved for the SyzAgent
// control region; everything beyond that is shadow.
//
// We can only hand out a CPU pointer if the direct mapping passed
// the init-time probe. When mUseBarIo == TRUE the asan runtime cannot
// use this region (its instrumentation issues plain CPU stores) and
// the caller is expected to leave asan deactivated.
//
EFI_STATUS
EFIAPI
SyzEdk2TransportGetShadowRegion (
  OUT VOID    **ShadowBase,
  OUT UINTN   *ShadowSize
  )
{
  *ShadowBase = NULL;
  *ShadowSize = 0;

  if ((mShared == NULL) || mUseBarIo) {
    return EFI_UNSUPPORTED;
  }
  if (mSharedSize <= SYZ_EDK2_OFF_SHADOW) {
    return EFI_BUFFER_TOO_SMALL;
  }

  *ShadowBase = mShared + SYZ_EDK2_OFF_SHADOW;
  *ShadowSize = mSharedSize - SYZ_EDK2_OFF_SHADOW;
  return EFI_SUCCESS;
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
  // Probe whether the firmware page tables actually identity-map the
  // BAR window. We write a magic word at offset 0x1FFC via PciIo
  // (which definitely lands in the device) and read it back through
  // the direct mShared pointer. If they don't agree, the direct view
  // is broken and we have to route every access through PciIo.
  //
  if (mPciIo != NULL) {
    UINT32 Magic     = 0xFEED5A11;
    UINT32 Verify    = 0;
    UINT32 ProbeOff  = 0x1FFC;
    mPciIo->Mem.Write (mPciIo, EfiPciIoWidthUint32, IVSHMEM_BAR_INDEX,
                       ProbeOff, 1, &Magic);
    Verify = *(volatile UINT32 *)(mShared + ProbeOff);
    if (Verify != Magic) {
      mUseBarIo = TRUE;
      DEBUG ((
        DEBUG_INFO,
        "[SYZ-AGENT] direct BAR view stale (got 0x%x want 0x%x); routing via PciIo\n",
        (UINTN)Verify, (UINTN)Magic
        ));
    } else {
      DEBUG ((
        DEBUG_INFO,
        "[SYZ-AGENT] direct BAR view OK\n"
        ));
    }
    //
    // Restore the probe word to zero so the host doesn't see garbage
    // in the cover ring.
    //
    Magic = 0;
    mPciIo->Mem.Write (mPciIo, EfiPciIoWidthUint32, IVSHMEM_BAR_INDEX,
                       ProbeOff, 1, &Magic);
  }

  //
  // Reset the host_seq / guest_seq pair to a known state.
  //
  SyzBarWrite32 (SYZ_EDK2_OFF_GUEST_SEQ, 0);
  SyzBarWrite32 (SYZ_EDK2_OFF_GUEST_STATUS, 0);

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
  if ((mShared == NULL) && !mUseBarIo) {
    return FALSE;
  }

  *HostSeq = SyzBarRead32 (SYZ_EDK2_OFF_HOST_SEQ);
  return *HostSeq != gSyzEdk2Agent.LastSeq;
}

VOID
EFIAPI
SyzEdk2TransportAck (
  IN UINT32  Status
  )
{
  if ((mShared == NULL) && !mUseBarIo) {
    return;
  }
  //
  // Publish the status first, then bump the sequence number so the host
  // never observes a stale status with a fresh sequence.
  //
  SyzBarWrite32 (SYZ_EDK2_OFF_GUEST_STATUS, Status);
  MemoryFence ();
  SyzBarWrite32 (SYZ_EDK2_OFF_GUEST_SEQ, gSyzEdk2Agent.LastSeq);
}

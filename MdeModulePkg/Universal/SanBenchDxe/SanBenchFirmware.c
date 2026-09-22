/** @file
  Faults peculiar to firmware, which a memory sanitizer is not built to see.

  Each of these is an in-bounds access to memory that happens to be the wrong memory, or
  a use of something whose lifetime has ended without its storage being freed. ASan
  models allocations; none of this is about allocations.

  Built only when SAN_BENCH is defined. Never ship this.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SanBench.h>

STATIC UINT8              mAbsorbed[64];
STATIC EFI_BOOT_SERVICES  *mCapturedBs   = NULL;
STATIC VOID               *mStaleHandle  = NULL;
STATIC EFI_HANDLE         mStaleOwner    = NULL;
STATIC EFI_GUID           mStaleGuid     = { 0x9e14b7c2, 0x38a5, 0x4d6f,
                                             { 0xbb, 0x71, 0x05, 0x2a, 0xc8, 0x3f, 0x96, 0x1d } };
STATIC BOOLEAN            mAfterExitBoot = FALSE;

/**
  Dereference a pointer from outside without asking where it points.

  The length is bounded and the destination is fixed, so nothing here is a buffer
  overflow. The fault is that Foreign is never checked against any region this driver is
  entitled to read: SMRAM, a firmware volume and MMIO are all read exactly as happily as
  the caller's own buffer. This is the shape of an SMM callout, and it is invisible to a
  sanitizer that only knows allocation bounds.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchAbsorb (
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN VOID                         *Foreign,
  IN UINTN                        Length
  )
{
  if ((Foreign == NULL) || (Length == 0) || (Length > sizeof (mAbsorbed))) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // No region check. A correct implementation asks whether Foreign lies inside the
  // buffer it was promised, and refuses everything else.
  //
  CopyMem (mAbsorbed, Foreign, Length);
  return EFI_SUCCESS;
}

/**
  Fetch an untrusted length twice with the check in between.

  Shared is memory the caller can still write while this runs -- a communication buffer,
  a queue an agent outside the firmware owns. The first read is validated and the second
  is used, so the value that passed the check is not necessarily the value that acts.
  Both reads are in bounds, so there is nothing for ASan to object to.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchDoubleFetch (
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN VOID                         *Shared,
  IN UINTN                        SharedSize
  )
{
  volatile UINT32  *Length;
  UINT8            Local[32];

  if ((Shared == NULL) || (SharedSize < sizeof (UINT32) + sizeof (Local))) {
    return EFI_INVALID_PARAMETER;
  }

  Length = (volatile UINT32 *)Shared;

  if (*Length > sizeof (Local)) {            // fetch one: validated
    return EFI_BAD_BUFFER_SIZE;
  }

  //
  // volatile, so the compiler must read it again rather than reuse the checked value.
  // That is what makes this a double fetch instead of a redundant expression.
  //
  CopyMem (Local, (UINT8 *)Shared + sizeof (UINT32), *Length);   // fetch two: used

  return EFI_SUCCESS;
}

/**
  Use boot services from a path that can run after they are gone.

  gBS is captured once and kept. After ExitBootServices the table and everything it
  points at may be repurposed, so this is a call through a pointer whose lifetime ended.
  Nothing was freed in the allocator's sense, so no shadow byte changed.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchLateBootService (
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This
  )
{
  VOID  *Scratch;

  if (mCapturedBs == NULL) {
    return EFI_NOT_READY;
  }

  //
  // The flag records that the transition happened; the call goes ahead regardless,
  // which is the defect. A correct driver either converts its pointers at the
  // ExitBootServices notification or refuses to run at all.
  //
  Scratch = NULL;
  mCapturedBs->AllocatePool (EfiBootServicesData, 32, &Scratch);
  if (Scratch != NULL) {
    mCapturedBs->FreePool (Scratch);
  }

  return mAfterExitBoot ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

/**
  Keep an interface pointer after the protocol is uninstalled.

  The handle database no longer lists it, but the pointer still refers to storage that is
  mapped and still looks like a protocol. Calling through it reaches whatever now lives
  there. The lifetime that ended is the protocol's, not the allocation's.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchStaleInterface (
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This
  )
{
  EFI_STATUS  Status;

  if (mStaleHandle == NULL) {
    return EFI_NOT_READY;
  }

  //
  // Uninstall the protocol and keep the interface pointer, which is the whole mistake.
  // The storage is still allocated and still readable, so this keeps working right up
  // until the allocator hands the memory to somebody else.
  //
  if (mStaleOwner != NULL) {
    Status = gBS->UninstallProtocolInterface (mStaleOwner, &mStaleGuid, mStaleHandle);
    if (!EFI_ERROR (Status)) {
      mStaleOwner = NULL;
    }
  }

  //
  // Read through the cached interface without re-locating it. Correct code re-opens the
  // protocol, or registers for its uninstall notification and drops the pointer.
  //
  return (*(volatile UINT32 *)mStaleHandle == 0) ? EFI_NOT_FOUND : EFI_SUCCESS;
}

/**
  Trust the size a variable reports.

  The variable is writable from an operating system. Its size is used to copy into a
  fixed buffer with no comparison, so an OS that writes a large value reaches past the
  destination. The read side is in bounds; the write side is the defect, and it only
  happens for a variable an attacker controls.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchTrustVariable (
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN UINT32                       Selector
  )
{
  UINT8       Fixed[32];
  UINTN       Size;
  EFI_STATUS  Status;
  CHAR16      *Name;

  Name = (Selector & 1) ? L"SanBenchPayload" : L"SanBenchSmall";
  Size = sizeof (Fixed);

  Status = gRT->GetVariable (Name, &gSanBenchFirmwareProtocolGuid, NULL, &Size, Fixed);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    //
    // Size now holds what the variable needs, which is larger than Fixed. Asking again
    // with the same fixed destination and the variable's own size is the defect: a
    // correct caller allocates Size, or refuses anything above sizeof (Fixed).
    //
    Status = gRT->GetVariable (Name, &gSanBenchFirmwareProtocolGuid, NULL, &Size, Fixed);
  }

  return Status;
}

SAN_BENCH_FIRMWARE_PROTOCOL  gSanBenchFirmware = {
  SanBenchAbsorb,
  SanBenchDoubleFetch,
  SanBenchLateBootService,
  SanBenchStaleInterface,
  SanBenchTrustVariable
};

VOID
SanBenchFirmwareInit (
  VOID
  )
{
  mCapturedBs  = gBS;

  //
  // On the heap, and actually installed. A protocol whose interface is a global has no
  // redzone for the sanitizer to measure against, so poison-on-uninstall can say nothing
  // about it -- and a benchmark modelling the case the check cannot see measures the
  // wrong thing.
  //
  mStaleHandle = AllocateZeroPool (32);
  if (mStaleHandle != NULL) {
    *(UINT32 *)mStaleHandle = 0x5A5A5A5A;
    gBS->InstallProtocolInterface (
           &mStaleOwner,
           &mStaleGuid,
           EFI_NATIVE_INTERFACE,
           mStaleHandle
           );
  }
}

VOID
SanBenchNoteExitBootServices (
  VOID
  )
{
  mAfterExitBoot = TRUE;
}

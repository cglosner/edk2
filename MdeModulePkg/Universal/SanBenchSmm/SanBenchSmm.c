/** @file
  Memory-safety faults inside SMRAM, raised from an SMM driver's OWN code.

  The positive control for SMM detection. Every SMM finding so far came from an
  instrumented LIBRARY linked into an SMM image -- BaseLib, the memory wrappers, the SMM
  core -- which proves the shadow covers TSEG and the reporter runs in SMM, but says
  nothing about a fault in a driver's own instrumented code. That is the thing a campaign
  is actually looking for, and nothing had ever demonstrated it.

  So the faults here are written as DIRECT loads and stores on this module's own
  statements, never through CopyMem or SetMem. A fault inside CopyMem reports against
  AsanMemoryLibRepStr and is attributed to the library, which is exactly the result
  already in hand; a store written here reports against SanBenchSmm.efi and is the result
  that is missing.

  Nothing is exercised at boot. Every case needs a software SMI carrying a command code,
  so an image with this module in it boots exactly as it did without it. The handler
  GUID is

      7A2F1C84-5D63-4B19-9E0A-3C71D4862B55

  and the request is SAN_BENCH_SMM_COMM below: a command, a length, and 64 bytes of
  caller data. scripts/discover_smi.py finds the handler by the SmiHandlerRegister call
  site, so a locally declared GUID is discoverable without a DEC entry.

  Built only when SAN_BENCH is defined. Never ship this.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiSmm.h>
#include <Library/Asan.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/SmmMemLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SanBench.h>

//
// The allocation every pool case works on. 32 bytes requests a 32-byte right redzone
// (ComputePoolRightRedzoneSize) on top of POOL_OVERHEAD's 184, which lands the block in
// the 256-byte bucket: the caller's buffer is at block+168..199, the redzone and the
// slack the SMM core now poisons run to block+239, and POOL_TAIL sits at block+240.
// An overflow of up to SAN_BENCH_SMM_DATA_BYTES bytes therefore stays inside this
// block's own poisoned span and cannot reach the tail or the next block -- the fault is
// detectable without being destructive, which is what lets the case run in a boot that
// has to keep going.
//
#define SAN_BENCH_SMM_POOL_BYTES  32

//
// The command codes, the request layout and this GUID all live in
// MdePkg/Include/Protocol/SanBench.h, because SanBenchDrive has to agree with them
// exactly in order to raise the SMI. A second copy here would be a copy that can drift.
//
STATIC CONST EFI_GUID  mSanBenchSmmHandlerGuid = SAN_BENCH_SMM_HANDLER_GUID;

//
// Where every faulting read lands. volatile, because a load whose result is discarded is
// a load the compiler is entitled to delete -- and a deleted load is a case that reports
// nothing while looking like it ran.
//
STATIC volatile UINT8  mSanBenchSmmSink = 0;

/**
  Allocate from the SMM pool.

  gSmst directly, not MemoryAllocationLib. The library's FreePool and FreePages end in
  ASSERT_EFI_ERROR, and the double-free case below deliberately makes a free fail:
  PcdDebugPropertyMask is 0x2F in this build, so that ASSERT takes the deadloop arm, and
  a CpuDeadLoop inside an SMI hangs the guest with no further output. The control would
  destroy the run that collects its own result.

  @param  Size    Bytes to allocate.

  @return The allocation, or NULL.
**/
STATIC
VOID *
SanBenchSmmAllocate (
  IN UINTN  Size
  )
{
  EFI_STATUS  Status;
  VOID        *Buffer;

  Buffer = NULL;
  Status = gSmst->SmmAllocatePool (EfiRuntimeServicesData, Size, &Buffer);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return Buffer;
}

/**
  Heap overflow inside SMRAM, written by this module.

  The allocation is a fixed SAN_BENCH_SMM_POOL_BYTES and the loop bound is the caller's
  Length, so a caller that sends a record of the documented size is served correctly and
  the fault needs Length > 32 -- one comparison a campaign has to get past.

  @param  Request   The caller's request, already copied into SMRAM.
**/
STATIC
VOID
SanBenchSmmPoolOverflow (
  IN SAN_BENCH_SMM_COMM  *Request
  )
{
  UINT8  *Buffer;
  UINTN  Length;
  UINTN  Index;

  Length = Request->Length;
  if (Length == 0) {
    return;
  }

  //
  // A sanity bound that is NOT the allocation's bound, the shape this whole benchmark is
  // built on. It also keeps the overflow inside the block's own 256-byte bucket, so the
  // report is a shadow hit on this driver's store rather than a corrupted neighbour that
  // surfaces somewhere unattributable later.
  //
  if (Length > SAN_BENCH_SMM_DATA_BYTES) {
    return;
  }

  Buffer = SanBenchSmmAllocate (SAN_BENCH_SMM_POOL_BYTES);
  if (Buffer == NULL) {
    return;
  }

  //
  // A store per byte, in this module, so the report names this file. The overflow begins
  // at Index == SAN_BENCH_SMM_POOL_BYTES.
  //
  for (Index = 0; Index < Length; Index++) {
    Buffer[Index] = Request->Data[Index];
  }

  gSmst->SmmFreePool (Buffer);
}

/**
  Use-after-free inside SMRAM.

  Reads offset 0 of the freed buffer on purpose. That byte is the one the SMM pool's
  quarantine exists to describe: a block put straight back on mSmmPoolLists has to keep
  its first 16 bytes readable, because FREE_POOL_HEADER's Link lands exactly there, so a
  stale read of Buffer[0] could not be caught at all before the quarantine. This case
  therefore fails if the quarantine is turned off, and that is the point of it.

  A read rather than a write: the memory is freed, and writing it could corrupt a free
  list node that the allocator is about to walk.
**/
STATIC
VOID
SanBenchSmmPoolUseAfterFree (
  VOID
  )
{
  UINT8  *Buffer;

  Buffer = SanBenchSmmAllocate (SAN_BENCH_SMM_POOL_BYTES);
  if (Buffer == NULL) {
    return;
  }

  Buffer[0] = 0x5A;
  gSmst->SmmFreePool (Buffer);

  mSanBenchSmmSink = Buffer[0];
}

/**
  Double free inside SMRAM.

  The second free is reported by PiSmmCore/Pool.c, which recognises the quarantine
  signature the first free left behind; without the quarantine the block is back on the
  free list with Signature == 0 and the second free is a silent EFI_INVALID_PARAMETER.

  The return status is checked and discarded rather than asserted, for the reason
  SanBenchSmmAllocate gives.
**/
STATIC
VOID
SanBenchSmmDoubleFree (
  VOID
  )
{
  UINT8  *Buffer;

  Buffer = SanBenchSmmAllocate (SAN_BENCH_SMM_POOL_BYTES);
  if (Buffer == NULL) {
    return;
  }

  gSmst->SmmFreePool (Buffer);
  gSmst->SmmFreePool (Buffer);
}

/**
  Use-after-free on an SMM PAGE allocation.

  The class PiSmmCore/Page.c had no poisoning for at all, which is why it is a separate
  case from the pool one. The offset is past sizeof (FREE_PAGE_LIST): the first 24 bytes
  of a freed range are the free list node itself and stay addressable by construction, so
  a case that read offset 0 would report nothing and would be measuring that hole rather
  than the hook.
**/
STATIC
VOID
SanBenchSmmPageUseAfterFree (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Address;

  Address = 0;
  Status  = gSmst->SmmAllocatePages (
                     AllocateAnyPages,
                     EfiRuntimeServicesData,
                     1,
                     &Address
                     );
  if (EFI_ERROR (Status) || (Address == 0)) {
    return;
  }

  Status = gSmst->SmmFreePages (Address, 1);
  if (EFI_ERROR (Status)) {
    return;
  }

  mSanBenchSmmSink = ((UINT8 *)(UINTN)Address)[64];
}

/**
  The control. Allocates, fills, frees, and is correct.

  A board with no negative control cannot tell a sanitizer that detects faults from one
  that reports on everything it is shown, so this case must produce no report at all.
**/
STATIC
VOID
SanBenchSmmControl (
  IN SAN_BENCH_SMM_COMM  *Request
  )
{
  UINT8  *Buffer;
  UINTN  Index;

  Buffer = SanBenchSmmAllocate (SAN_BENCH_SMM_POOL_BYTES);
  if (Buffer == NULL) {
    return;
  }

  for (Index = 0; Index < SAN_BENCH_SMM_POOL_BYTES; Index++) {
    Buffer[Index] = Request->Data[Index % SAN_BENCH_SMM_DATA_BYTES];
  }

  mSanBenchSmmSink = Buffer[SAN_BENCH_SMM_POOL_BYTES - 1];
  gSmst->SmmFreePool (Buffer);
}

/**
  Dispatch function for the software SMI.

  @param DispatchHandle  The handle assigned by SmiHandlerRegister.
  @param Context         Unused.
  @param CommBuffer      The caller's buffer, outside SMRAM.
  @param CommBufferSize  Its size.

  @retval EFI_SUCCESS    Always. A handler that returns an error from an SMI tells the
                         caller nothing it can act on, and the result of this module is
                         on the sanitizer's wire, not in a status code.
**/
EFI_STATUS
EFIAPI
SanBenchSmmHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  SAN_BENCH_SMM_COMM  Request;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    return EFI_SUCCESS;
  }

  if (*CommBufferSize < sizeof (SAN_BENCH_SMM_COMM)) {
    return EFI_SUCCESS;
  }

  //
  // Validated and copied, in that order, before anything is read twice. This module is
  // wrong on purpose in five chosen ways and must not ALSO be a general SMRAM write
  // primitive or a double-fetch: a control that is reachable through an unintended path
  // scores the unintended path, and the finding is then about this file rather than
  // about the sanitizer.
  //
  if (!SmmIsBufferOutsideSmmValid (
         (EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer,
         sizeof (SAN_BENCH_SMM_COMM)
         ))
  {
    return EFI_SUCCESS;
  }

  CopyMem (&Request, CommBuffer, sizeof (Request));

  //
  // Narration carries no class name. The scoreboard matches class names on this same
  // wire, so a line that said "running double-free" would score itself as a detection.
  //
  SerialOutput ("SanBenchSmm: dispatch\n");

  switch (Request.Command) {
    case SAN_BENCH_SMM_CMD_CONTROL:
      SanBenchSmmControl (&Request);
      break;

    case SAN_BENCH_SMM_CMD_POOL_OVERFLOW:
      SanBenchSmmPoolOverflow (&Request);
      break;

    case SAN_BENCH_SMM_CMD_POOL_UAF:
      SanBenchSmmPoolUseAfterFree ();
      break;

    case SAN_BENCH_SMM_CMD_DOUBLE_FREE:
      SanBenchSmmDoubleFree ();
      break;

    case SAN_BENCH_SMM_CMD_PAGE_UAF:
      SanBenchSmmPageUseAfterFree ();
      break;

    default:
      break;
  }

  return EFI_SUCCESS;
}

/**
  Print this image's own address range on the sanitizer's wire.

  An ASan report names no module. It says "in file: asan-outline-instrumentation" and
  carries an ip, so "a report raised by an SMM driver's OWN code" -- the thing this
  module exists to demonstrate -- cannot be read off the report text. Publishing the
  range lets the scorer test the ip against it, and an ip outside it means the report
  came from a library linked into this image instead, which is the result already in hand
  and must not be scored as this one.

  The range comes from EFI_LOADED_IMAGE_PROTOCOL, so it is the real base AND the real
  size. The alternative -- parsing the SMM core's "Loading SMM driver at" lines -- gives
  bases only, and each image's end then has to be guessed from the next image's base.

  gBS, not gSmst: the SMM core calls an SMM driver's entry point with the DXE-side
  ImageHandle (Dispatcher.c, "(DriverEntry->ImageHandle, gST)"), and it is the DXE
  protocol database that carries the loaded-image protocol for that handle. The SMM
  database has it on a different handle this function is never given. Boot services are
  safe here because this runs during SMM dispatch in the DXE phase, not from an SMI.

  @param  ImageHandle   The handle the entry point was given.
**/
STATIC
VOID
SanBenchSmmPublishImage (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                 Status;
  EFI_LOADED_IMAGE_PROTOCOL  *Image;
  CHAR8                      NumStr[19];

  Image  = NULL;
  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&Image
                  );
  if (EFI_ERROR (Status) || (Image == NULL)) {
    //
    // Said out loud rather than passed over. Without the range no report from this
    // module can be attributed, and a scorer that cannot attribute must report that
    // rather than credit the class.
    //
    SerialOutput ("SanBenchSmm: no loaded image protocol, reports cannot be attributed\n");
    return;
  }

  SerialOutput (SAN_BENCH_SMM_IMAGE_PREFIX);
  Num2Str64bit ((UINTN)Image->ImageBase, NumStr);
  SerialOutput (NumStr);
  SerialOutput (" size=");
  Num2Str64bit ((UINTN)Image->ImageSize, NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
}

/**
  Register the handler. That is all this entry point does.

  No ASSERT_EFI_ERROR on the registration: this runs inside the SMM core's dispatch, and
  an ASSERT there deadloops the guest. A registration that fails is reported on the wire
  and the module then does nothing, which is a boot that still completes.

  @param  ImageHandle   This image.
  @param  SystemTable   The DXE system table.

  @return Whatever SmiHandlerRegister returned.
**/
EFI_STATUS
EFIAPI
SanBenchSmmEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  DispatchHandle;

  DispatchHandle = NULL;
  Status         = gSmst->SmiHandlerRegister (
                            SanBenchSmmHandler,
                            &mSanBenchSmmHandlerGuid,
                            &DispatchHandle
                            );
  if (EFI_ERROR (Status)) {
    SerialOutput ("SanBenchSmm: registration failed\n");
    return Status;
  }

  SanBenchSmmPublishImage (ImageHandle);
  SerialOutput ("SanBenchSmm: armed\n");
  return EFI_SUCCESS;
}

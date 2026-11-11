/** @file
  SMM Memory pool management functions.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiSmmCore.h"

LIST_ENTRY  mSmmPoolLists[SmmPoolTypeMax][MAX_POOL_INDEX];
//
// To cache the SMRAM base since when Loading modules At fixed address feature is enabled,
// all module is assigned an offset relative the SMRAM base in build time.
//
GLOBAL_REMOVE_IF_UNREFERENCED  EFI_PHYSICAL_ADDRESS  gLoadModuleAtFixAddressSmramBase = 0;

//
// ASAN. A quarantine for freed pool blocks, which is what makes use-after-free and
// double-free inside SMRAM detectable at all.
//
// Poisoning a freed block was not enough on its own. InternalFreePoolByIndex put it
// straight back on mSmmPoolLists and InternalAllocPoolByIndex takes the FIRST node of
// that list, so the next allocation of the same size class got the block that had just
// been freed and UnpoisonPool cleared the poison again -- the poison expired before
// anything could trip over it. A double free was worse than invisible: the second free
// found Signature == 0, returned EFI_INVALID_PARAMETER and said nothing.
//
// Holding the most recent frees back fixes both. A freed block is poisoned, carries a
// signature of its own so a second free of the same pointer is recognisable, and is
// released -- put back on its free list, where the allocator can have it again -- only
// once later frees have pushed it out of the ring.
//
// The hold is bounded twice over, because SMRAM is small and wedging the boot by
// exhausting it is the expensive failure here:
//
//   * ASAN_SMM_QUARANTINE_SLOTS blocks at most, and
//   * ASAN_SMM_QUARANTINE_MAX_BYTES bytes at most, enforced BEFORE the insert.
//
// Only the bucket path reaches here, so a held block is at most MAX_POOL_SIZE bytes and
// the high-water mark is ASAN_SMM_QUARANTINE_MAX_BYTES exactly -- 64KB, against a TSEG
// measured in tens of MB. Setting the ceiling to 0 turns the quarantine off: every block
// is then released on the spot, which is the pre-quarantine behaviour byte for byte, and
// that is the one-line revert if SMM is ever shown to be short of pool.
//
// Why it cannot wedge the boot:
//
//   * the ring is a static array, so holding a block allocates nothing. A quarantine
//     that had to allocate in order to record a free would recurse into the allocator
//     from inside the free path, which is the classic way to deadlock one;
//   * work per free is O(1) amortised -- at most one eviction per push for the count
//     bound, plus however many the byte bound needs, and each eviction strictly
//     decrements the count, so the loop cannot spin;
//   * it takes no lock, and the SMM core has none to take on this path;
//   * a block too large for the ceiling is released immediately rather than queued, so
//     there is no size for which the quarantine refuses to make progress;
//   * starvation is bounded by the same ceiling. The allocator does not fail when a free
//     list is empty: InternalAllocPoolByIndex recurses to the next bucket and ultimately
//     to SmmInternalAllocatePages, so the worst case is 64KB of SMRAM in flight, not an
//     allocation failure.
//
#define POOL_QUARANTINE_SIGNATURE      SIGNATURE_32('s','p','q','r')
#define ASAN_SMM_QUARANTINE_SLOTS      64
#define ASAN_SMM_QUARANTINE_MAX_BYTES  SIZE_64KB

//
// What stays addressable while a block is quarantined.
//
// A quarantined block is on no list, so its Link does not have to be readable -- and
// Link is the first 16 bytes of what was the caller's buffer, because FREE_POOL_HEADER
// puts it exactly where POOL_HEADER ends. That is the whole reason the quarantine buys
// detection rather than just delay: a block on the free list must keep those 16 bytes
// live, so a use-after-free read of Buffer[0] through Buffer[15] could never be caught,
// and those are the bytes a stale pointer is most likely to touch.
//
// Signature, Available, Type and Size stay readable: SmmInternalFreePool reads Signature
// to recognise the double free, the SMRAM profile walk reads Available, and the release
// path below needs Size to give the byte ceiling back what the block was costing.
//
#define ASAN_SMM_QUARANTINE_KEEP  OFFSET_OF (POOL_HEADER, OriSize)

typedef struct {
  FREE_POOL_HEADER    *Block;
  SMM_POOL_TYPE       PoolType;
  UINTN               PoolIndex;
} ASAN_SMM_QUARANTINE_ENTRY;

STATIC ASAN_SMM_QUARANTINE_ENTRY  mAsanSmmQuarantine[ASAN_SMM_QUARANTINE_SLOTS];
STATIC UINTN                      mAsanSmmQuarantineFirst = 0;
STATIC UINTN                      mAsanSmmQuarantineCount = 0;
STATIC UINTN                      mAsanSmmQuarantineBytes = 0;

//
// Declared here rather than in Asan.h for the reason MdeModulePkg/Core/Dxe/Mem/Pool.c
// gives at its own copy of this line: AsanRuntimeLib carries its own static
// AsanSignalSolution, and a non-static declaration in the shared header collides with it.
//
void AsanSignalSolution (VOID);

/**
  Convert a UEFI memory type to SMM pool type.

  @param[in]  MemoryType              Type of pool to allocate.

  @return SMM pool type
**/
SMM_POOL_TYPE
UefiMemoryTypeToSmmPoolType (
  IN  EFI_MEMORY_TYPE  MemoryType
  )
{
  ASSERT ((MemoryType == EfiRuntimeServicesCode) || (MemoryType == EfiRuntimeServicesData));
  switch (MemoryType) {
    case EfiRuntimeServicesCode:
      return SmmPoolTypeCode;
    case EfiRuntimeServicesData:
      return SmmPoolTypeData;
    default:
      return SmmPoolTypeMax;
  }
}

/**
  Called to initialize the memory service.

  @param   SmramRangeCount       Number of SMRAM Regions
  @param   SmramRanges           Pointer to SMRAM Descriptors

**/
VOID
SmmInitializeMemoryServices (
  IN UINTN                 SmramRangeCount,
  IN EFI_SMRAM_DESCRIPTOR  *SmramRanges
  )
{
  UINTN                                       Index;
  EFI_STATUS                                  Status;
  UINTN                                       SmmPoolTypeIndex;
  EFI_LOAD_FIXED_ADDRESS_CONFIGURATION_TABLE  *LMFAConfigurationTable;

  //
  // Initialize Pool list
  //
  for (SmmPoolTypeIndex = 0; SmmPoolTypeIndex < SmmPoolTypeMax; SmmPoolTypeIndex++) {
    for (Index = 0; Index < ARRAY_SIZE (mSmmPoolLists[SmmPoolTypeIndex]); Index++) {
      InitializeListHead (&mSmmPoolLists[SmmPoolTypeIndex][Index]);
    }
  }

  Status = EfiGetSystemConfigurationTable (
             &gLoadFixedAddressConfigurationTableGuid,
             (VOID **)&LMFAConfigurationTable
             );
  if (!EFI_ERROR (Status) && (LMFAConfigurationTable != NULL)) {
    gLoadModuleAtFixAddressSmramBase = LMFAConfigurationTable->SmramBase;
  }

  //
  // Add Free SMRAM regions
  // Need add Free memory at first, to let gSmmMemoryMap record data
  //
  for (Index = 0; Index < SmramRangeCount; Index++) {
    if ((SmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    SmmAddMemoryRegion (
      SmramRanges[Index].CpuStart,
      SmramRanges[Index].PhysicalSize,
      EfiConventionalMemory,
      SmramRanges[Index].RegionState
      );
  }

  //
  // Add the allocated SMRAM regions
  //
  for (Index = 0; Index < SmramRangeCount; Index++) {
    if ((SmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) == 0) {
      continue;
    }

    SmmAddMemoryRegion (
      SmramRanges[Index].CpuStart,
      SmramRanges[Index].PhysicalSize,
      EfiConventionalMemory,
      SmramRanges[Index].RegionState
      );
  }
}

/**
  ASAN. Poison the left and the right redzone of a freshly handed out block.

  The block layout produced by SmmInternalAllocatePool() is

    [ POOL_HEADER (incl. AsanLeftRZ[128]) ][ user OriSize ][ right RZ ][ pad ][ POOL_TAIL ]

  AsanLeftRZ ends immediately before the user buffer, so a left redzone hit is
  an underflow and a right redzone hit is an overflow.

  @param  PoolHdr   The header of the block being handed out.  OriSize and
                    AsanRightRZSize must already be filled in.
**/
STATIC
VOID
AsanPoisonPoolRedZones (
  IN POOL_HEADER  *PoolHdr
  )
{
  UINTN    UserEnd;
  UINTN    PoisonEnd;
  BOOLEAN  HasPoolTail;

  PoisonPool (
    (UINTN)PoolHdr->AsanLeftRZ,
    kAsanHeapLeftRedzoneSize,
    kAsanHeapLeftRedzoneMagic
    );

  //
  // ASAN. Poison everything between the caller's buffer and POOL_TAIL, not only
  // AsanRightRZSize bytes of it.
  //
  // ComputePoolRightRedzoneSize sizes a redzone; it does not describe the gap a bucket
  // allocation actually leaves.  A 16-byte request takes a 16-byte redzone and lands in
  // the 256-byte bucket: POOL_HEADER is 168 bytes, the caller gets 168..183, the redzone
  // covers 184..199, POOL_TAIL sits at 240..255, and 200..239 is padding that nothing
  // described.  OvmfPkg/Spi/SmmSpi.c assigns SmmSpiReadDataIn->Buffer at block+200 --
  // the first byte PAST the redzone -- before the check that would have stopped it, so
  // the overflow this code exists to catch fell in the hole.  Measured: that write
  // executed at least 261 times in run 42703964006 and reported nothing.
  //
  // Poisoning to the tail closes the hole and makes the right redzone the whole slack of
  // the bucket rather than a fixed 16 bytes, so detection no longer depends on the
  // request size landing near a bucket boundary.
  //
  // POOL_TAIL itself must stay addressable.  SmmInternalFreePool reads PoolTail->Signature
  // and PoolTail->Size BEFORE it unpoisons the block, and once SMM_CORE is instrumented
  // those reads are checked.  HasPoolTail is therefore recomputed exactly the way the free
  // path computes it, so both agree where the poisoned span ends.  The fields the
  // allocator reads out of POOL_HEADER sit below AsanLeftRZ, which is why poisoning the
  // left redzone has always been safe.
  //
  UserEnd     = (UINTN)(PoolHdr + 1) + PoolHdr->OriSize;
  HasPoolTail = !(IsHeapGuardEnabled () &&
                  IsMemoryGuarded ((EFI_PHYSICAL_ADDRESS)(UINTN)PoolHdr) &&
                  ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));

  PoisonEnd = (UINTN)PoolHdr + PoolHdr->Size;
  if (HasPoolTail) {
    PoisonEnd -= sizeof (POOL_TAIL);
  }

  if (PoisonEnd > UserEnd) {
    PoisonPool (UserEnd, PoisonEnd - UserEnd, kAsanHeapLeftRedzoneMagic);
  }
}

/**
  Internal Function. Allocate a pool by specified PoolIndex.

  @param  PoolType              Type of pool to allocate.
  @param  PoolIndex             Index which indicate the Pool size.
  @param  FreePoolHdr           The returned Free pool.

  @retval EFI_OUT_OF_RESOURCES   Allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
InternalAllocPoolByIndex (
  IN  EFI_MEMORY_TYPE   PoolType,
  IN  UINTN             PoolIndex,
  OUT FREE_POOL_HEADER  **FreePoolHdr
  )
{
  EFI_STATUS            Status;
  FREE_POOL_HEADER      *Hdr;
  POOL_TAIL             *Tail;
  EFI_PHYSICAL_ADDRESS  Address;
  SMM_POOL_TYPE         SmmPoolType;

  Address     = 0;
  SmmPoolType = UefiMemoryTypeToSmmPoolType (PoolType);

  ASSERT (PoolIndex <= MAX_POOL_INDEX);
  Status = EFI_SUCCESS;
  Hdr    = NULL;
  if (PoolIndex == MAX_POOL_INDEX) {
    Status = SmmInternalAllocatePages (
               AllocateAnyPages,
               PoolType,
               EFI_SIZE_TO_PAGES (MAX_POOL_SIZE << 1),
               &Address,
               FALSE
               );
    if (EFI_ERROR (Status)) {
      return EFI_OUT_OF_RESOURCES;
    }

    Hdr = (FREE_POOL_HEADER *)(UINTN)Address;
  } else if (!IsListEmpty (&mSmmPoolLists[SmmPoolType][PoolIndex])) {
    Hdr = BASE_CR (GetFirstNode (&mSmmPoolLists[SmmPoolType][PoolIndex]), FREE_POOL_HEADER, Link);
    RemoveEntryList (&Hdr->Link);
  } else {
    Status = InternalAllocPoolByIndex (PoolType, PoolIndex + 1, &Hdr);
    if (!EFI_ERROR (Status)) {
      Hdr->Header.Signature = 0;
      Hdr->Header.Size    >>= 1;
      Hdr->Header.Available = TRUE;
      Hdr->Header.Type      = 0;
      Tail                  = HEAD_TO_TAIL (&Hdr->Header);
      Tail->Signature       = 0;
      Tail->Size            = 0;
      InsertHeadList (&mSmmPoolLists[SmmPoolType][PoolIndex], &Hdr->Link);
      //
      // ASAN. The buddy half stays on the free list: poison everything past
      // FREE_POOL_HEADER (Signature/Available/Type/Size/redzone fields and the
      // Link the allocator itself walks stay addressable).
      //
      if (Hdr->Header.Size > sizeof (FREE_POOL_HEADER)) {
        PoisonPool (
          (UINTN)Hdr + sizeof (FREE_POOL_HEADER),
          Hdr->Header.Size - sizeof (FREE_POOL_HEADER),
          kAsanHeapFreeMagic
          );
      }

      Hdr = (FREE_POOL_HEADER *)((UINT8 *)Hdr + Hdr->Header.Size);
    }
  }

  if (!EFI_ERROR (Status)) {
    //
    // ASAN. Make the whole block addressable again before the core writes its
    // header and tail into it; the caller re-poisons the redzones afterwards.
    //
    UnpoisonPool ((UINTN)Hdr, (UINTN)MIN_POOL_SIZE << PoolIndex);
    Hdr->Header.Signature = POOL_HEAD_SIGNATURE;
    Hdr->Header.Size      = MIN_POOL_SIZE << PoolIndex;
    Hdr->Header.Available = FALSE;
    Hdr->Header.Type      = PoolType;
    Tail                  = HEAD_TO_TAIL (&Hdr->Header);
    Tail->Signature       = POOL_TAIL_SIGNATURE;
    Tail->Size            = Hdr->Header.Size;
  }

  *FreePoolHdr = Hdr;
  return Status;
}

/**
  ASAN. Release one quarantined block back to the allocator.

  The block stays poisoned past sizeof (FREE_POOL_HEADER); only the header prefix is made
  addressable again, which is exactly the state the pre-quarantine free path left a block
  in.

  @param  Entry   The ring slot being evicted. A NULL Block is tolerated so the caller
                  does not have to distinguish an empty slot from a full one.
**/
STATIC
VOID
AsanSmmQuarantineRelease (
  IN ASAN_SMM_QUARANTINE_ENTRY  *Entry
  )
{
  FREE_POOL_HEADER  *Hdr;

  Hdr = Entry->Block;
  if (Hdr == NULL) {
    return;
  }

  //
  // The Link write below is INSIDE the span the quarantine poisoned, because Link
  // overlaps the first bytes of what was the caller's buffer. Unpoison the header prefix
  // first, or the core reports a use-after-free against its own list insertion. The rest
  // of the block keeps the free poison, so the block is still described while it sits on
  // the free list -- which is what the code did before the quarantine existed.
  //
  UnpoisonPool ((UINTN)Hdr, sizeof (FREE_POOL_HEADER));

  //
  // Back to the free-list state upstream uses. Available and Type were set when the
  // block was freed and have not been touched since.
  //
  Hdr->Header.Signature = 0;
  InsertHeadList (&mSmmPoolLists[Entry->PoolType][Entry->PoolIndex], &Hdr->Link);
}

/**
  ASAN. Hold a freed block back from the free list, evicting older ones to stay inside
  both bounds.

  @param  Hdr        The block being freed. Signature must already carry
                     POOL_QUARANTINE_SIGNATURE and the tail must already be scrubbed.
  @param  PoolType   The SMM pool type the block came from.
  @param  PoolIndex  The size class index to return it to on release.
**/
STATIC
VOID
AsanSmmQuarantinePush (
  IN FREE_POOL_HEADER  *Hdr,
  IN SMM_POOL_TYPE     PoolType,
  IN UINTN             PoolIndex
  )
{
  UINTN                      Size;
  ASAN_SMM_QUARANTINE_ENTRY  *Slot;
  ASAN_SMM_QUARANTINE_ENTRY  Immediate;

  Size = Hdr->Header.Size;

  //
  // Poison first, so the block is described for the whole time it is held, including the
  // window in which the eviction loop below runs. ASAN_SMM_QUARANTINE_KEEP leaves the
  // four header fields the core still reads on a free block addressable.
  //
  if (Size > ASAN_SMM_QUARANTINE_KEEP) {
    PoisonPool (
      (UINTN)Hdr + ASAN_SMM_QUARANTINE_KEEP,
      Size - ASAN_SMM_QUARANTINE_KEEP,
      kAsanHeapFreeMagic
      );
  }

  //
  // Make room, by count and by bytes. Each iteration strictly decrements the count and
  // the loop stops at zero, so it cannot spin; and it releases rather than drops, so no
  // block is ever lost to the allocator.
  //
  while ((mAsanSmmQuarantineCount > 0) &&
         ((mAsanSmmQuarantineCount >= ASAN_SMM_QUARANTINE_SLOTS) ||
          (mAsanSmmQuarantineBytes + Size > ASAN_SMM_QUARANTINE_MAX_BYTES)))
  {
    Slot = &mAsanSmmQuarantine[mAsanSmmQuarantineFirst];
    //
    // Guarded rather than assumed. mAsanSmmQuarantineBytes is what enforces the ceiling,
    // so an underflow here would not be a wrong number, it would be an unbounded
    // quarantine.
    //
    if (Slot->Block != NULL) {
      mAsanSmmQuarantineBytes -= Slot->Block->Header.Size;
    }

    mAsanSmmQuarantineFirst  = (mAsanSmmQuarantineFirst + 1) % ASAN_SMM_QUARANTINE_SLOTS;
    mAsanSmmQuarantineCount -= 1;
    AsanSmmQuarantineRelease (Slot);
    Slot->Block = NULL;
  }

  //
  // Reached with the ring empty by a block larger than the whole ceiling, and by every
  // block when the ceiling is 0 -- which is how the quarantine is turned off. Release it
  // on the spot: queueing it would mean holding more than the ceiling allows, and
  // refusing to hold it costs a detection, never a block.
  //
  if (mAsanSmmQuarantineBytes + Size > ASAN_SMM_QUARANTINE_MAX_BYTES) {
    Immediate.Block     = Hdr;
    Immediate.PoolType  = PoolType;
    Immediate.PoolIndex = PoolIndex;
    AsanSmmQuarantineRelease (&Immediate);
    return;
  }

  Slot = &mAsanSmmQuarantine[(mAsanSmmQuarantineFirst + mAsanSmmQuarantineCount) %
                             ASAN_SMM_QUARANTINE_SLOTS];
  Slot->Block              = Hdr;
  Slot->PoolType           = PoolType;
  Slot->PoolIndex          = PoolIndex;
  mAsanSmmQuarantineCount += 1;
  mAsanSmmQuarantineBytes += Size;
}

/**
  Internal Function. Free a pool by specified PoolIndex.

  @param  FreePoolHdr           The pool to free.
  @param  PoolTail              The pointer to the pool tail.

  @retval EFI_SUCCESS           Pool successfully freed.

**/
EFI_STATUS
InternalFreePoolByIndex (
  IN FREE_POOL_HEADER  *FreePoolHdr,
  IN POOL_TAIL         *PoolTail
  )
{
  UINTN          PoolIndex;
  SMM_POOL_TYPE  SmmPoolType;

  ASSERT ((FreePoolHdr->Header.Size & (FreePoolHdr->Header.Size - 1)) == 0);
  ASSERT (((UINTN)FreePoolHdr & (FreePoolHdr->Header.Size - 1)) == 0);
  ASSERT (FreePoolHdr->Header.Size >= MIN_POOL_SIZE);

  SmmPoolType = UefiMemoryTypeToSmmPoolType (FreePoolHdr->Header.Type);

  PoolIndex = (UINTN)(HighBitSet32 ((UINT32)FreePoolHdr->Header.Size) - MIN_POOL_SHIFT);
  //
  // ASAN. POOL_QUARANTINE_SIGNATURE rather than upstream's 0, and nothing in the SMM core
  // reads a pool Signature of 0 as meaning anything -- SmmInternalFreePool compares
  // against POOL_HEAD_SIGNATURE and the SMRAM profile walk reads Available. The signature
  // is what turns a second free of this pointer from a silent EFI_INVALID_PARAMETER into
  // a named double-free report.
  //
  FreePoolHdr->Header.Signature = POOL_QUARANTINE_SIGNATURE;
  FreePoolHdr->Header.Available = TRUE;
  FreePoolHdr->Header.Type      = 0;
  PoolTail->Signature           = 0;
  PoolTail->Size                = 0;
  ASSERT (PoolIndex < MAX_POOL_INDEX);
  //
  // ASAN. The block does not go back on the free list here any more; the quarantine
  // poisons it, holds it, and puts an older block back in its place. Poisoning on its own
  // caught nothing, because the next allocation of this size class took this same block
  // off the head of the list and unpoisoned it.
  //
  // Called after the header and the tail have been scrubbed above, so those writes land
  // on addressable memory rather than on the poison this is about to write.
  //
  AsanSmmQuarantinePush (FreePoolHdr, SmmPoolType, PoolIndex);

  return EFI_SUCCESS;
}

/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate.
  @param  Size                   The amount of pool to allocate.
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool.

  @retval EFI_INVALID_PARAMETER  PoolType not valid.
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
SmmInternalAllocatePool (
  IN   EFI_MEMORY_TYPE  PoolType,
  IN   UINTN            Size,
  OUT  VOID             **Buffer
  )
{
  POOL_HEADER           *PoolHdr;
  POOL_TAIL             *PoolTail;
  FREE_POOL_HEADER      *FreePoolHdr;
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Address;
  UINTN                 PoolIndex;
  BOOLEAN               HasPoolTail;
  BOOLEAN               NeedGuard;
  UINTN                 NoPages;
  UINTN                 OriSize;
  UINTN                 RightRedZoneSize;

  Address = 0;

  if ((PoolType != EfiRuntimeServicesCode) &&
      (PoolType != EfiRuntimeServicesData))
  {
    return EFI_INVALID_PARAMETER;
  }

  NeedGuard   = IsPoolTypeToGuard (PoolType);
  HasPoolTail = !(NeedGuard &&
                  ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));

  //
  // ASAN. Reserve a right redzone immediately after the caller's buffer.  Note
  // this eats into the MAX_POOL_SIZE budget: with POOL_OVERHEAD == 184 the
  // largest bucket served request drops from 1864 to 1736 bytes, anything
  // larger falls through to the page path (which is instrumented too).
  //
  OriSize          = Size;
  RightRedZoneSize = ComputePoolRightRedzoneSize (Size);
  Size            += RightRedZoneSize;

  //
  // Adjust the size by the pool header & tail overhead
  //
  Size += POOL_OVERHEAD;
  if ((Size > MAX_POOL_SIZE) || NeedGuard) {
    if (!HasPoolTail) {
      Size -= sizeof (POOL_TAIL);
    }

    NoPages = EFI_SIZE_TO_PAGES (Size);
    Status  = SmmInternalAllocatePages (
                AllocateAnyPages,
                PoolType,
                NoPages,
                &Address,
                NeedGuard
                );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (NeedGuard) {
      ASSERT (VerifyMemoryGuard (Address, NoPages) == TRUE);
      Address = (EFI_PHYSICAL_ADDRESS)(UINTN)AdjustPoolHeadA (
                                               Address,
                                               NoPages,
                                               Size
                                               );
    }

    PoolHdr            = (POOL_HEADER *)(UINTN)Address;
    PoolHdr->Signature = POOL_HEAD_SIGNATURE;
    PoolHdr->Size      = EFI_PAGES_TO_SIZE (NoPages);
    PoolHdr->Available = FALSE;
    PoolHdr->Type      = PoolType;

    if (HasPoolTail) {
      PoolTail            = HEAD_TO_TAIL (PoolHdr);
      PoolTail->Signature = POOL_TAIL_SIGNATURE;
      PoolTail->Size      = PoolHdr->Size;
    }

    PoolHdr->OriSize         = OriSize;
    PoolHdr->AsanRightRZSize = RightRedZoneSize;

    *Buffer = PoolHdr + 1;
    AsanPoisonPoolRedZones (PoolHdr);
    return Status;
  }

  Size      = (Size + MIN_POOL_SIZE - 1) >> MIN_POOL_SHIFT;
  PoolIndex = (UINTN)HighBitSet32 ((UINT32)Size);
  if ((Size & (Size - 1)) != 0) {
    PoolIndex++;
  }

  Status = InternalAllocPoolByIndex (PoolType, PoolIndex, &FreePoolHdr);
  if (!EFI_ERROR (Status)) {
    FreePoolHdr->Header.OriSize         = OriSize;
    FreePoolHdr->Header.AsanRightRZSize = RightRedZoneSize;

    *Buffer = &FreePoolHdr->Header + 1;
    AsanPoisonPoolRedZones (&FreePoolHdr->Header);
  }

  return Status;
}

/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate.
  @param  Size                   The amount of pool to allocate.
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool.

  @retval EFI_INVALID_PARAMETER  PoolType not valid.
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
SmmAllocatePool (
  IN   EFI_MEMORY_TYPE  PoolType,
  IN   UINTN            Size,
  OUT  VOID             **Buffer
  )
{
  EFI_STATUS  Status;

  Status = SmmInternalAllocatePool (PoolType, Size, Buffer);
  if (!EFI_ERROR (Status)) {
    SmmCoreUpdateProfile (
      (EFI_PHYSICAL_ADDRESS)(UINTN)RETURN_ADDRESS (0),
      MemoryProfileActionAllocatePool,
      PoolType,
      Size,
      *Buffer,
      NULL
      );
  }

  return Status;
}

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free.

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
SmmInternalFreePool (
  IN VOID  *Buffer
  )
{
  FREE_POOL_HEADER  *FreePoolHdr;
  POOL_TAIL         *PoolTail;
  BOOLEAN           HasPoolTail;
  BOOLEAN           MemoryGuarded;

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  FreePoolHdr = (FREE_POOL_HEADER *)((POOL_HEADER *)Buffer - 1);

  //
  // ASAN. A block held in the quarantine carries POOL_QUARANTINE_SIGNATURE, so reaching
  // here with one is a double free of a pointer this allocator handed out. Upstream turns
  // that into a quiet EFI_INVALID_PARAMETER; report it the way asan reports its own
  // findings, and signal it as a solution so a campaign scores it.
  //
  // Returning HERE, ahead of the two ASSERTs below, is deliberate and is the one
  // difference from the DXE core's copy of this check. PcdDebugPropertyMask is 0x2F in
  // this build: ASSERT is enabled and takes the deadloop arm, and a CpuDeadLoop inside an
  // SMI never returns to the guest -- the OS hangs with the report already on the wire
  // but every later iteration of the campaign lost. The report is the product; the
  // deadloop would destroy the run that collects it.
  //
  // Reading Signature is safe on a quarantined block: it sits inside
  // ASAN_SMM_QUARANTINE_KEEP, which is why that window exists. The POOL_TAIL reads
  // further down are NOT -- the quarantine poisons the tail -- and they are below this
  // return, which is the other reason it is here rather than after the ASSERTs.
  //
  if (FreePoolHdr->Header.Signature == POOL_QUARANTINE_SIGNATURE) {
    CHAR8  NumStr[19];

    SerialOutput ("[ASan] ERROR: double free of ");
    Num2Str64bit ((UINTN)Buffer, NumStr);
    SerialOutput (NumStr);
    SerialOutput ("\n");
    SerialOutput ("bug_descr=double-free in file: "__FILE__" at line: 0x1F\n");
    AsanSignalSolution ();
    return EFI_INVALID_PARAMETER;
  }

  ASSERT (FreePoolHdr->Header.Signature == POOL_HEAD_SIGNATURE);
  ASSERT (!FreePoolHdr->Header.Available);
  if (FreePoolHdr->Header.Signature != POOL_HEAD_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  MemoryGuarded = IsHeapGuardEnabled () &&
                  IsMemoryGuarded ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr);
  HasPoolTail = !(MemoryGuarded &&
                  ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));

  if (HasPoolTail) {
    PoolTail = HEAD_TO_TAIL (&FreePoolHdr->Header);
    ASSERT (PoolTail->Signature == POOL_TAIL_SIGNATURE);
    ASSERT (FreePoolHdr->Header.Size == PoolTail->Size);
    if (PoolTail->Signature != POOL_TAIL_SIGNATURE) {
      return EFI_INVALID_PARAMETER;
    }

    if (FreePoolHdr->Header.Size != PoolTail->Size) {
      return EFI_INVALID_PARAMETER;
    }
  } else {
    PoolTail = NULL;
  }

  //
  // ASAN. The whole block goes back to the allocator: drop both redzones
  // before any allocator bookkeeping writes into them.  Header.Size is the
  // real block size for every path below (bucket, page, guarded page).
  //
  UnpoisonPool ((UINTN)FreePoolHdr, (UINTN)FreePoolHdr->Header.Size);

  if (MemoryGuarded) {
    Buffer = AdjustPoolHeadF ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr);
    return SmmInternalFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size),
             TRUE
             );
  }

  if (FreePoolHdr->Header.Size > MAX_POOL_SIZE) {
    ASSERT (((UINTN)FreePoolHdr & EFI_PAGE_MASK) == 0);
    ASSERT ((FreePoolHdr->Header.Size & EFI_PAGE_MASK) == 0);
    return SmmInternalFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size),
             FALSE
             );
  }

  return InternalFreePoolByIndex (FreePoolHdr, PoolTail);
}

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free.

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
SmmFreePool (
  IN VOID  *Buffer
  )
{
  EFI_STATUS  Status;

  Status = SmmInternalFreePool (Buffer);
  if (!EFI_ERROR (Status)) {
    SmmCoreUpdateProfile (
      (EFI_PHYSICAL_ADDRESS)(UINTN)RETURN_ADDRESS (0),
      MemoryProfileActionFreePool,
      EfiMaxMemoryType,
      0,
      Buffer,
      NULL
      );
  }

  return Status;
}

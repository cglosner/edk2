/** @file
  Memory-safety faults, each behind a condition an input has to satisfy.

  Ground truth for the fuzzer. Every member is correct for the inputs a reasonable caller
  supplies and wrong for a set the caller has to find, so a campaign that reports one has
  demonstrated that it searched rather than that it ran.

  Built only when SAN_BENCH is defined. Never ship this.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SanBench.h>

#define SAN_BENCH_RECORD_BYTES  64
#define SAN_BENCH_TABLE_ENTRIES 16
#define SAN_BENCH_SESSIONS      4

typedef struct {
  UINT32  Magic;
  UINT32  Value;
} SAN_BENCH_SESSION;

STATIC SAN_BENCH_SESSION  *mSessions[SAN_BENCH_SESSIONS];

typedef struct {
  UINT16  Type;
  UINT16  Length;
  UINT32  Value;
} SAN_BENCH_TLV;

/**
  Heap overflow above 64 bytes.

  The allocation is a fixed 64 and the copy is the caller's Length. Callers that pass a
  record of the documented size are served correctly; the fault needs Length > 64, which
  is one comparison the fuzzer has to get past.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchCopyRecord (
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN VOID                       *Record,
  IN UINTN                      Length
  )
{
  UINT8  *Buffer;

  if ((Record == NULL) || (Length == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // A sanity bound that is not the allocation's bound. 4096 keeps the fault inside the
  // heap rather than turning it into a wild write, so ASan reports an overflow instead
  // of the guest taking a page fault nobody can attribute.
  //
  if (Length > 4096) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Buffer = AllocatePool (SAN_BENCH_RECORD_BYTES);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (Buffer, Record, Length);          // overflow when Length > 64

  FreePool (Buffer);
  return EFI_SUCCESS;
}

/**
  Underflow through a signed bound check.

  Index is INT32 and the check only rejects the high side, so any negative Index passes
  and indexes before the allocation. The classic shape of a bounds check that forgot the
  other end.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchReadEntry (
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  INT32                      Index,
  OUT UINT32                     *Value
  )
{
  UINT32  *Table;

  if (Value == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Index >= SAN_BENCH_TABLE_ENTRIES) {    // the low side is never checked
    return EFI_INVALID_PARAMETER;
  }

  //
  // Keep the fault near the allocation. Without this an Index of INT32_MIN lands far
  // outside any mapping and the report is a page fault rather than a shadow hit.
  //
  if (Index < -8) {
    return EFI_INVALID_PARAMETER;
  }

  Table = AllocateZeroPool (SAN_BENCH_TABLE_ENTRIES * sizeof (UINT32));
  if (Table == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Value = Table[Index];                     // underflow when Index < 0

  FreePool (Table);
  return EFI_SUCCESS;
}

/**
  Overread by checking the length after reading the header.

  The header is dereferenced to learn the record length, and only then is the blob's own
  size consulted. A blob shorter than a header is read past its end first.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchParseTlv (
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  VOID                       *Blob,
  IN  UINTN                      BlobSize,
  OUT UINT32                     *Value
  )
{
  SAN_BENCH_TLV  *Record;

  if ((Blob == NULL) || (Value == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Record = (SAN_BENCH_TLV *)Blob;

  //
  // Read first, check second. Correct order is to require BlobSize >= sizeof (*Record)
  // before touching Record at all.
  //
  if (Record->Length > BlobSize) {           // overread when BlobSize < sizeof (*Record)
    return EFI_BAD_BUFFER_SIZE;
  }

  *Value = Record->Value;
  return EFI_SUCCESS;
}

/**
  Allocation sized by a product that can overflow.

  Count * sizeof (SAN_BENCH_TLV) wraps for a large Count, so the allocation is tiny and
  the loop that fills it is not. The fuzzer has to supply a Count above 2^64 / 8.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchFillTable (
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN UINTN                      Count
  )
{
  SAN_BENCH_TLV  *Table;
  UINTN          Index;
  UINTN          Bytes;

  if (Count == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The guard is on Count, and the multiply below is what actually overflows. Bounding
  // the loop keeps a wrapped Count from running for an hour before it faults.
  //
  if ((Count > 64) && (Count < (MAX_UINTN / sizeof (SAN_BENCH_TLV)))) {
    return EFI_INVALID_PARAMETER;
  }

  Bytes = Count * sizeof (SAN_BENCH_TLV);    // wraps for Count >= 2^64 / 8
  Table = AllocateZeroPool (Bytes);
  if (Table == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  for (Index = 0; (Index < Count) && (Index < 32); Index++) {
    Table[Index].Type   = (UINT16)Index;     // writes past a wrapped allocation
    Table[Index].Length = sizeof (SAN_BENCH_TLV);
    Table[Index].Value  = 0;
  }

  FreePool (Table);
  return EFI_SUCCESS;
}

/**
  Double free, and the use-after-free that follows it.

  The session is freed but the slot keeps the pointer, so a second release frees it again
  and UseSession reads it after it is gone.
**/
STATIC
EFI_STATUS
EFIAPI
SanBenchReleaseSession (
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN UINTN                      Session
  )
{
  if (Session >= SAN_BENCH_SESSIONS) {
    return EFI_INVALID_PARAMETER;
  }

  if (mSessions[Session] == NULL) {
    mSessions[Session] = AllocateZeroPool (sizeof (SAN_BENCH_SESSION));
    if (mSessions[Session] == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    mSessions[Session]->Magic = 0x5A5A5A5A;
  }

  FreePool (mSessions[Session]);             // the slot is not cleared
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
SanBenchUseSession (
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  UINTN                      Session,
  OUT UINT32                     *Value
  )
{
  if ((Value == NULL) || (Session >= SAN_BENCH_SESSIONS)) {
    return EFI_INVALID_PARAMETER;
  }

  if (mSessions[Session] == NULL) {
    return EFI_NOT_READY;
  }

  *Value = mSessions[Session]->Value;        // use-after-free once released
  return EFI_SUCCESS;
}

SAN_BENCH_MEMORY_PROTOCOL  gSanBenchMemory = {
  SanBenchCopyRecord,
  SanBenchReadEntry,
  SanBenchParseTlv,
  SanBenchFillTable,
  SanBenchReleaseSession,
  SanBenchUseSession
};

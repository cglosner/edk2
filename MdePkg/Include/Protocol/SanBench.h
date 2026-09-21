/** @file
  Protocols that are wrong on purpose, as ground truth for the fuzzer and the sanitizer.

  The self test proves the runtime reports an error it is handed directly. It cannot
  answer the question a campaign actually asks: given a protocol and no knowledge of it,
  does the fuzzer reach the input that breaks it, and does the sanitizer say so when it
  does. Every member here hides its fault behind a condition an input has to satisfy --
  a length, a magic value, a count -- so a campaign that finds them has demonstrated
  search, and one that does not has measured its own reach.

  Two protocols, because two different things are being measured:

    SAN_BENCH_MEMORY    classic memory safety, which ASan is expected to catch
    SAN_BENCH_FIRMWARE  faults peculiar to firmware, which it is not

  Built only when SAN_BENCH is defined. These must never appear in a production image.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SAN_BENCH_PROTOCOL_H_
#define SAN_BENCH_PROTOCOL_H_

#define SAN_BENCH_MEMORY_PROTOCOL_GUID \
  { 0x3d9a4f21, 0x7c68, 0x4b0e, { 0xa1, 0x53, 0x62, 0xd8, 0x7e, 0x94, 0x11, 0x05 } }

#define SAN_BENCH_FIRMWARE_PROTOCOL_GUID \
  { 0x5e2c8b70, 0x1a4d, 0x49f6, { 0xb7, 0x28, 0x0c, 0x3f, 0xd5, 0x61, 0x8a, 0x2e } }

typedef struct _SAN_BENCH_MEMORY_PROTOCOL    SAN_BENCH_MEMORY_PROTOCOL;
typedef struct _SAN_BENCH_FIRMWARE_PROTOCOL  SAN_BENCH_FIRMWARE_PROTOCOL;

/**
  Copy Length bytes of Record into a 64 byte allocation.

  Correct for Length <= 64. Above that it writes past the end -- a heap overflow the
  caller controls through a length it also supplies.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_COPY_RECORD)(
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN VOID                       *Record,
  IN UINTN                      Length
  );

/**
  Read the Index'th entry of a 16 entry table.

  The bound is checked as a signed comparison, so a negative Index passes it and reads
  before the allocation.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_READ_ENTRY)(
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  INT32                      Index,
  OUT UINT32                     *Value
  );

/**
  Parse a TLV blob, returning the value of the first record.

  The header is read before the length is checked, so a blob shorter than the header
  is read past its end.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_PARSE_TLV)(
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  VOID                       *Blob,
  IN  UINTN                      BlobSize,
  OUT UINT32                     *Value
  );

/**
  Allocate Count records and fill them.

  Count * sizeof(record) overflows UINTN for a large Count, so the allocation is small
  and the loop that fills it is not.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_FILL_TABLE)(
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN UINTN                      Count
  );

/**
  Release a session handle.

  Frees the session but leaves the pointer in the table, so releasing the same handle
  twice is a double free and using it afterwards is a use-after-free.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_RELEASE_SESSION)(
  IN SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN UINTN                      Session
  );

/**
  Use a session handle previously obtained.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_USE_SESSION)(
  IN  SAN_BENCH_MEMORY_PROTOCOL  *This,
  IN  UINTN                      Session,
  OUT UINT32                     *Value
  );

struct _SAN_BENCH_MEMORY_PROTOCOL {
  SAN_BENCH_COPY_RECORD      CopyRecord;
  SAN_BENCH_READ_ENTRY       ReadEntry;
  SAN_BENCH_PARSE_TLV        ParseTlv;
  SAN_BENCH_FILL_TABLE       FillTable;
  SAN_BENCH_RELEASE_SESSION  ReleaseSession;
  SAN_BENCH_USE_SESSION      UseSession;
};

/**
  Copy a caller-supplied pointer's contents into the driver's own storage.

  The pointer arrives from outside and is dereferenced without asking where it points.
  A pointer into SMRAM, a firmware volume or MMIO is honoured exactly like a pointer into
  the caller's own buffer. ASan cannot see this: the access is in bounds of *something*,
  it is simply in bounds of memory this driver has no business reading.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_ABSORB)(
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN VOID                         *Foreign,
  IN UINTN                        Length
  );

/**
  Read a length out of a shared buffer, validate it, then read it again to use it.

  Two fetches of the same untrusted word with a check in between. Whatever the check
  approved is not necessarily what gets used. Single-threaded ASan sees two ordinary
  in-bounds reads.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_DOUBLE_FETCH)(
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN VOID                         *Shared,
  IN UINTN                        SharedSize
  );

/**
  Use boot services from a path that may run after ExitBootServices.

  gBS is captured at entry and used later. After ExitBootServices the table is gone and
  the call is into freed or repurposed memory -- a lifetime rule ASan has no model of.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_LATE_BOOT_SERVICE)(
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This
  );

/**
  Keep using a protocol interface after uninstalling it.

  The interface pointer is cached at open and not dropped when the protocol goes away.
  The memory may still be mapped and may still hold plausible function pointers, so this
  is a lifetime fault rather than a memory-safety one.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_STALE_INTERFACE)(
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This
  );

/**
  Trust a size that came back from GetVariable.

  The variable is attacker-writable from an OS. Its size is used to copy into a fixed
  buffer without comparing the two.
**/
typedef
EFI_STATUS
(EFIAPI *SAN_BENCH_TRUST_VARIABLE)(
  IN SAN_BENCH_FIRMWARE_PROTOCOL  *This,
  IN UINT32                       Selector
  );

struct _SAN_BENCH_FIRMWARE_PROTOCOL {
  SAN_BENCH_ABSORB             Absorb;
  SAN_BENCH_DOUBLE_FETCH       DoubleFetch;
  SAN_BENCH_LATE_BOOT_SERVICE  LateBootService;
  SAN_BENCH_STALE_INTERFACE    StaleInterface;
  SAN_BENCH_TRUST_VARIABLE     TrustVariable;
};

extern EFI_GUID  gSanBenchMemoryProtocolGuid;
extern EFI_GUID  gSanBenchFirmwareProtocolGuid;

#endif

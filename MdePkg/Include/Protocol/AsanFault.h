/** @file
  A protocol that is wrong on purpose, for proving the sanitizer reports.

  The self-test application proves ASan sees errors in its own allocations. It cannot prove
  the thing a fuzzing campaign depends on: that an error inside a separately built DXE
  driver, on memory that driver allocated, reached through a protocol call while the
  harness is running, is detected and reported. Those are different images, different
  instrumentation runs and a different reporting path, and a campaign that finds nothing
  looks identical whether the firmware is clean or the detector is blind.

  This protocol is the positive control for that path. It is built only when
  ASAN_FAULT_PROTOCOL is defined and must never appear in a production build.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ASAN_FAULT_PROTOCOL_H_
#define ASAN_FAULT_PROTOCOL_H_

#define ASAN_FAULT_PROTOCOL_GUID \
  { 0x7ac1f9d2, 0x5b30, 0x4e71, { 0x9a, 0x42, 0x1d, 0x8c, 0x6f, 0x25, 0xb3, 0x04 } }

typedef struct _ASAN_FAULT_PROTOCOL ASAN_FAULT_PROTOCOL;

/**
  Write Length bytes into a buffer this driver allocated at a fixed 64 bytes.
  A Length above 64 runs past it, which is a heap-buffer-overflow write.
**/
typedef
EFI_STATUS
(EFIAPI *ASAN_FAULT_OVERFLOW)(
  IN ASAN_FAULT_PROTOCOL  *This,
  IN UINTN                Length,
  IN UINT8                Fill
  );

/**
  Read one byte at Offset from a 64 byte allocation. An Offset above 64 is a
  heap-buffer-overflow read.
**/
typedef
EFI_STATUS
(EFIAPI *ASAN_FAULT_OVERREAD)(
  IN  ASAN_FAULT_PROTOCOL  *This,
  IN  UINTN                Offset,
  OUT UINT8                *Value
  );

/**
  Free a buffer and then write to it when Touch is non-zero: use-after-free.
**/
typedef
EFI_STATUS
(EFIAPI *ASAN_FAULT_USEAFTERFREE)(
  IN ASAN_FAULT_PROTOCOL  *This,
  IN BOOLEAN              Touch
  );

struct _ASAN_FAULT_PROTOCOL {
  ASAN_FAULT_OVERFLOW        Overflow;
  ASAN_FAULT_OVERREAD        Overread;
  ASAN_FAULT_USEAFTERFREE    UseAfterFree;
};

extern EFI_GUID  gAsanFaultProtocolGuid;

#endif

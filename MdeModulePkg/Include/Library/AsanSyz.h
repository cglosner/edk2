/** @file
  AsanSyz - syzkaller-facing wrappers around the EDK2 AddressSanitizer
  port. The functions declared here are guaranteed to:

    1. Emit reports in a format pkg/report/edk2.go on the syzkaller side
       can parse (the "==ERROR: AddressSanitizer:" line).
    2. Use only the small subset of the ASan internal API that is safe
       to call from a fuzzing dispatcher (no thread-locals, no globals
       that survive across programs in undefined ways).

  This is the public surface SyzAgentDxe and similar consumers should
  prefer over reaching directly into Library/Asan.h.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ASAN_SYZ_H_
#define ASAN_SYZ_H_

#include <Base.h>

/**
  Mark Length bytes starting at Addr as inaccessible. Subsequent loads
  or stores in this region will trigger an ASan report. Aligns Addr
  down to the nearest shadow granule.

  @param[in] Addr   First byte to poison.
  @param[in] Length Number of bytes (rounded up to a shadow granule).
**/
VOID
EFIAPI
AsanSyzPoison (
  IN UINTN  Addr,
  IN UINTN  Length
  );

/**
  Inverse of AsanSyzPoison. Calling AsanSyzUnpoison on a region that
  was never poisoned is a no-op.
**/
VOID
EFIAPI
AsanSyzUnpoison (
  IN UINTN  Addr,
  IN UINTN  Length
  );

/**
  Manually fire an ASan report. Useful for the fuzzer to deliberately
  walk shadow memory after a sequence of allocations and observe state
  via the report mechanism.

  @param[in] Addr     The address that was "accessed".
  @param[in] Size     The access width in bytes.
  @param[in] IsWrite  Non-zero for writes.
**/
VOID
EFIAPI
AsanSyzReport (
  IN UINTN  Addr,
  IN UINTN  Size,
  IN UINT8  IsWrite
  );

/**
  Returns TRUE if AsanLib has been constructed and the shadow region
  is mapped. Consumers should bail out early if this returns FALSE,
  because every other entry point in the AsanSyz family becomes a no-op
  in that state.
**/
BOOLEAN
EFIAPI
AsanSyzReady (
  VOID
  );

#endif // ASAN_SYZ_H_

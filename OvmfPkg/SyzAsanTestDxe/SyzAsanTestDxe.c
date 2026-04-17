/** @file
  SyzAsanTestDxe — proof-of-life for the asan-instrumented SyzAgent
  build. The depex on gAsanShadowReadyProtocolGuid guarantees we run
  AFTER SyzAgentDxe has located the BAR-backed shadow region and
  installed the rendezvous protocol. We pick up the shadow info,
  call AsanLibActivate() to flip THIS module's per-instance asan
  globals on, and then deliberately read past the end of an
  AllocatePool() buffer. The expected outcome:

    [SYZ-ASAN-TEST] activated, base=0x380000200000 size=0xfe00000
    [SYZ-ASAN-TEST] before OOB read
    ==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
    [SYZ-ASAN-TEST] after OOB read (recovered)

  -fsanitize-recover=address keeps execution going after the report
  so we can confirm the driver returns cleanly.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Guid/AsanInfo.h>

//
// Wrapped in noinline so the compiler can't optimize the OOB read
// away — and so the stack frame is its own asan-instrumented frame
// with its own redzones, separate from the entry-point function.
//
__attribute__((noinline))
STATIC
UINT8
StackOob (
  IN UINTN  Index
  )
{
  volatile UINT8  buf[16];
  // Initialize so the OOB read isn't an uninit-data read.
  for (UINTN i = 0; i < 16; i++) {
    buf[i] = (UINT8)(0xA0 + i);
  }
  // The compiler-emitted __asan_set_shadow_f1 in the prologue
  // poisoned the right-redzone (the bytes from &buf[16] up to the
  // next 32-byte boundary on the stack). Reading buf[Index] for
  // Index >= 16 lands inside that redzone and the __asan_load1
  // call before the read should fire __asan_report_load1.
  return buf[Index];
}

EFI_STATUS
EFIAPI
SyzAsanTestDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS         Status;
  ASAN_SHADOW_INFO   *Info = NULL;
  volatile UINT8     sink = 0;

  DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] entry\n"));

  Status = gBS->LocateProtocol (
                  &gAsanShadowReadyProtocolGuid,
                  NULL,
                  (VOID **)&Info
                  );
  if (EFI_ERROR (Status) || (Info == NULL)) {
    DEBUG ((DEBUG_ERROR, "[SYZ-ASAN-TEST] no asan shadow ready protocol: %r\n", Status));
    return EFI_SUCCESS;
  }
  DEBUG ((
    DEBUG_INFO,
    "[SYZ-ASAN-TEST] activating, base=0x%lx size=0x%lx\n",
    Info->ShadowMemoryStart,
    Info->ShadowMemorySize
    ));

  AsanLibActivate (
    (VOID *)(UINTN)Info->ShadowMemoryStart,
    (UINTN)Info->ShadowMemorySize
    );

  DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] in-bounds read buf[5]\n"));
  sink ^= StackOob (5);
  DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] in-bounds read OK\n"));

  DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] stack OOB read buf[20] - expecting asan report\n"));
  sink ^= StackOob (20);
  DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] after stack OOB, sink=%u (recovered)\n", (UINTN)sink));

  //
  // Heap OOB test: allocate 16 bytes, read at buf[24].
  // The DxeCore pool allocator calls PoisonPool which does lazy
  // config-table activation via AsanTryLazyActivate. If the shadow
  // offset is correct and the config table was installed by
  // SyzAgentDxe, the __asan_load1_noabort at buf[24] should see
  // the pool right-redzone poison byte and fire a report.
  //
  {
    UINT8 *hbuf = AllocatePool (16);
    if (hbuf != NULL) {
      SetMem (hbuf, 16, 0xBB);
      //
      // The old debug peek hardcoded shadow offset 0x380000200000,
      // which no longer matches the runtime BAR-backed shadow
      // (published by SyzAgentDxe) so reading it page-faulted. We
      // now rely on the compiler-emitted __asan_load1_noabort call
      // for the OOB detection — it consults the runtime shadow via
      // mShadowOffset / __asan_shadow_memory_dynamic_address.
      //
      DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] heap OOB read hbuf[16] - expecting asan report (shadow=0xFA)\n"));
      sink ^= hbuf[16];
      DEBUG ((DEBUG_INFO, "[SYZ-ASAN-TEST] after heap OOB, sink=%u (recovered)\n", (UINTN)sink));
      FreePool (hbuf);
    }
  }

  return EFI_SUCCESS;
}

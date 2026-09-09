/** @file
  A deliberate memory error, so "ASan is enabled" can be told from "ASan detects".

  Instrumenting firmware and seeing no findings proves nothing on its own: the shadow may
  be unmapped, the runtime may have deactivated itself for want of a HOB, or the report
  may be going to a fuzzer that is not listening. Every one of those failures looks
  exactly like a clean run. This application commits a known error of a chosen class and
  is expected to be reported; if it is not, the pipeline is broken rather than the
  firmware clean.

  Selected by the first input byte, so one image covers every class and the fuzzer picks:
    0  heap overflow, write one past a pool allocation
    1  heap underflow, write one before it
    2  use after free
    3  double free
    4  control -- a correct allocation and free, which must NOT be reported

  Copyright (c) 2026, Firness contributors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

//
// The fuzzer handshake, written out rather than included: this application deliberately
// lives outside the generated harness tree so it can be built by any platform dsc.
// Values from FirnessBackend.h -- START_VIRT is 0, END is 4, END_OK is 1.
//
#define ASAN_SELFTEST_INPUT_SIZE  0x1000

STATIC UINT8  mInput[ASAN_SELFTEST_INPUT_SIZE];

#if defined (ASAN_SELFTEST_BACKEND_QEMU)
STATIC
UINT64
HarnessStart (
  VOID    *Buffer,
  UINT64  MaxLen
  )
{
  UINT64  Ret = 0;

  __asm__ __volatile__ (".byte 0x0f, 0x3a, 0xf2, 0x66\n\t"
                        : "+a" (Ret)
                        : "D" ((UINT64)(UINTN)Buffer), "S" (MaxLen)
                        : "memory", "cc");
  return Ret;
}

STATIC
VOID
HarnessStop (
  VOID
  )
{
  UINT64  Ret = 4;

  __asm__ __volatile__ (".byte 0x0f, 0x3a, 0xf2, 0x66\n\t"
                        : "+a" (Ret)
                        : "D" ((UINT64)1)
                        : "memory", "cc");
}

#else
STATIC
UINT64
HarnessStart (
  VOID    *Buffer,
  UINT64  MaxLen
  )
{
  UINTN         Size = (UINTN)MaxLen;
  unsigned int  Value = (1U << 0x10U) | 0x4711U;
  unsigned int  a = 0, b = 0, c = 0, d = 0;

  __asm__ __volatile__ ("cpuid"
                        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
                        : "a" (Value), "D" (0), "S" (Buffer), "d" (&Size)
                        : "memory");
  return (UINT64)Size;
}

STATIC
VOID
HarnessStop (
  VOID
  )
{
  unsigned int  Value = (4U << 0x10U) | 0x4711U;
  unsigned int  a = 0, b = 0, c = 0, d = 0;

  __asm__ __volatile__ ("cpuid"
                        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
                        : "a" (Value), "D" (0)
                        : "memory");
}

#endif

//
// Not inlined and not optimised away: the compiler can see that these writes are out of
// bounds and is entitled to drop them, which would make the test silently vacuous.
//
STATIC
VOID
EFIAPI
Scribble (
  IN volatile UINT8  *Where,
  IN UINT8           Value
  )
{
  *Where = Value;
}

EFI_STATUS
EFIAPI
AsanSelfTestMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  UINT8  *Buffer;
  UINT64  Length;
  UINTN   Choice;

  Length = ASAN_SELFTEST_INPUT_SIZE;
  Length = HarnessStart (mInput, Length);
  Choice = (Length > 0) ? mInput[0] : 0;

  //
  // ASAN_SELFTEST_ALL walks every class in one boot. That only works when a report does
  // not end the run, so build it with ASAN_FUZZER_BACKEND=1: the TSFFS handshake is a
  // cpuid, which is a legal no-op with no fuzzer attached, whereas the libafl-qemu
  // instruction is #UD and would stop at the first finding.
  //
#if defined (ASAN_SELFTEST_ALL)
  for (Choice = 0; Choice < 5; Choice++) {
#endif
  Buffer = AllocatePool (64);
  if (Buffer == NULL) {
    HarnessStop ();
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_ERROR, "AsanSelfTest: case %d buffer 0x%lx shadow",
          (UINTN)(Choice % 5), (UINT64)(UINTN)Buffer));
  {
    volatile UINT8  *Shadow;
    UINTN            Index;

    Shadow = (volatile UINT8 *)(UINTN)(((UINTN)Buffer >> 3) + 0x5000000);
    for (Index = 0; Index < 12; Index++) {
      DEBUG ((DEBUG_ERROR, " %02x", Shadow[Index]));
    }

    DEBUG ((DEBUG_ERROR, "\n"));
  }

  switch (Choice % 5) {
    case 0:
      DEBUG ((DEBUG_ERROR, "AsanSelfTest: expect heap-buffer-overflow\n"));
      Scribble (&Buffer[64], 0x41);
      FreePool (Buffer);
      break;

    case 1:
      DEBUG ((DEBUG_ERROR, "AsanSelfTest: expect heap-buffer-underflow\n"));
      Scribble (&Buffer[-1], 0x42);
      FreePool (Buffer);
      break;

    case 2:
      DEBUG ((DEBUG_ERROR, "AsanSelfTest: expect use-after-free\n"));
      FreePool (Buffer);
      Scribble (&Buffer[0], 0x43);
      break;

    case 3:
      DEBUG ((DEBUG_ERROR, "AsanSelfTest: expect double-free\n"));
      FreePool (Buffer);
      FreePool (Buffer);
      break;

    default:
      DEBUG ((DEBUG_ERROR, "AsanSelfTest: control, expect NO report\n"));
      SetMem (Buffer, 64, 0x44);
      FreePool (Buffer);
      break;
  }

  DEBUG ((DEBUG_ERROR, "AsanSelfTest: case %d done\n", (UINTN)(Choice % 5)));
#if defined (ASAN_SELFTEST_ALL)
  }
#endif

  HarnessStop ();
  return EFI_SUCCESS;
}

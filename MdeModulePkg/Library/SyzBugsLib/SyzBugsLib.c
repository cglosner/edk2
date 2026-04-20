/** @file
  SyzBugsLib — deterministic bug-class primitives.

  Each function deliberately triggers exactly ONE sanitizer-detectable
  bug class. Volatile locals + indirect indices defeat dead-code
  elimination and constant-folding.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SyzBugsLib.h>

// Global sinks prevent dead-code elimination of the result path.
volatile UINT64 gSyzBugsLibSinkU64 = 0;
volatile UINT8  gSyzBugsLibSinkU8  = 0;

// Global buffer for the global-overflow primitive.
static UINT8 gSyzBugsLibGlobalBuf[16] = { 0 };

#define NOINLINE __attribute__((noinline, used))

// Shadow byte layout for KASan mode (-fasan-shadow-offset=0x30000000):
//   shadow(addr) = (addr >> 3) + 0x30000000
//   shadow byte 0x00 = accessible, 0xfa = heap-right-redzone,
//   0xfd = heap-freed, 0xfb = heap-left-redzone
#define SYZBUGS_SHADOW_OFFSET  0x30000000UL
#define SYZBUGS_REDZONE_MAGIC  0xfa
#define SYZBUGS_FREED_MAGIC    0xfd

STATIC
VOID
SyzBugsPoisonRange (
  IN UINTN   Addr,
  IN UINTN   Size,
  IN UINT8   Magic
  )
{
  // Direct shadow-byte write — bypasses AsanLib to work from
  // any module (SyzAgentDxe links AsanLibNull so AsanLib helpers are
  // no-ops). Caller must pass an 8-byte-aligned address and size.
  volatile UINT8 *Shadow = (volatile UINT8 *)(UINTN)((Addr >> 3) + SYZBUGS_SHADOW_OFFSET);
  UINTN           I;
  for (I = 0; I < (Size >> 3); I++) {
    Shadow[I] = Magic;
  }
}

STATIC
VOID
SyzBugsUnpoisonRange (
  IN UINTN  Addr,
  IN UINTN  Size
  )
{
  volatile UINT8 *Shadow = (volatile UINT8 *)(UINTN)((Addr >> 3) + SYZBUGS_SHADOW_OFFSET);
  UINTN           I;
  for (I = 0; I < (Size >> 3); I++) {
    Shadow[I] = 0;
  }
}

// =====================================================================
// ASan-class primitives
// =====================================================================

//
// Heap primitives: EDK2's AllocatePool doesn't hook ASan so allocations
// have no automatic redzones. We work around by allocating a larger
// buffer, manually poisoning bytes [16..32) as right-redzone, then
// reading/writing into the poisoned range. ASan's shadow check does fire
// (shadow byte is non-zero).
//
NOINLINE
UINT64
SyzBugsLibTriggerHeapOobRead (
  VOID
  )
{
  UINT8  *Buf;
  UINT8   V;

  Buf = (UINT8 *)AllocatePool (64);
  if (Buf == NULL) {
    return 0;
  }
  // Align up to 8-byte boundary for clean shadow mapping.
  UINTN AlignedAddr = ((UINTN)Buf + 7) & ~(UINTN)7;
  SyzBugsPoisonRange (AlignedAddr + 16, 16, SYZBUGS_REDZONE_MAGIC);
  V = ((volatile UINT8 *)(UINTN)AlignedAddr)[20];  // into the redzone
  gSyzBugsLibSinkU8 = V;
  SyzBugsUnpoisonRange (AlignedAddr + 16, 16);
  FreePool (Buf);
  return (UINT64)V;
}

NOINLINE
UINT64
SyzBugsLibTriggerHeapOobWrite (
  VOID
  )
{
  UINT8  *Buf;

  Buf = (UINT8 *)AllocatePool (64);
  if (Buf == NULL) {
    return 0;
  }
  UINTN AlignedAddr = ((UINTN)Buf + 7) & ~(UINTN)7;
  SyzBugsPoisonRange (AlignedAddr + 16, 16, SYZBUGS_REDZONE_MAGIC);
  ((volatile UINT8 *)(UINTN)AlignedAddr)[24] = 0xCA;  // write into redzone
  SyzBugsUnpoisonRange (AlignedAddr + 16, 16);
  FreePool (Buf);
  return 1;
}

NOINLINE
UINT64
SyzBugsLibTriggerHeapUaf (
  VOID
  )
{
  UINT8  *Buf;
  UINT8   V;

  Buf = (UINT8 *)AllocatePool (32);
  if (Buf == NULL) {
    return 0;
  }
  UINTN AlignedAddr = ((UINTN)Buf + 7) & ~(UINTN)7;
  ((volatile UINT8 *)(UINTN)AlignedAddr)[0] = 0x5A;
  // Mark the range as freed without actually freeing (freed shadow = 0xfd)
  SyzBugsPoisonRange (AlignedAddr, 16, SYZBUGS_FREED_MAGIC);
  V = ((volatile UINT8 *)(UINTN)AlignedAddr)[0];  // UAF read
  gSyzBugsLibSinkU8 = V;
  SyzBugsUnpoisonRange (AlignedAddr, 16);
  FreePool (Buf);
  return (UINT64)V;
}

NOINLINE
static
UINT8
StackOobReadHelper (
  volatile UINTN Idx
  )
{
  volatile UINT8 LocalBuf[16] = { 0 };
  return LocalBuf[Idx];          // stack OOB read
}

NOINLINE
UINT64
SyzBugsLibTriggerStackOobRead (
  VOID
  )
{
  UINT8 V = StackOobReadHelper (20);
  gSyzBugsLibSinkU8 = V;
  return (UINT64)V;
}

NOINLINE
static
VOID
StackOobWriteHelper (
  volatile UINTN Idx,
  UINT8          V
  )
{
  volatile UINT8 LocalBuf[16] = { 0 };
  LocalBuf[Idx] = V;             // stack OOB write
  gSyzBugsLibSinkU8 = LocalBuf[0];
}

NOINLINE
UINT64
SyzBugsLibTriggerStackOobWrite (
  VOID
  )
{
  StackOobWriteHelper (20, 0xAB);
  return 1;
}

NOINLINE
UINT64
SyzBugsLibTriggerGlobalOob (
  VOID
  )
{
  volatile UINTN Idx = 24;
  UINT8          V   = gSyzBugsLibGlobalBuf[Idx]; // global OOB
  gSyzBugsLibSinkU8 = V;
  return (UINT64)V;
}

// =====================================================================
// UBSan-class primitives
// =====================================================================

NOINLINE
UINT64
SyzBugsLibTriggerDivByZero (
  VOID
  )
{
  volatile UINT32 Num = 0xCAFE;
  volatile UINT32 Den = 0;
  UINT32          R   = Num / Den;       // UBSan div-0 (or CPU #DE)
  gSyzBugsLibSinkU64 = R;
  return R;
}

NOINLINE
UINT64
SyzBugsLibTriggerSignedAddOv (
  VOID
  )
{
  volatile INT32 A = 0x7FFFFFFF;
  volatile INT32 B = 1;
  INT32          R = A + B;              // UBSan signed add-ov
  gSyzBugsLibSinkU64 = (UINT32)R;
  return (UINT64)(UINT32)R;
}

NOINLINE
UINT64
SyzBugsLibTriggerMulOverflow (
  VOID
  )
{
  volatile INT32 A = 0x10000;
  volatile INT32 B = 0x10000;
  INT32          R = A * B;              // UBSan signed mul-ov
  gSyzBugsLibSinkU64 = (UINT32)R;
  return (UINT64)(UINT32)R;
}

NOINLINE
UINT64
SyzBugsLibTriggerShiftOutOfBnd (
  VOID
  )
{
  volatile UINT32 V = 1;
  volatile UINT32 S = 33;                // >= bit-width(int)
  UINT32          R = V << S;            // UBSan shift-oob
  gSyzBugsLibSinkU64 = R;
  return (UINT64)R;
}

NOINLINE
UINT64
SyzBugsLibTriggerNullDeref (
  VOID
  )
{
  volatile UINT64 *P = NULL;
  UINT64            V = *P;              // #PF / UBSan null
  gSyzBugsLibSinkU64 = V;
  return V;
}

// =====================================================================
// Firmware-sanitizer-class primitives (MMIOCS, SMIBVS, PLS)
// =====================================================================

// Bogus MMIO address outside every GCD-registered range. MMIOCS
// (when enforcing) must reject this.
NOINLINE
UINT64
SyzBugsLibTriggerMmiocsViolation (
  VOID
  )
{
  volatile UINT64 *Mmio = (volatile UINT64 *)(UINTN)0xDEADBEEFULL;
  UINT64            V     = *Mmio;       // kGPF on unmapped addr;
                                         // MMIOCS should catch before fault
  gSyzBugsLibSinkU64 = V;
  return V;
}

NOINLINE
UINT64
SyzBugsLibTriggerSmiBufInSmram (
  VOID
  )
{
  // Placeholder — SMM harness will overwrite this with a CommBuffer
  // pointer pointing into SMRAM. Without SMM_REQUIRE=TRUE this is a
  // no-op.
  gSyzBugsLibSinkU64 = 0x5A11B0F;
  return 0;
}

NOINLINE
UINT64
SyzBugsLibTriggerUafProtocol (
  VOID
  )
{
  // Placeholder — PLS (ProtocolLifetimeSan) target. Currently disabled
  // due to false positives on static globals.
  gSyzBugsLibSinkU64 = 0xB10C4DED;
  return 0;
}

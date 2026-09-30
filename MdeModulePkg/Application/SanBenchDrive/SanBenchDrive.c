/** @file
  Calls every benchmark fault with the input that triggers it.

  Ground truth needs two measurements and they answer different questions. Fuzzing the
  benchmark protocols measures whether the fuzzer can FIND the faults. This measures
  whether the sanitizers can SEE them, by going straight to each one. A class that fails
  here can never be found by any amount of searching, and knowing which of the two broke
  is the whole point of keeping them apart.

  Every case announces itself first, so a run that stops early says which case stopped it.

  Two of the cases are destructive -- a double free takes the pool free list with it, and
  a wrapped size allocates a few bytes and writes hundreds into them -- so a single boot
  cannot measure everything after them. Each case is therefore self-contained and
  selectable: with

    -fw_cfg name=opt/sanbench/case,string=size-overflow

  only that case runs, and scoring one case per boot gives every class a clean
  measurement. With no fw_cfg the whole sequence runs in the safe order, which is the
  cheap answer and still scores everything up to the first destructive case.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SanBench.h>

//
// Announce on the wire the sanitizers report on, not through DEBUG. The two are
// different streams: interleaving a case with its report is the only way to say which
// case a report belongs to, and with them apart the scoring is guesswork.
//
VOID SerialOutput (IN CONST CHAR8 *String);
VOID AsanSetRegionChecks (IN BOOLEAN Active);
VOID AsanRegisterUntrusted (IN UINT64 Base, IN UINT64 Size);

STATIC SAN_BENCH_MEMORY_PROTOCOL    *mMem;
STATIC SAN_BENCH_FIRMWARE_PROTOCOL  *mFw;

typedef VOID (*SAN_BENCH_CASE) (VOID);

typedef struct {
  CONST CHAR8       *Name;
  SAN_BENCH_CASE    Run;
  BOOLEAN           Destructive;   // nothing measurable can follow it in the same boot
} SAN_BENCH_ENTRY;

//
// The control. If nothing is reported for the rest, a silent runtime and a clean one
// look the same; if something is reported for THIS, the runtime is crying wolf and
// every later report is worth less.
//
STATIC
VOID
CaseControl (
  VOID
  )
{
  UINT8  Big[64];

  mMem->CopyRecord (mMem, Big, sizeof (Big));   // exactly the allocation: correct
}

STATIC
VOID
CaseHeapOverflow (
  VOID
  )
{
  UINT8  Big[72];

  mMem->CopyRecord (mMem, Big, sizeof (Big));   // eight bytes past the fixed 64
}

STATIC
VOID
CaseHeapUnderflow (
  VOID
  )
{
  UINT32  Value;

  mMem->ReadEntry (mMem, -1, &Value);           // one entry below the table
}

//
// On the heap, not the stack. The obvious way to write this is a two byte local, and it
// reports nothing: the build carries -mllvm -asan-stack=0 because enabling stack
// instrumentation faults the boot in CpuDxe, so a stack overread is outside what this
// sanitizer can see at all. Putting the blob on the heap measures the coverage that
// exists rather than the gap that is already known.
//
STATIC
VOID
CaseTlvOverread (
  VOID
  )
{
  UINT32  Value;
  VOID    *Blob;

  Blob = AllocatePool (2);
  if (Blob != NULL) {
    mMem->ParseTlv (mMem, Blob, 2, &Value);     // the header is eight bytes
  }
}

STATIC
VOID
CaseForeignPointer (
  VOID
  )
{
  mFw->Absorb (mFw, (VOID *)(UINTN)0xFFC00000, 32);   // the flash region, not ours
}

//
// Declare the buffer untrusted for the duration of the call, which is what a harness
// does for every buffer it fills from fuzzer input and hands to a protocol. Without
// that the check has nothing to watch: a double fetch reads ordinary valid memory and
// is invisible unless someone says which memory is not to be trusted.
//
STATIC
VOID
CaseDoubleFetch (
  VOID
  )
{
  VOID  *Shared;

  Shared = AllocateZeroPool (256);
  if (Shared == NULL) {
    return;
  }

  *(UINT32 *)Shared = 8;
  AsanRegisterUntrusted ((UINT64)(UINTN)Shared, 256);
  mFw->DoubleFetch (mFw, Shared, 256);
  AsanRegisterUntrusted (0, 0);
}

STATIC
VOID
CaseStaleInterface (
  VOID
  )
{
  mFw->StaleInterface (mFw);
}

//
// Reachable only after ExitBootServices, which an application running under BDS is by
// definition before. Say so rather than calling it and scoring a silence: "not detected"
// and "not attempted" are different results and a benchmark that conflates them
// overstates its own gaps.
//
STATIC
VOID
CaseLateBootService (
  VOID
  )
{
  SerialOutput ("SanBenchDrive: not attempted -- needs the runtime phase\n");
}

//
// One free, then the read through the slot that still points at it. Self-contained: it
// opens the session it is about to release, so the case does not depend on whatever ran
// before it.
//
STATIC
VOID
CaseUseAfterFree (
  VOID
  )
{
  UINT32  Value;

  mMem->ReleaseSession (mMem, 0);
  mMem->UseSession (mMem, 0, &Value);
}

//
// Both frees here. In the full sequence the use-after-free case supplies the first one,
// but a case picked on its own has to do the whole thing itself or it is measuring a
// single ordinary free.
//
STATIC
VOID
CaseDoubleFree (
  VOID
  )
{
  mMem->ReleaseSession (mMem, 0);
  mMem->ReleaseSession (mMem, 0);               // the slot still holds the pointer
}

//
// TrustVariable copies the variable's bytes into a 32 byte local and the stack does not
// survive it. The variable has to exist and be bigger than the destination, or
// GetVariable answers EFI_NOT_FOUND and the two-call pattern the check looks for never
// happens. Writing it here is what makes the case reachable.
//
STATIC
VOID
CaseVariableSizeTrusted (
  VOID
  )
{
  UINT8  Big[256];

  gRT->SetVariable (
         L"SanBenchPayload",
         &gSanBenchFirmwareProtocolGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS,
         sizeof (Big),
         Big
         );
  mFw->TrustVariable (mFw, 1);
}

STATIC
VOID
CaseSizeOverflow (
  VOID
  )
{
  mMem->FillTable (mMem, (MAX_UINTN / 8) + 4);  // the product wraps
}

//
// Order matters for a whole-sequence run: everything measurable first, the two that take
// the heap with them last. A selected run ignores the order entirely, which is the point
// of having the selector.
//
STATIC CONST SAN_BENCH_ENTRY  mCases[] = {
  { "control",                CaseControl,             FALSE },
  { "heap-buffer-overflow",   CaseHeapOverflow,        FALSE },
  { "heap-buffer-underflow",  CaseHeapUnderflow,       FALSE },
  { "tlv-overread",           CaseTlvOverread,         FALSE },
  { "foreign-pointer",        CaseForeignPointer,      FALSE },
  { "double-fetch",           CaseDoubleFetch,         FALSE },
  { "stale-interface",        CaseStaleInterface,      FALSE },
  { "boot-service-after-exit", CaseLateBootService,    FALSE },
  { "variable-size-trusted",  CaseVariableSizeTrusted, FALSE },
  { "use-after-free",         CaseUseAfterFree,        FALSE },
  { "double-free",            CaseDoubleFree,          TRUE  },
  { "size-overflow",          CaseSizeOverflow,        TRUE  },
};

STATIC
BOOLEAN
SameName (
  IN CONST CHAR8  *A,
  IN CONST CHAR8  *B
  )
{
  while ((*A != '\0') && (*A == *B)) {
    A++;
    B++;
  }

  return (BOOLEAN)((*A == '\0') && (*B == '\0'));
}

//
// The selector, over fw_cfg's own I/O ports rather than QemuFwCfgLib. The library's
// instances declare no UEFI_APPLICATION in their LIBRARY_CLASS, so linking it means
// either patching an upstream INF -- drift that conflicts on every rebase and changes
// what unrelated builds see -- or this, which is the whole classic interface: a selector
// word, a data byte, and a directory of named items in big endian.
//
#define FW_CFG_SELECTOR_PORT  0x510
#define FW_CFG_DATA_PORT      0x511
#define FW_CFG_SIGNATURE      0x0000
#define FW_CFG_FILE_DIR       0x0019

#pragma pack (1)
typedef struct {
  UINT32    Size;      // big endian
  UINT16    Select;    // big endian
  UINT16    Reserved;
  CHAR8     Name[56];
} FW_CFG_FILE;
#pragma pack ()

STATIC
VOID
FwCfgSelect (
  IN UINT16  Item
  )
{
  IoWrite16 (FW_CFG_SELECTOR_PORT, Item);
}

STATIC
VOID
FwCfgRead (
  OUT VOID   *Buffer,
  IN  UINTN  Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; Index++) {
    ((UINT8 *)Buffer)[Index] = IoRead8 (FW_CFG_DATA_PORT);
  }
}

STATIC
UINT32
Be32 (
  IN UINT32  Value
  )
{
  return SwapBytes32 (Value);
}

//
// Absent fw_cfg, an absent file or an empty value all mean "run everything", so the
// default costs a caller nothing and the file only ever narrows. The signature check is
// what keeps a stray port read from mattering on a machine that has no fw_cfg: reading
// an unclaimed port returns 0xFF and the compare fails.
//
STATIC
VOID
SelectedCase (
  OUT CHAR8  *Name,
  IN  UINTN  Size
  )
{
  FW_CFG_FILE  File;
  CHAR8        Signature[4];
  UINT32       Count;
  UINT32       Index;
  UINTN        Length;

  Name[0] = '\0';

  FwCfgSelect (FW_CFG_SIGNATURE);
  FwCfgRead (Signature, sizeof (Signature));
  if ((Signature[0] != 'Q') || (Signature[1] != 'E') ||
      (Signature[2] != 'M') || (Signature[3] != 'U'))
  {
    return;
  }

  FwCfgSelect (FW_CFG_FILE_DIR);
  FwCfgRead (&Count, sizeof (Count));
  Count = Be32 (Count);

  //
  // The directory is read in one pass: every entry has to be consumed in order because
  // the data port has no seek, so a match cannot stop the walk early.
  //
  for (Index = 0; Index < Count; Index++) {
    FwCfgRead (&File, sizeof (File));
    File.Name[sizeof (File.Name) - 1] = '\0';
    if (!SameName (File.Name, "opt/sanbench/case")) {
      continue;
    }

    Length = (UINTN)Be32 (File.Size);
    if ((Length == 0) || (Length >= Size)) {
      return;
    }

    //
    // Selecting the item is what rewinds the data port, so this has to wait until the
    // whole directory has been read -- selecting here and then continuing the walk
    // would read the file's bytes as directory entries.
    //
    FwCfgSelect (SwapBytes16 (File.Select));
    FwCfgRead (Name, Length);
    Name[Length] = '\0';

    //
    // QEMU counts the terminating NUL of a string= value in the size, and a caller may
    // have let a newline through. Trim both.
    //
    while ((Length > 0) && ((Name[Length - 1] == '\n') || (Name[Length - 1] == '\r') ||
                            (Name[Length - 1] == ' ') || (Name[Length - 1] == '\0')))
    {
      Name[--Length] = '\0';
    }

    return;
  }
}

EFI_STATUS
EFIAPI
SanBenchDriveEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  CHAR8       Want[64];
  UINTN       Index;
  BOOLEAN     Matched;

  Status = gBS->LocateProtocol (&gSanBenchMemoryProtocolGuid, NULL, (VOID **)&mMem);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SanBenchDrive: no memory protocol -- build with -D SAN_BENCH\n"));
    return Status;
  }

  Status = gBS->LocateProtocol (&gSanBenchFirmwareProtocolGuid, NULL, (VOID **)&mFw);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SelectedCase (Want, sizeof (Want));

  SerialOutput ("SanBenchDrive: start\n");
  //
  // Turn the region check on without opening the escalation window. The window is what
  // makes a finding end the iteration, and ending it is a LibAFL command -- an invalid
  // opcode under a plain QEMU, so opening it here kills the guest on the first report
  // and the remaining cases never run. This switch enables the check and leaves
  // escalation alone.
  //
  AsanSetRegionChecks (TRUE);

  Matched = FALSE;
  for (Index = 0; Index < ARRAY_SIZE (mCases); Index++) {
    if ((Want[0] != '\0') && !SameName (Want, mCases[Index].Name)) {
      continue;
    }

    Matched = TRUE;
    if (SameName (mCases[Index].Name, "control")) {
      SerialOutput ("SanBenchDrive: control, expect NO report\n");
    } else {
      SerialOutput ("SanBenchDrive: expect ");
      SerialOutput (mCases[Index].Name);
      SerialOutput ("\n");
    }

    mCases[Index].Run ();

    //
    // A destructive case in a whole-sequence run ends it. Continuing would measure the
    // wreckage and report it against whichever case came next.
    //
    if (mCases[Index].Destructive && (Want[0] == '\0') &&
        (Index + 1 < ARRAY_SIZE (mCases)))
    {
      SerialOutput ("SanBenchDrive: stopping -- the rest need one boot each\n");
      break;
    }
  }

  if (!Matched) {
    SerialOutput ("SanBenchDrive: no such case -- ");
    SerialOutput (Want);
    SerialOutput ("\n");
  }

  AsanSetRegionChecks (FALSE);
  SerialOutput ("SanBenchDrive: done\n");
  return EFI_SUCCESS;
}

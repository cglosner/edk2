/** @file
  Trigger shim for the qemu-fwfuzz harness.

  The standard syz-agent dispatch model is asynchronous: the dispatch
  timer callback polls the ivshmem doorbell and runs SyzEdk2Dispatch()
  on whatever program the host wrote there. That model works great for
  KVM + cold-restart fuzzing, but it's incompatible with
  contrib/plugins/libfwsnap.so, which snapshots at a fixed trigger PC,
  runs a "fuzz function" to an exit PC, and restores.

  This file provides a synchronous re-entry point that fwsnap can snap
  at. The host-side harness (fwfuzz.py) writes fuzz input directly
  into gSyzFwfuzzInputBuffer (a fixed-address region), then sends the
  RESTORE command. fwsnap restores CPU + guarded memory regions and
  unwinds back to SyzFwfuzzTrigger(), which dispatches the buffer as
  if it were a fresh doorbell poke.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SyzAgentDxe.h"
#include <Library/SyzCoverLib.h>

//
// The fuzz input buffer. Its physical address is discovered at init
// time via the standard EDK2 memory allocator, but from then on it is
// pinned for the life of the DXE phase. fwfuzz.py reads its address
// from the fwfuzz trigger registry config table (see below) or by
// parsing the SyzAgentDxe debug output line we print at startup.
//
// Size must be >= SYZ_EDK2_MAX_PROGRAM_BYTES so the host can write a
// full-sized program in one shot.
//
#define SYZ_FWFUZZ_INPUT_SIZE  (64 * 1024)

// Note: keep this statically allocated at known RVA so the host's
// memory map file can compute its runtime physical address.
__attribute__((aligned(4096)))
volatile UINT8  gSyzFwfuzzInputBuffer[SYZ_FWFUZZ_INPUT_SIZE];

//
// Registry table installed in the UEFI configuration table so fwfuzz
// harnesses can discover the trigger + input buffer physical addresses
// without parsing debug output.
//
// The GUID is deliberately random and specific to this shim.
// {b0c5f7a2-3d41-4e29-91a2-d5e8a4b3c9f1}
//
EFI_GUID  gSyzFwfuzzRegistryGuid = {
  0xb0c5f7a2, 0x3d41, 0x4e29,
  { 0x91, 0xa2, 0xd5, 0xe8, 0xa4, 0xb3, 0xc9, 0xf1 }
};

typedef struct {
  UINT32    Magic;                 ///< 'FWFZ'
  UINT32    Version;               ///< 3
  UINT64    InputBufferPhys;       ///< physical address of the input buffer
  UINT64    InputBufferSize;       ///< SYZ_FWFUZZ_INPUT_SIZE
  UINT64    TriggerPc;             ///< runtime PC of SyzFwfuzzTrigger entry
  UINT64    ExitPc;                ///< runtime PC of the exit nop (SyzFwfuzzExit)
  UINT64    AsanShadowBase;        ///< physical address of the ASan shadow region (0 if disabled)
  UINT64    AsanShadowSize;        ///< size of the ASan shadow region in bytes
} SYZ_FWFUZZ_REGISTRY;

STATIC SYZ_FWFUZZ_REGISTRY  gFwfuzzRegistry;

//
// Signature word so fwfuzz.py can scan the firmware binary for the
// trigger function even without a symbol map.
//
__attribute__((used))
STATIC volatile UINT64  gSyzFwfuzzSignature = 0x535A464D465A5357ULL; // "WSZFMFZS" (little-endian "SYZFMFZS")

//
// Declared in SyzAgentDxe.h so SyzAgentDxe.c can invoke this at init.
//
//
// Forward decl: separate noinline function whose entry serves as the
// fwsnap exit_trigger PC. QEMU TCG plugins receive callbacks at TB
// (translation-block) boundaries, not per-instruction, so the exit
// point MUST be a function entry (or other control-flow target) to
// reliably start a new TB that the plugin can pattern-match.
//
__attribute__((noinline, used))
VOID
EFIAPI
SyzFwfuzzExit (
  VOID
  );

VOID
EFIAPI
SyzFwfuzzRegister (
  VOID
  )
{
  EFI_STATUS  Status;

  // Seed the input buffer with a minimal valid NOP program so the
  // pre-snapshot SyzFwfuzzTrigger() call does something innocuous.
  {
    UINT32 *Header = (UINT32 *)(UINTN)gSyzFwfuzzInputBuffer;
    Header[0] = SYZ_EDK2_PROGRAM_MAGIC;
    Header[1] = 1;  // ncalls
    Header[2] = 1;  // call=NOP
    Header[3] = 16; // size
    *(UINT64 *)(UINTN)(gSyzFwfuzzInputBuffer + 16) = 0; // cookie
  }

  gFwfuzzRegistry.Magic           = 0x5A465746U; // 'FWFZ'
  gFwfuzzRegistry.Version         = 3;
  gFwfuzzRegistry.InputBufferPhys = (UINT64)(UINTN)gSyzFwfuzzInputBuffer;
  gFwfuzzRegistry.InputBufferSize = SYZ_FWFUZZ_INPUT_SIZE;
  gFwfuzzRegistry.TriggerPc       = (UINT64)(UINTN)&SyzFwfuzzTrigger;
  gFwfuzzRegistry.ExitPc          = (UINT64)(UINTN)&SyzFwfuzzExit;
  gFwfuzzRegistry.AsanShadowBase  = (UINT64)(UINTN)gSyzEdk2Agent.AsanShadowBase;
  gFwfuzzRegistry.AsanShadowSize  = (UINT64)gSyzEdk2Agent.AsanShadowSize;

  Status = gBS->InstallConfigurationTable (&gSyzFwfuzzRegistryGuid, &gFwfuzzRegistry);

  // Print the stable, easily-greppable marker line. We publish this
  // BEFORE calling SyzFwfuzzTrigger() so the host-side parser can
  // publish the ASan shadow region into the fwsnap control shmem
  // BEFORE the plugin's first snapshot fires. Otherwise the first
  // snapshot would miss the shadow and ASan state would drift
  // across iterations.
  DEBUG ((DEBUG_INFO | DEBUG_ERROR,
          "SYZFWFUZZ trigger=0x%lx exit=0x%lx input=0x%lx size=0x%x "
          "shadow=0x%lx shadow_size=0x%lx status=%r\n",
          gFwfuzzRegistry.TriggerPc,
          gFwfuzzRegistry.ExitPc,
          gFwfuzzRegistry.InputBufferPhys,
          SYZ_FWFUZZ_INPUT_SIZE,
          gFwfuzzRegistry.AsanShadowBase,
          gFwfuzzRegistry.AsanShadowSize,
          Status));

  // Give the host-side shadow publisher a window to see the marker
  // and write the correct shadow_base/shadow_size into the fwsnap
  // control shmem. The host polls the debug log every 500ms, so a
  // 2-second stall is plenty of slack. This only runs once at boot.
  //
  // Note: gBS->Stall wants microseconds.
  gBS->Stall (2 * 1000 * 1000);

  // Call the trigger once so that, with the fwsnap plugin attached,
  // the initial snapshot is taken here. Without the plugin this is
  // a harmless NOP-program dispatch.
  SyzFwfuzzTrigger ();
}

//
// Leaf function whose entry is the exit_trigger PC. Must be noinline
// so it actually has a call site (and therefore a TB entry) at its
// first instruction.
//
__attribute__((noinline, used))
VOID
EFIAPI
SyzFwfuzzExit (
  VOID
  )
{
  // Force a memory fence so the compiler can't eliminate the call.
  __asm__ volatile ("" ::: "memory");
}

//
// The actual trigger function. First call: fwsnap snapshots here. On
// every subsequent RESTORE command, fwsnap rewinds execution to the
// start of this function, but gSyzFwfuzzInputBuffer has been rewritten
// by the host with fresh fuzz data.
//
// Do NOT mark static/inline: we want a stable symbol name.
//
__attribute__((used))
VOID
EFIAPI
SyzFwfuzzTrigger (
  VOID
  )
{
  CONST UINT32  *Header;
  UINT32        Magic;
  UINT32        NumCalls;
  UINT8         *Payload;

  Header = (CONST UINT32 *)(UINTN)gSyzFwfuzzInputBuffer;
  Magic  = Header[0];
  if (Magic != SYZ_EDK2_PROGRAM_MAGIC) {
    SyzFwfuzzExit ();
    return;
  }
  NumCalls = Header[1];
  if ((NumCalls == 0) || (NumCalls > SYZ_EDK2_MAX_CALLS)) {
    SyzFwfuzzExit ();
    return;
  }

  Payload = (UINT8 *)(UINTN)gSyzFwfuzzInputBuffer + 8;

  SyzCoverReset ();  // enable gate
  SyzEdk2Dispatch (Payload, SYZ_FWFUZZ_INPUT_SIZE - 8, NumCalls);
  SyzCoverStop ();   // disable gate

  // Exit trigger: fwsnap pattern-matches pc == &SyzFwfuzzExit.
  SyzFwfuzzExit ();
}

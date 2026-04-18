# EDK2 AddressSanitizer (ASan) + UndefinedBehaviorSanitizer (UBSan)

This directory contains the KASAN-style runtime for EDK2 firmware. When
enabled it detects memory-safety bugs (buffer overflows, use-after-free,
uninitialized-region writes) in every instrumented DXE driver at runtime,
and emits one-line `==ERROR: AddressSanitizer:` reports to the OVMF
debugcon for the host fuzzer to parse.

## Quick start

Build OVMF with everything on:

```sh
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b NOOPT \
      -D SYZ_AGENT_ENABLE=TRUE \
      -D ASAN_ENABLE=TRUE \
      -D ASAN_INSTRUMENT=TRUE \
      -D UBSAN_INSTRUMENT=TRUE \
      -D FD_SIZE_IN_KB=8192
```

The four flags you need to know:

| Flag | Default | Effect |
|------|---------|--------|
| `SYZ_AGENT_ENABLE` | FALSE | Pull SyzAgentDxe + syzkaller transport into the image |
| `ASAN_ENABLE` | FALSE | Pull AsanLib into the library resolution chain |
| `ASAN_INSTRUMENT` | FALSE | Compile every DXE module with `-fsanitize=kernel-address` and inject the AsanLib runtime |
| `UBSAN_INSTRUMENT` | FALSE | Compile every DXE module with `-fsanitize=undefined -fsanitize=pointer-overflow` |

`FD_SIZE_IN_KB=8192` is required when instrumentation is on — the extra
code for ASan+UBSan redzones and runtime pushes the DXE FV past the
default 4 MB budget.

## Bug classes detected

| Class | Shadow byte | Trigger |
|-------|-------------|---------|
| heap-buffer-overflow | 0xFA | Write past end of `AllocatePool` buffer |
| heap-buffer-overflow | 0xFB | Write just before start of `AllocatePool` buffer |
| heap-use-after-free | 0xFD | Access to `AllocatePool` buffer after `FreePool` |
| stack-buffer-overflow | 0xF3 | Write past end of stack-local array |
| stack-buffer-underflow | 0xF1 | Write before start of stack-local array |
| global-buffer-overflow | 0xF9 | Write past end of module static/global array |
| UBSan: pointer-overflow | — | Pointer arithmetic past valid object range |
| UBSan: signed-integer-overflow | — | `INT_MAX + 1` and similar |
| UBSan: shift-out-of-bounds | — | Shift by ≥ bit-width |
| UBSan: array-bounds | — | Static-size array with out-of-range index |

## How it works

### Shadow memory

`PlatformPei` reserves 256 MB of DRAM at physical address `0x30000000`
via `BuildMemoryAllocationHob(EfiBootServicesData)` and zeroes it. The
region covers 2 GB of memory at ASan's 1:8 ratio: every byte at address
`A` is tracked by the shadow byte at `(A >> 3) + 0x30000000`.

A `gAsanInfoGuid` HOB is produced with `{start=0x30000000, size=256M}`.
Every instrumented module's `AsanLibFull` constructor reads this HOB
and activates its per-instance asan globals before the module's entry
point runs. See `OvmfPkg/PlatformPei/Platform.c::ReserveAsanShadow()`
and `Asan.c::SetupAsanShadowMemory()`.

### Outlined instrumentation only

Modules compile with `--param asan-instrumentation-with-call-threshold=0`
which forces GCC to emit out-of-line `__asan_loadN_noabort` / `__asan_storeN_noabort`
calls rather than inline shadow checks. The runtime functions live in
this directory and use the runtime-resolved shadow offset. This lets
the shadow region's physical address be chosen at boot time without
per-module recompilation.

### Module carveouts

A few modules cannot be instrumented:

- `SyzAgentDxe` — the agent itself (would trip ASan during its own
  dispatch loop, deadlock).
- `PciBusDxe` + `PciHostBridgeDxe` — PCI enumeration is O(devices ×
  MMIO-ops); ASan instrumentation adds a shadow lookup to every access,
  stalling TCG boot for minutes. Carved out in `OvmfPkgX64.dsc`.
- `SecMain` and all PEIMs — run before DRAM / the shadow region exist.
  See `AsanLib.inf` `LIBRARY_CLASS` list for the supported module-type
  scope.

### Recoverable reports

Every module is built with `-fsanitize-recover=address`, so an ASan
detection emits the report but does not halt execution. This lets the
fuzzer keep running past known bugs and surface new ones.

## Firmware-specific sanitizers

Three custom sanitizers live alongside the stock ASan runtime:

### MMIOConstraintSan (MMIOCS)
In `OvmfPkg/SyzAgentDxe/SyzAgentDispatch.c`. Every `cpu_io_mem_*`
syscall looks up the target address in the GCD memory-space descriptor
table and emits `==ERROR: MMIOCS: undeclared address …` if the address
is not inside any declared MMIO region. ASan can't cover this because
high-MMIO addresses fall outside the shadow window.

### ProtocolLifetimeSan (PLS)
Hooks `gBS->UninstallProtocolInterface` at `SyzAgentDxe` startup. On
a successful uninstall, poisons the first 128 bytes of the interface
struct with the heap-freed shadow byte (0xFD). Any future method call
through the now-stale pointer surfaces as `==ERROR: heap-use-after-free`.

### SmmBufValSan (SMIBVS)
In `MdeModulePkg/Library/SmmBufValLib/`. NULL-injected into every
`DXE_SMM_DRIVER`. Validates that pointers smuggled through the SMI
`CommBuffer` argument never alias SMRAM — the classic SMM privesc
pattern. Inert unless built with `SMM_REQUIRE=TRUE` and launched
with `-machine q35,smm=on`.

## Runtime report format

ASan emits a single line per bug to port 0x402 (debugcon):

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x3C7B1185 at pc 0x3CDCB81F shadow=0xfa
```

UBSan uses the same debugcon channel, prefixed `__ubsan_handle_<kind>`.

The syzkaller host-side report parser (`pkg/report/edk2.go`) walks
the fwsnap discovery log, matches the PC against loaded driver bases,
runs `addr2line` on the module's `.debug` file and appends:

```
  in DxeCore+0x2979a => CoreGetNextLocateByProtocol at .../Hand/Locate.c:399
```

## Known limitations

- **No PEI coverage** — PEI modules run before DRAM is up. A future
  `AsanLibFullPei.inf` with a PEIM-signature constructor would work
  with a bootstrap CAR-resident shadow.
- **No SMM coverage in default build** — requires `SMM_REQUIRE=TRUE`.
  SMIBVS infrastructure is already wired (see `MdeModulePkg/Library/SmmBufValLib`).
- **SEC never instrumented** — runs in Cache-as-RAM before any DRAM.

## Files

| File | Purpose |
|------|---------|
| `Asan.c` | Main runtime — `__asan_loadN_noabort`, `__asan_storeN_noabort`, shadow mapping, UBSan handlers |
| `AsanLib.inf` | Named library class `AsanLib`; consumed by modules that explicitly reference it |
| `AsanLibFull.inf` | `NULL`-injected library class, gets pulled into every instrumented module via DSC wildcard |
| `AsanLibFullStub.c` | Thin `#include "Asan.c"` — the stub instance injected into every DXE driver |
| `asan_mapping.h` | Shadow-offset macros |
| `SerialDebug.c` | Debugcon + COM output helpers |

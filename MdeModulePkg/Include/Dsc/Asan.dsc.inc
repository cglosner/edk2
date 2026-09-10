## @file
#  AddressSanitizer for an EDK2 platform, in one include.
#
#  USAGE
#    Set the two defines before including, anywhere above [LibraryClasses]:
#
#      DEFINE ASAN_SCOPE  = per-module      # off | per-module | full
#      DEFINE ASAN_FUZZER = tsffs           # tsffs | qemu | none
#      !include MdeModulePkg/Include/Dsc/Asan.dsc.inc
#
#    ASAN_SCOPE = per-module instruments nothing until a module opts in. Give the
#    module's entry in [Components]:
#
#      MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf {
#        <BuildOptions>
#          *_CLANGSAN_X64_SAN_FLAGS == $(ASAN_SAN_FLAGS)
#        <LibraryClasses>
#          AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
#          NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
#          BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf
#      }
#
#    ASAN_SCOPE = full instruments every DXE phase module. That is what finds an error
#    whose allocation and access are in different drivers, and it costs roughly three
#    times the image size -- budget the firmware volumes first. OVMF needs
#    -D FD_SIZE_IN_KB=8192 for it.
#
#  WHAT THE PLATFORM STILL HAS TO DO
#    Reserve the shadow region and publish gAsanInfoGuid from PEI. Without that HOB
#    AsanLib deactivates itself and every instrumented access is a no-op that looks
#    exactly like a clean run. See OvmfPkg/PlatformPei/MemDetect.c.
#
#  THREE RULES THAT ARE EASY TO GET WRONG
#    - The backend define goes in the global [BuildOptions]. edk2 builds a library
#      instance once with the global flags, and AsanLib is a library, so a
#      <BuildOptions> block on a module never reaches it.
#    - SAN_FLAGS is replaced with "==", never appended to. build_rule puts $(SAN_FLAGS)
#      after $(CC_FLAGS), so -fno-sanitize in CC_FLAGS has no effect.
#    - PEI gets the Null instance only. It is a BASE library with no constructor, which
#      is what lets it link into a PEIM; the real AsanLib is a DXE library whose NULL|
#      constructor takes an ImageHandle a PEIM does not have.
#
#  Copyright (c) 2026, Firness contributors. All rights reserved.<BR>
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
!ifndef ASAN_SCOPE
  DEFINE ASAN_SCOPE = per-module
!endif
!ifndef ASAN_FUZZER
  DEFINE ASAN_FUZZER = tsffs
!endif
  #
  # Named so an opt-in site can restate it. Every such site must repeat the flags
  # verbatim, because "==" replaces: an entry listing a subset silently turns the rest off.
  #
  DEFINE ASAN_SAN_FLAGS = -fsanitize=address -fno-sanitize-address-use-after-scope -mllvm -asan-stack-dynamic-alloca=0 -mllvm -asan-instrumentation-with-call-threshold=0 -mllvm -asan-force-dynamic-shadow=true -fsanitize=undefined -fno-sanitize=alignment -Wno-frame-address

[LibraryClasses]
  #
  # Resolvable in every phase, including PEI. Modules that are actually instrumented
  # override this with the real instance below.
  #
  AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf

!if "$(ASAN_SCOPE)" == "full"
[LibraryClasses.common.SEC]
  #
  # SecMain is not instrumented, but the PEI typed libraries it links are --
  # a library is built once with the global flags and BuildOptions cannot be
  # scoped to one -- so it still needs the symbols.
  #
  NULL|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf

[LibraryClasses.common.PEI_CORE]
  #
  # PEI is instrumented at full scope whether or not it is useful -- the global
  # SAN_FLAGS reaches the PEI typed library instances too, and BuildOptions cannot
  # be scoped to a library. It therefore needs a runtime, and only the Null one can
  # link here. It reports nothing, which is right: PEI runs before the shadow exists.
  #
  NULL|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf

[LibraryClasses.common.PEIM]
  NULL|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf

[LibraryClasses.common.DXE_CORE]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf

[LibraryClasses.common.DXE_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf

[LibraryClasses.common.UEFI_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf

[LibraryClasses.common.UEFI_APPLICATION]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf
!endif

[BuildOptions]
  #
  # Which fuzzer AsanLib reports a finding to. Emitting the wrong one is not an error:
  # the TSFFS handshake is a cpuid, legal and ignored where nothing is watching, so the
  # firmware logs memory errors and the fuzzer records nothing.
  #
!ifdef FIRNESS_QEMU_CRASH
!if "$(FIRNESS_QEMU_CRASH)" == "TRUE"
  #
  # A guest fault ends the iteration instead of dead looping until the timeout.
  # See UefiCpuPkg/Library/CpuExceptionHandlerLib/PeiDxeSmmCpuException.c.
  #
  GCC:*_*_*_CC_FLAGS = -D FIRNESS_LIBAFL_CRASH_ON_EXCEPTION
!endif
!endif
!if "$(ASAN_FUZZER)" == "qemu"
  GCC:*_*_*_CC_FLAGS = -D ASAN_FUZZER_BACKEND=2
!elseif "$(ASAN_FUZZER)" == "none"
  GCC:*_*_*_CC_FLAGS = -D ASAN_FUZZER_BACKEND=4
!else
  GCC:*_*_*_CC_FLAGS = -D ASAN_FUZZER_BACKEND=1
!endif

!if "$(ASAN_SCOPE)" == "full"
  #
  # Heap only, platform wide -- and that is not a compromise. A cross-module error
  # is a heap error by construction: one driver allocates, another overruns. A stack
  # frame never outlives the function that owns it, so it has no cross-module case.
  #
  # Stack instrumentation must not be global. The compiler writes frame redzones
  # inline and unconditionally, which bypasses AsanLib's range guard -- that guard
  # only covers the checks. A module whose stack sits outside the mapped shadow then
  # corrupts whatever MEM_TO_SHADOW lands on. The symptom is a clobbered return
  # address, a non-canonical RIP, and zero ASan reports, so it looks nothing like a
  # sanitizer problem. Per-module opt-in sites restate the full set and keep it.
  #
  # Restating the flags here also pins them. Falling through to the tools_def default
  # silently picks up a different set, including -fsanitize=local-bounds.
  #
  *_CLANGSAN_X64_SAN_FLAGS == $(ASAN_SAN_FLAGS) -mllvm -asan-stack=0
!else
  #
  # Off by default; the opt-in blocks in [Components] turn it back on.
  #
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address
!endif

[BuildOptions.common.EDKII.SEC]
  #
  # Never instrument SEC. OvmfPkg/ResetVector is a SEC module built only from
  # nasm, so it has nothing to link a runtime into: GenFw then fails with
  # "Did not find any '.text' section".
  #
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address

[BuildOptions.common.EDKII.SMM_CORE]
  #
  # SMM keeps its own shadow and its own runtime (AsanRuntimeLib). Wiring that is a
  # separate job, and an instrumented SMM driver without it does not link.
  #
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address

[BuildOptions.common.EDKII.DXE_SMM_DRIVER]
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address

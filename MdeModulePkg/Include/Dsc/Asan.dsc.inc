## @file
#  AddressSanitizer for an EDK2 platform, in one include.
#
#  USAGE
#    Set the two defines, then include this before [LibraryClasses]:
#
#      DEFINE ASAN_SCOPE  = per-module      # off | per-module | full
#      DEFINE ASAN_FUZZER = tsffs           # tsffs | qemu | none
#      !include MdeModulePkg/Include/Dsc/Asan.dsc.inc
#
#    With ASAN_SCOPE = per-module (the default, and what a flash-constrained platform
#    wants) nothing is instrumented until a module opts in. Give the module's entry in
#    [Components]:
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
#    With ASAN_SCOPE = full every module is instrumented. That finds errors whose
#    allocation and access are in different drivers, and costs roughly three times the
#    image size -- budget the firmware volumes before choosing it.
#
#  WHAT THE PLATFORM STILL HAS TO DO
#    Reserve the shadow region and publish gAsanInfoGuid from PEI. Without that HOB
#    AsanLib deactivates itself and every instrumented access is a no-op that looks
#    exactly like a clean run. See OvmfPkg/PlatformPei/MemDetect.c or
#    SimicsOpenBoardPkg/SimicsPei/MemDetect.c: one eighth of the memory below 4GB,
#    zeroed, based somewhere the platform has not already claimed.
#
#  WHY THE DEFINES ARE WHERE THEY ARE
#    ASAN_FUZZER_BACKEND is set in the global [BuildOptions] and not per module: edk2
#    builds a library instance once with the global flags, and AsanLib is a library, so a
#    <BuildOptions> block on a module never reaches it.
#
#    SAN_FLAGS is replaced with "==" rather than appended to. build_rule puts
#    $(SAN_FLAGS) after $(CC_FLAGS), so -fno-sanitize in CC_FLAGS is overridden and has
#    no effect.
#
#  Copyright (c) 2026, Firness contributors. All rights reserved.<BR>
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

!ifndef ASAN_SCOPE
  DEFINE ASAN_SCOPE = per-module
!endif

!ifndef ASAN_FUZZER
  DEFINE ASAN_FUZZER = tsffs
!endif

#
# The toolchain's own sanitizer flags, named so a module can restate them. Kept in one
# place because every opt-in site has to repeat them verbatim -- "==" replaces, so an
# entry that lists a subset silently turns the rest off.
#
DEFINE ASAN_SAN_FLAGS = -fsanitize=address -fno-sanitize-address-use-after-scope -mllvm -asan-stack-dynamic-alloca=0 -mllvm -asan-instrumentation-with-call-threshold=0 -mllvm -asan-force-dynamic-shadow=true -fsanitize=undefined -fno-sanitize=alignment -Wno-frame-address

!if $(ASAN_FUZZER) == "qemu"
  DEFINE ASAN_BACKEND_ID = 2
!elseif $(ASAN_FUZZER) == "none"
  DEFINE ASAN_BACKEND_ID = 4
!else
  DEFINE ASAN_BACKEND_ID = 1
!endif

[LibraryClasses]
  #
  # Resolvable in every phase. The Null instance is a BASE library with no constructor,
  # which is what lets it link into PEI; the real AsanLib is a DXE library whose NULL|
  # constructor takes an ImageHandle a PEIM does not have. Modules that are actually
  # instrumented override this with the real one.
  #
  AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf

!if $(ASAN_SCOPE) == "full"
[LibraryClasses.common.DXE_CORE, LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.DXE_RUNTIME_DRIVER, LibraryClasses.common.UEFI_DRIVER, LibraryClasses.common.UEFI_APPLICATION]
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
  GCC:*_*_*_CC_FLAGS = -D ASAN_FUZZER_BACKEND=$(ASAN_BACKEND_ID)

!if $(ASAN_SCOPE) == "per-module"
  #
  # Off by default; the opt-in blocks in [Components] turn it back on.
  #
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address
!endif

!if $(ASAN_SCOPE) == "off"
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address
!endif

!if $(ASAN_SCOPE) != "full"
[BuildOptions.common.EDKII.DXE_SMM_DRIVER, BuildOptions.common.EDKII.SMM_CORE]
  #
  # SMM keeps its own shadow and its own runtime (AsanRuntimeLib). Wiring that is a
  # separate job, and an instrumented SMM driver without it does not link.
  #
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address
!endif

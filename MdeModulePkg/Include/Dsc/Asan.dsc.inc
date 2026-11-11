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
#        #      }
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
!ifndef ASAN_SMM
  #
  # Instrument SMM_CORE and DXE_SMM_DRIVER. On by default: an SMI handler's own code is
  # where the SMM attack surface is, and leaving it off is what made 0 of 17 SMM modules
  # checked while the stage still called 288 of 290 images "instrumented".
  #
  # Set FALSE to go back to the old behaviour. Worth having as a knob rather than an edit,
  # because the regions inside SMRAM that nothing maintains -- SMM page allocations and
  # SMM stacks, neither of which has a poisoning hook -- can produce reports that are
  # about the shadow rather than about the firmware.
  #
  DEFINE ASAN_SMM = TRUE
!endif
  #
  # Named so an opt-in site can restate it. Every such site must repeat the flags
  # verbatim, because "==" replaces: an entry listing a subset silently turns the rest off.
  #
  DEFINE ASAN_SAN_FLAGS = -fsanitize=address -fno-sanitize-address-use-after-scope -mllvm -asan-stack-dynamic-alloca=0 -mllvm -asan-instrumentation-with-call-threshold=0 -mllvm -asan-force-dynamic-shadow=true -fsanitize=undefined -fno-sanitize=alignment -Wno-frame-address

!if "$(ASAN_SCOPE)" != "off"
#
# Check every CopyMem, SetMem and ZeroMem in the image, at any scope.
#
# This is the difference between finding a firmware bug and not. AsanMemoryLibRepStr
# range checks explicitly -- it needs no compiler instrumentation and no AsanLib, only
# DebugLib and BaseLib -- so a driver that is not itself instrumented still has its
# memory operations checked. Every out of bounds copy found so far came through here:
# DevicePathDxe, SnpDxe and DxeCore are none of them in an opt-in list.
#
# Resolving it only inside the per-module opt-in blocks, as this did, left OVMF
# checking 3 modules of 312 while the Simics board checked every one of them, which
# is most of why the two backends did not find the same bugs.
#
[LibraryClasses.common.DXE_CORE, LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.DXE_RUNTIME_DRIVER, LibraryClasses.common.UEFI_DRIVER, LibraryClasses.common.UEFI_APPLICATION]
  BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf
!endif

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

[LibraryClasses.common.DXE_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf

[LibraryClasses.common.UEFI_DRIVER]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf

[LibraryClasses.common.UEFI_APPLICATION]
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLib.inf
  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf
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
  #
  # Opt in to double-fetch findings becoming fuzzer solutions. Off by default: a
  # comm-buffer field read twice is what a validating handler does, so this fires on
  # nearly every well-formed SMI call, and an objective is not added to the corpus --
  # which left the EVAL-1 SMI campaign at corpus 0 for its whole budget. The report
  # still reaches serial either way; this only decides whether the input is saved.
  #
!ifdef FWSAN_DOUBLE_FETCH_SOLUTION
!if "$(FWSAN_DOUBLE_FETCH_SOLUTION)" == "TRUE"
  GCC:*_*_*_CC_FLAGS = -D FWSAN_DOUBLE_FETCH_SOLUTION
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

#
# SMM. The comment that used to sit here said SMM "keeps its own shadow and its own
# runtime (AsanRuntimeLib)" and that an instrumented SMM driver "does not link". Both
# statements were true when they were written and neither is true now:
#
#   * The shadow is ONE region and it already covers SMRAM. MemDetect.c sizes it as
#     LowMemory >> 3 and reserves [0, LowMemory); PlatformInitLib carves TSEG out of the
#     TOP of LowMemory, so TSEG is inside the reservation by construction, at any RAM
#     size. Checked against two real configurations: with LowMemory 0x20000000 the shadow
#     is [0x5000000, 0x8FFFFFF] and SMRAM 0x1C009000-0x1FFFFFFF maps to
#     0x8801200-0x8FFFFFF; with LowMemory 0x80000000 the shadow is
#     [0x5000000, 0x14FFFFFF] and SMRAM 0x7F009000-0x7FFFFFFF maps to
#     0x14E01200-0x14FFFFFF. Both land inside, ending on the reservation's last byte.
#   * SMM can reach it. PcdCpuSmmRestrictedMemoryAccess defaults FALSE, and even set TRUE
#     the permitted types are reserved, runtime and ACPI NVS -- MemDetect.c reserves the
#     shadow as EfiRuntimeServicesData, one of exactly those.
#   * The runtime links. OvmfPkgX64.dsc resolves AsanLib and NULL|AsanLib for both module
#     types, so __asan_init and the __asan_load/store family resolve.
#
# The check path guards on MEM_TO_SHADOW(addr) rather than on addr, so an access whose
# shadow byte is outside the region is skipped instead of reading unmapped memory.
#
# -asan-stack=0 is NOT optional here and is the reason these blocks restate the flags
# rather than falling through. Clang writes stack frame redzones INLINE and
# unconditionally, which bypasses that guard entirely; an SMM stack lives in TSEG, so
# without this the frame poisoning writes shadow for addresses nothing else maintains.
#
# What is still missing, so a report is read correctly: PiSmmCore/Page.c has no poisoning
# hooks, so SMM page allocations read as addressable, and SMM stacks are untracked. Pool
# allocations ARE tracked -- PiSmmCore/Pool.c poisons the left redzone and everything from
# the caller's buffer to POOL_TAIL -- so SMM heap overflow is real detection. A finding
# inside SMRAM from any other region should be treated as a shadow question first.
#
!if "$(ASAN_SMM)" == "TRUE"
[BuildOptions.common.EDKII.SMM_CORE]
  *_CLANGSAN_X64_SAN_FLAGS == $(ASAN_SAN_FLAGS) -mllvm -asan-stack=0

[BuildOptions.common.EDKII.DXE_SMM_DRIVER]
  *_CLANGSAN_X64_SAN_FLAGS == $(ASAN_SAN_FLAGS) -mllvm -asan-stack=0
!else
[BuildOptions.common.EDKII.SMM_CORE]
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address

[BuildOptions.common.EDKII.DXE_SMM_DRIVER]
  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address
!endif

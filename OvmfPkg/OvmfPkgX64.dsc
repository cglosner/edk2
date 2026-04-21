## @file
#  EFI/Framework Open Virtual Machine Firmware (OVMF) platform
#
#  Copyright (c) 2006 - 2022, Intel Corporation. All rights reserved.<BR>
#  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
#  Copyright (c) Microsoft Corporation.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
[Defines]
  PLATFORM_NAME                  = Ovmf
  PLATFORM_GUID                  = 5a9e7754-d81b-49ea-85ad-69eaa7b1539b
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/OvmfX64
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = NOOPT|DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = OvmfPkg/OvmfPkgX64.fdf

  #
  # Defines for default states.  These can be changed on the command line.
  # -D FLAG=VALUE
  #
  DEFINE SECURE_BOOT_ENABLE      = FALSE
  DEFINE SMM_REQUIRE             = FALSE
  DEFINE SOURCE_DEBUG_ENABLE     = FALSE
  DEFINE CC_MEASUREMENT_ENABLE   = FALSE

  #
  # syzkaller fuzzing build flags. SYZ_AGENT_ENABLE pulls in the
  # SyzAgentDxe driver and the SyzCoverLib NULL library injection;
  # ASAN_ENABLE pulls in MdeModulePkg's AddressSanitizer port. Both
  # default to FALSE so production builds are unaffected. See
  # docs/edk2_design.md on the syzkaller side.
  #
  DEFINE SYZ_AGENT_ENABLE        = FALSE
  DEFINE ASAN_ENABLE             = FALSE
  DEFINE ASAN_INSTRUMENT         = FALSE
  DEFINE UBSAN_INSTRUMENT        = FALSE
  #
  # SYZ_BUGS_DISPATCH_INJECT: when TRUE, the dispatcher handlers plant
  # one deterministic canary per category (see docs/edk2/bug-injection-catalog.md).
  # Each canary is keyed on a magic value in the payload, so the fuzzer
  # must actually reach that handler with that magic to trip it. Used
  # to validate the full grammar -> syscall -> sanitizer pipeline.
  #
  DEFINE SYZ_BUGS_DISPATCH_INJECT = FALSE
  #
  # MMIOCS_ENFORCE: when TRUE, MMIOCS rejects accesses to undeclared /
  # non-MMIO addresses at the dispatcher layer — the CPU-level access
  # is skipped. Turn on to prevent fuzzer-cascade #GP/#PF noise from
  # invalid MMIO addresses. Production runs should set this TRUE; the
  # FALSE default preserves legacy log-only behaviour.
  #
  DEFINE MMIOCS_ENFORCE           = FALSE

!include OvmfPkg/Include/Dsc/OvmfTpmDefines.dsc.inc

  #
  # Shell can be useful for debugging but should not be enabled for production
  #
  DEFINE BUILD_SHELL             = TRUE

  #
  # Network definition
  #
  DEFINE NETWORK_TLS_ENABLE             = FALSE
  DEFINE NETWORK_IP6_ENABLE             = FALSE
  DEFINE NETWORK_HTTP_BOOT_ENABLE       = FALSE
  DEFINE NETWORK_ALLOW_HTTP_CONNECTIONS = TRUE
  DEFINE NETWORK_ISCSI_ENABLE           = TRUE

!include NetworkPkg/NetworkDefines.dsc.inc

  #
  # Device drivers
  #
  DEFINE PVSCSI_ENABLE           = FALSE
  DEFINE MPT_SCSI_ENABLE         = FALSE
  DEFINE LSI_SCSI_ENABLE         = FALSE

  #
  # Flash size selection. Setting FD_SIZE_IN_KB on the command line directly to
  # one of the supported values, in place of any of the convenience macros, is
  # permitted.
  #
!ifdef $(FD_SIZE_1MB)
  DEFINE FD_SIZE_IN_KB           = 1024
!else
!ifdef $(FD_SIZE_2MB)
  DEFINE FD_SIZE_IN_KB           = 2048
!else
!ifdef $(FD_SIZE_4MB)
  DEFINE FD_SIZE_IN_KB           = 4096
!else
  DEFINE FD_SIZE_IN_KB           = 4096
!endif
!endif
!endif

  #
  # Define the FILE_GUID of CpuMpPei/CpuDxe for unique-processor version.
  #
  DEFINE UP_CPU_PEI_GUID  = 280251c4-1d09-4035-9062-839acb5f18c1
  DEFINE UP_CPU_DXE_GUID  = 6490f1c5-ebcc-4665-8892-0075b9bb49b7

[BuildOptions]
  GCC:RELEASE_*_*_CC_FLAGS             = -DMDEPKG_NDEBUG
  INTEL:RELEASE_*_*_CC_FLAGS           = /D MDEPKG_NDEBUG
  MSFT:RELEASE_*_*_CC_FLAGS            = /D MDEPKG_NDEBUG

!if $(SYZ_AGENT_ENABLE) == TRUE
  #
  # Enable gcc -fsanitize-coverage=trace-pc on every DXE-and-later
  # module (where DRAM and the SyzCoverLib runtime are available).
  # SEC/PEI modules run before DRAM init / before the
  # SyzCoverLibNull NULL injection has any effect, so we leave them
  # uninstrumented. The SyzCoverLib runtime itself overrides this
  # via its own BuildOptions to avoid recursion.
  #
  GCC:*_*_*_CC_FLAGS                   = -DSYZ_AGENT_ENABLE=1

!if $(SYZ_BUGS_DISPATCH_INJECT) == TRUE
  GCC:*_*_*_CC_FLAGS                   = -DSYZ_BUGS_DISPATCH_INJECT=1
!endif

!if $(MMIOCS_ENFORCE) == TRUE
  GCC:*_*_*_CC_FLAGS                   = -DMMIOCS_ENFORCE=1
!endif

#
# Coverage-only by default for every DXE/SMM module — sanitizer-
# coverage trace-pc has zero runtime side effects beyond writing PCs
# into the SyzAgent cover ring, so it's safe everywhere.
#
# ASan and UBSan are NOT applied per MODULE_TYPE here. They are
# enabled per-component on a deny-list basis: every module is
# uninstrumented by default and we OPT IN specific MdeModulePkg
# drivers further down via the [Components] section's per-INF
# <BuildOptions> override. This avoids dragging asan into the
# OvmfPkg early-boot drivers (QemuFwCfgLib's DMA path, IoMmuDxe's
# bounce-buffer encryption, the SEV/TDX libs) where activating asan
# wedges the boot dispatcher before SyzAgent's timer fires.
#
#
# IMPORTANT: do NOT add -fsanitize=kernel-address blanket-fashion to
# these per-MODULE_TYPE blocks. Under TCG each instrumented memory
# access becomes a helper call into AsanLibFull, and applying ASan
# to every DXE driver makes BdsConnectAll take hours to complete
# (the PCI enumeration + driver binding walk is O(handles * accesses)
# and each access now triggers a shadow read). This is incompatible
# with the fwsnap snapshot-fuzzing path, which needs to reach
# SyzAgentDxe's init in reasonable time.
#
# ASan/UBSan are therefore applied PER COMPONENT via <BuildOptions>
# overrides in the [Components] section further down. Only the
# modules actually being fuzzed get the instrumentation. The
# SyzAgentDxe dispatch host itself stays uninstrumented.
#
# Phase 1 of "instrument everything": the ASan and UBSan flags below
# are now applied at the MODULE_TYPE wildcard level, not per-component.
# Every DXE_DRIVER / UEFI_DRIVER / DXE_RUNTIME_DRIVER / DXE_SMM_DRIVER
# built under ASAN_INSTRUMENT=TRUE picks them up automatically. Modules
# that must stay un-instrumented (SyzAgentDxe, SyzCoverLib, the
# protocol-notify-sensitive early drivers) use a per-component
# <BuildOptions> override with -fno-sanitize=kernel-address /
# -fno-sanitize=undefined to opt out — the gcc-wrap wrapper strips
# -fasan-shadow-offset automatically when it sees -fno-sanitize=
# kernel-address, so the opt-out pattern is just "append -fno-*".
#
# Outlined instrumentation (--param asan-instrumentation-with-call-
# threshold=0) is mandatory: inlined mode bakes the compile-time
# shadow offset into every memory access callsite, which #PFs the
# moment the module is loaded at a relocation that doesn't match.
# Outlined mode puts the shadow lookup inside __asan_load1_noabort
# where the runtime sees mShadowOffset / mAsanShadowMemoryStart.
#
# asan-stack=0 / asan-globals=0: these instrumentation passes write
# stack red-zones in every function prologue and poison global red-
# zones at __asan_register_globals time. Both need the shadow to
# already cover those addresses. Phase 1 keeps the shadow in the
# ivshmem BAR at 0xC000200000, which covers only the DRAM range that
# falls in (addr>>3)+0xC000200000 — the stack and global-data
# addresses mostly fall inside that, but the early boot stack does
# not. Phase 2 moves the shadow to reserved DRAM and re-enables both.
#
[BuildOptions.common.EDKII.DXE_DRIVER]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions.common.EDKII.DXE_RUNTIME_DRIVER]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions.common.EDKII.UEFI_DRIVER]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions.common.EDKII.UEFI_APPLICATION]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  # Covers UiApp (BDS menu) and Shell — same wildcard pattern as DXE
  # drivers. Boot applications run AFTER all DXE drivers dispatch so
  # the DRAM shadow is already initialized.
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions.common.EDKII.DXE_SMM_DRIVER]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  #
  # Phase 4: SMM ASan. The shadow now lives in normal DRAM at
  # 0x30000000 (Phase 2), which SMM mode can read/write since
  # SMI handlers run with full physical-memory access. The only
  # constraint is that SMRAM must not overlap the shadow range —
  # Q35 TSEG defaults to the top of low RAM, so for 1 GB DRAM
  # SMRAM at [0x3F800000, 0x40000000) is clear of the shadow at
  # [0x30000000, 0x3F800000 overlap!]. To avoid the collision
  # we shrink TSEG or move the shadow in later iterations.
  # Phase 4 with SMM_REQUIRE=FALSE builds no SMM drivers, so this
  # block only takes effect once SMM is enabled in a follow-up
  # build config.
  #
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions.common.EDKII.SMM_CORE]
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

#
# Phase 6 (PEI/SEC instrumentation) infrastructure note:
#
# PEIM and PEI_CORE instrumentation requires an AsanLibFullPei.inf
# with a PEI-compatible CONSTRUCTOR signature:
#   RETURN_STATUS AsanLibPeiConstructor(EFI_PEI_FILE_HANDLE, EFI_PEI_SERVICES **)
# that reads the gAsanInfoGuid HOB produced by PlatformPei. Currently
# SyzCoverLibNull depends on UefiBootServicesTableLib which is
# DXE-only, so it can't be NULL-injected into PEIMs either.
#
# Until both of these are addressed, PEI modules stay uninstrumented.
# SEC runs in CAR before DRAM exists — instrumentation requires a
# bootstrap shadow, high effort / low value. SEC stays off.
#

[BuildOptions.common.EDKII.DXE_CORE]
  # DXE_CORE processes MILLIONS of comparisons during boot (memory
  # allocator, image loader, driver dispatcher, ...). Enabling
  # trace-cmp here makes boot hang under TCG — every cmp becomes a
  # callback into SyzCoverLibNull, which even with early-return
  # adds 100x overhead. Trace-pc only for DxeCore; trace-cmp is
  # enabled only for DXE_DRIVER/DXE_RUNTIME_DRIVER/UEFI_DRIVER.
  GCC:*_*_*_CC_FLAGS = -fsanitize-coverage=trace-pc
!if $(UBSAN_INSTRUMENT) == TRUE
  GCC:*_*_*_CC_FLAGS = -fsanitize=undefined -fsanitize=pointer-overflow -fno-sanitize=alignment -fsanitize-recover=undefined -fsanitize-recover=pointer-overflow
!endif
!if $(ASAN_INSTRUMENT) == TRUE
  #
  # Phase 3: DxeCore ASan. Enabled now that:
  #   - PlatformPei produces the gAsanInfoGuid HOB (Phase 2), so
  #     DxeMain's own AsanLibFull CONSTRUCTOR finds the shadow at
  #     module load time and activates its per-instance globals.
  #   - PoisonPool / UnpoisonPool / FastPoisonShadow live in
  #     AsanLibFull which is built with -fno-sanitize=all, so the
  #     allocator's poison writes don't recursively self-instrument.
  #   - The shadow range [0x30000000, 0x40000000) is reserved via
  #     BuildMemoryAllocationHob, so CoreAllocatePool won't hand
  #     that range out and trip on its own poison bytes.
  #
  GCC:*_*_*_CC_FLAGS = -fsanitize=kernel-address -fasan-shadow-offset=0x30000000 --param asan-stack=1 --param asan-globals=1 --param asan-instrumentation-with-call-threshold=0 -fsanitize-recover=address -fno-omit-frame-pointer
!endif

[BuildOptions]
!endif
!if $(TOOL_CHAIN_TAG) != "XCODE5" && $(TOOL_CHAIN_TAG) != "CLANGPDB"
  GCC:*_*_*_CC_FLAGS                   = -mno-mmx -mno-sse
!endif
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  MSFT:*_*_X64_GENFW_FLAGS  = --keepexceptiontable
  GCC:*_*_X64_GENFW_FLAGS   = --keepexceptiontable
  INTEL:*_*_X64_GENFW_FLAGS = --keepexceptiontable
!endif
  RELEASE_*_*_GENFW_FLAGS = --zero

  #
  # Disable deprecated APIs.
  #
  MSFT:*_*_*_CC_FLAGS = /D DISABLE_NEW_DEPRECATED_INTERFACES
  INTEL:*_*_*_CC_FLAGS = /D DISABLE_NEW_DEPRECATED_INTERFACES
  GCC:*_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES

  #
  # Add TDX_GUEST_SUPPORTED
  #
  MSFT:*_*_*_CC_FLAGS = /D TDX_GUEST_SUPPORTED
  INTEL:*_*_*_CC_FLAGS = /D TDX_GUEST_SUPPORTED
  GCC:*_*_*_CC_FLAGS = -D TDX_GUEST_SUPPORTED

  #
  # SECURE_BOOT_FEATURE_ENABLED
  #
!if $(SECURE_BOOT_ENABLE) == TRUE
  MSFT:*_*_*_CC_FLAGS = /D SECURE_BOOT_FEATURE_ENABLED
  INTEL:*_*_*_CC_FLAGS = /D SECURE_BOOT_FEATURE_ENABLED
  GCC:*_*_*_CC_FLAGS = -D SECURE_BOOT_FEATURE_ENABLED
!endif

!include NetworkPkg/NetworkBuildOptions.dsc.inc

[BuildOptions.common.EDKII.DXE_RUNTIME_DRIVER]
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000
  XCODE:*_*_*_DLINK_FLAGS = -seg1addr 0x1000 -segalign 0x1000
  XCODE:*_*_*_MTOC_FLAGS = -align 0x1000
  CLANGPDB:*_*_*_DLINK_FLAGS = /ALIGN:4096

# Force PE/COFF sections to be aligned at 4KB boundaries to support page level
# protection of DXE_SMM_DRIVER/SMM_CORE modules
[BuildOptions.common.EDKII.DXE_SMM_DRIVER, BuildOptions.common.EDKII.SMM_CORE]
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000
  XCODE:*_*_*_DLINK_FLAGS = -seg1addr 0x1000 -segalign 0x1000
  XCODE:*_*_*_MTOC_FLAGS = -align 0x1000
  CLANGPDB:*_*_*_DLINK_FLAGS = /ALIGN:4096

################################################################################
#
# SKU Identification section - list of all SKU IDs supported by this Platform.
#
################################################################################
[SkuIds]
  0|DEFAULT

################################################################################
#
# Library Class section - list of all Library Classes needed by this Platform.
#
################################################################################

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/BaseAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/BaseResetSystemLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  TimeBaseLib|EmbeddedPkg/Library/TimeBaseLib/TimeBaseLib.inf
  BmpSupportLib|MdeModulePkg/Library/BaseBmpSupportLib/BaseBmpSupportLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  CacheMaintenanceLib|MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
  UefiDecompressLib|MdePkg/Library/BaseUefiDecompressLib/BaseUefiDecompressLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf
  BootLogoLib|MdeModulePkg/Library/BootLogoLib/BootLogoLib.inf
  FileExplorerLib|MdeModulePkg/Library/FileExplorerLib/FileExplorerLib.inf
  CapsuleLib|MdeModulePkg/Library/DxeCapsuleLibNull/DxeCapsuleLibNull.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
  PciExpressLib|MdePkg/Library/BasePciExpressLib/BasePciExpressLib.inf
  PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  PciSegmentLib|MdePkg/Library/BasePciSegmentLibPci/BasePciSegmentLibPci.inf
  PciCapLib|OvmfPkg/Library/BasePciCapLib/BasePciCapLib.inf
  PciCapPciSegmentLib|OvmfPkg/Library/BasePciCapPciSegmentLib/BasePciCapPciSegmentLib.inf
  PciCapPciIoLib|OvmfPkg/Library/UefiPciCapPciIoLib/UefiPciCapPciIoLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsicSev.inf
  OemHookStatusCodeLib|MdeModulePkg/Library/OemHookStatusCodeLibNull/OemHookStatusCodeLibNull.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
  MtrrLib|UefiCpuPkg/Library/MtrrLib/MtrrLib.inf
  MicrocodeLib|UefiCpuPkg/Library/MicrocodeLib/MicrocodeLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
  NvVarsFileLib|OvmfPkg/Library/NvVarsFileLib/NvVarsFileLib.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  UefiCpuLib|UefiCpuPkg/Library/BaseUefiCpuLib/BaseUefiCpuLib.inf
  SecurityManagementLib|MdeModulePkg/Library/DxeSecurityManagementLib/DxeSecurityManagementLib.inf
  UefiUsbLib|MdePkg/Library/UefiUsbLib/UefiUsbLib.inf
  SerializeVariablesLib|OvmfPkg/Library/SerializeVariablesLib/SerializeVariablesLib.inf
  QemuFwCfgLib|OvmfPkg/Library/QemuFwCfgLib/QemuFwCfgDxeLib.inf
  QemuFwCfgSimpleParserLib|OvmfPkg/Library/QemuFwCfgSimpleParserLib/QemuFwCfgSimpleParserLib.inf
  VirtioLib|OvmfPkg/Library/VirtioLib/VirtioLib.inf
  LoadLinuxLib|OvmfPkg/Library/LoadLinuxLib/LoadLinuxLib.inf
  MemEncryptSevLib|OvmfPkg/Library/BaseMemEncryptSevLib/DxeMemEncryptSevLib.inf
  MemEncryptTdxLib|OvmfPkg/Library/BaseMemEncryptTdxLib/BaseMemEncryptTdxLib.inf
  PeiHardwareInfoLib|OvmfPkg/Library/HardwareInfoLib/PeiHardwareInfoLib.inf
  DxeHardwareInfoLib|OvmfPkg/Library/HardwareInfoLib/DxeHardwareInfoLib.inf

!if $(SMM_REQUIRE) == FALSE
  LockBoxLib|OvmfPkg/Library/LockBoxLib/LockBoxBaseLib.inf
  CcProbeLib|OvmfPkg/Library/CcProbeLib/DxeCcProbeLib.inf
!else
  CcProbeLib|MdePkg/Library/CcProbeLibNull/CcProbeLibNull.inf
!endif
  CustomizedDisplayLib|MdeModulePkg/Library/CustomizedDisplayLib/CustomizedDisplayLib.inf
  FrameBufferBltLib|MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.inf

!if $(SOURCE_DEBUG_ENABLE) == TRUE
  PeCoffExtraActionLib|SourceLevelDebugPkg/Library/PeCoffExtraActionLibDebug/PeCoffExtraActionLibDebug.inf
  DebugCommunicationLib|SourceLevelDebugPkg/Library/DebugCommunicationLibSerialPort/DebugCommunicationLibSerialPort.inf
!else
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  DebugAgentLib|MdeModulePkg/Library/DebugAgentLibNull/DebugAgentLibNull.inf
!endif

  LocalApicLib|UefiCpuPkg/Library/BaseXApicX2ApicLib/BaseXApicX2ApicLib.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
!if $(NETWORK_TLS_ENABLE) == TRUE
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf
!else
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibCrypto.inf
!endif
  RngLib|MdePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf

!if $(SECURE_BOOT_ENABLE) == TRUE
  PlatformSecureLib|OvmfPkg/Library/PlatformSecureLib/PlatformSecureLib.inf
  AuthVariableLib|SecurityPkg/Library/AuthVariableLib/AuthVariableLib.inf
  SecureBootVariableLib|SecurityPkg/Library/SecureBootVariableLib/SecureBootVariableLib.inf
  PlatformPKProtectionLib|SecurityPkg/Library/PlatformPKProtectionLibVarPolicy/PlatformPKProtectionLibVarPolicy.inf
  SecureBootVariableProvisionLib|SecurityPkg/Library/SecureBootVariableProvisionLib/SecureBootVariableProvisionLib.inf
!else
  AuthVariableLib|MdeModulePkg/Library/AuthVariableLibNull/AuthVariableLibNull.inf
!endif
  VarCheckLib|MdeModulePkg/Library/VarCheckLib/VarCheckLib.inf
  VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLib.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf
  VariableFlashInfoLib|MdeModulePkg/Library/BaseVariableFlashInfoLib/BaseVariableFlashInfoLib.inf


  #
  # Network libraries
  #
!include NetworkPkg/NetworkLibs.dsc.inc

!if $(NETWORK_TLS_ENABLE) == TRUE
  TlsLib|CryptoPkg/Library/TlsLib/TlsLib.inf
!endif

!if $(BUILD_SHELL) == TRUE
  ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
!endif
  ShellCEntryLib|ShellPkg/Library/UefiShellCEntryLib/UefiShellCEntryLib.inf

  S3BootScriptLib|MdeModulePkg/Library/PiDxeS3BootScriptLib/DxeS3BootScriptLib.inf
  SmbusLib|MdePkg/Library/BaseSmbusLibNull/BaseSmbusLibNull.inf
  OrderedCollectionLib|MdePkg/Library/BaseOrderedCollectionRedBlackTreeLib/BaseOrderedCollectionRedBlackTreeLib.inf

  #
  # AsanLib library class always resolves to the Null instance — the
  # real instance gets pulled into every instrumented module via the
  # NULL library injection in [LibraryClasses.common.<TYPE>] when
  # ASAN_INSTRUMENT=TRUE. The Null instance carries empty stubs for
  # PoisonPool / UnpoisonPool / SetupAsanShadowMemory / AsanSyz*
  # so modules that explicitly reference AsanLib (like the agent's
  # SyzAgentDispatch.c when SYZ_AGENT_HAS_ASAN_SYZ is set) still link.
  #
!if $(ASAN_INSTRUMENT) == TRUE
  # Modules that explicitly reference AsanLib in their .inf get the
  # real (full) runtime. The default for un-instrumented modules
  # remains AsanLibNull (just below) since they wouldn't activate
  # asan anyway.
  AsanLib|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!else
  AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf
!endif

!if $(SYZ_AGENT_ENABLE) == TRUE
  #
  # syzkaller fuzzing build: SyzCoverLib provides the named library
  # SyzAgentDxe consumes; the NULL injection that adds the
  # __sanitizer_cov_trace_pc_guard{,_init} hooks to every DXE driver
  # is configured per-MODULE_TYPE in the
  # [LibraryClasses.common.<TYPE>] blocks below.
  #
  SyzCoverLib|OvmfPkg/Library/SyzCoverLib/SyzCoverLib.inf

  #
  # SyzBugsLib: bug-class primitives for fuzzer validation. Consumers
  # gate invocation with `#ifdef SYZ_BUGS_DISPATCH_INJECT`; the DSC
  # DEFINE propagates that macro via the GCC CC_FLAGS block above.
  #
  SyzBugsLib|MdeModulePkg/Library/SyzBugsLib/SyzBugsLib.inf
!endif

!include OvmfPkg/Include/Dsc/OvmfTpmLibs.dsc.inc

[LibraryClasses.common]
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  CcExitLib|OvmfPkg/Library/CcExitLib/CcExitLib.inf
  TdxLib|MdePkg/Library/TdxLib/TdxLib.inf
  TdxMailboxLib|OvmfPkg/Library/TdxMailboxLib/TdxMailboxLib.inf

[LibraryClasses.common.SEC]
  TimerLib|OvmfPkg/Library/AcpiTimerLib/BaseRomAcpiTimerLib.inf
  QemuFwCfgLib|OvmfPkg/Library/QemuFwCfgLib/QemuFwCfgSecLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformRomDebugLibIoPort.inf
!endif
  ReportStatusCodeLib|MdeModulePkg/Library/PeiReportStatusCodeLib/PeiReportStatusCodeLib.inf
  ExtractGuidedSectionLib|MdePkg/Library/BaseExtractGuidedSectionLib/BaseExtractGuidedSectionLib.inf
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  DebugAgentLib|SourceLevelDebugPkg/Library/DebugAgent/SecPeiDebugAgentLib.inf
!endif
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLibIdt/PeiServicesTablePointerLibIdt.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
!if $(TOOL_CHAIN_TAG) == "XCODE5"
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/Xcode5SecPeiCpuExceptionHandlerLib.inf
!else
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/SecPeiCpuExceptionHandlerLib.inf
!endif
  CcExitLib|OvmfPkg/Library/CcExitLib/SecCcExitLib.inf
  MemEncryptSevLib|OvmfPkg/Library/BaseMemEncryptSevLib/SecMemEncryptSevLib.inf
  CcProbeLib|OvmfPkg/Library/CcProbeLib/SecPeiCcProbeLib.inf

[LibraryClasses.common.PEI_CORE]
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLibIdt/PeiServicesTablePointerLibIdt.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  PeiCoreEntryPoint|MdePkg/Library/PeiCoreEntryPoint/PeiCoreEntryPoint.inf
  ReportStatusCodeLib|MdeModulePkg/Library/PeiReportStatusCodeLib/PeiReportStatusCodeLib.inf
  OemHookStatusCodeLib|MdeModulePkg/Library/OemHookStatusCodeLibNull/OemHookStatusCodeLibNull.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformRomDebugLibIoPort.inf
!endif
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  CcProbeLib|OvmfPkg/Library/CcProbeLib/SecPeiCcProbeLib.inf

[LibraryClasses.common.PEIM]
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLibIdt/PeiServicesTablePointerLibIdt.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  ReportStatusCodeLib|MdeModulePkg/Library/PeiReportStatusCodeLib/PeiReportStatusCodeLib.inf
  OemHookStatusCodeLib|MdeModulePkg/Library/OemHookStatusCodeLibNull/OemHookStatusCodeLibNull.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformRomDebugLibIoPort.inf
!endif
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  ResourcePublicationLib|MdePkg/Library/PeiResourcePublicationLib/PeiResourcePublicationLib.inf
  ExtractGuidedSectionLib|MdePkg/Library/PeiExtractGuidedSectionLib/PeiExtractGuidedSectionLib.inf
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  DebugAgentLib|SourceLevelDebugPkg/Library/DebugAgent/SecPeiDebugAgentLib.inf
!endif
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/PeiCpuExceptionHandlerLib.inf
  MpInitLib|UefiCpuPkg/Library/MpInitLib/PeiMpInitLib.inf
  QemuFwCfgS3Lib|OvmfPkg/Library/QemuFwCfgS3Lib/PeiQemuFwCfgS3LibFwCfg.inf
  PcdLib|MdePkg/Library/PeiPcdLib/PeiPcdLib.inf
  QemuFwCfgLib|OvmfPkg/Library/QemuFwCfgLib/QemuFwCfgPeiLib.inf
  PlatformInitLib|OvmfPkg/Library/PlatformInitLib/PlatformInitLib.inf

  MemEncryptSevLib|OvmfPkg/Library/BaseMemEncryptSevLib/PeiMemEncryptSevLib.inf
  CcProbeLib|OvmfPkg/Library/CcProbeLib/SecPeiCcProbeLib.inf

[LibraryClasses.common.DXE_CORE]
  HobLib|MdePkg/Library/DxeCoreHobLib/DxeCoreHobLib.inf
  DxeCoreEntryPoint|MdePkg/Library/DxeCoreEntryPoint/DxeCoreEntryPoint.inf
  MemoryAllocationLib|MdeModulePkg/Library/DxeCoreMemoryAllocationLib/DxeCoreMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  ExtractGuidedSectionLib|MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  DebugAgentLib|SourceLevelDebugPkg/Library/DebugAgent/DxeDebugAgentLib.inf
!endif
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/DxeCpuExceptionHandlerLib.inf
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  #
  # Phase 3: inject AsanLibFull into DXE_CORE. Earlier attempts
  # wedged the dispatch loop because no HOB was produced and the
  # allocator's PoisonPool called into an uninitialized shadow.
  # Phase 2 fixed both: PlatformPei reserves + zeros the shadow
  # and publishes the gAsanInfoGuid HOB, and AsanLibConstructor
  # runs at DxeMain startup to activate the per-instance globals
  # before the first allocation.
  #
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  DxeCoreEntryPoint|MdePkg/Library/DxeCoreEntryPoint/DxeCoreEntryPoint.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/RuntimeDxeReportStatusCodeLib/RuntimeDxeReportStatusCodeLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/RuntimeCryptLib.inf
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
  QemuFwCfgS3Lib|OvmfPkg/Library/QemuFwCfgS3Lib/DxeQemuFwCfgS3LibFwCfg.inf
  VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLibRuntimeDxe.inf
!if $(SMM_REQUIRE) == TRUE
  MmUnblockMemoryLib|MdePkg/Library/MmUnblockMemoryLib/MmUnblockMemoryLibNull.inf
!endif
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

[LibraryClasses.common.UEFI_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  DxeCoreEntryPoint|MdePkg/Library/DxeCoreEntryPoint/DxeCoreEntryPoint.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  UefiScsiLib|MdePkg/Library/UefiScsiLib/UefiScsiLib.inf
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

[LibraryClasses.common.DXE_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  UefiScsiLib|MdePkg/Library/UefiScsiLib/UefiScsiLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  PlatformBootManagerLib|OvmfPkg/Library/PlatformBootManagerLib/PlatformBootManagerLib.inf
  PlatformBmPrintScLib|OvmfPkg/Library/PlatformBmPrintScLib/PlatformBmPrintScLib.inf
  QemuBootOrderLib|OvmfPkg/Library/QemuBootOrderLib/QemuBootOrderLib.inf
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/DxeCpuExceptionHandlerLib.inf
!if $(SMM_REQUIRE) == TRUE
  LockBoxLib|MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxDxeLib.inf
!else
  LockBoxLib|OvmfPkg/Library/LockBoxLib/LockBoxDxeLib.inf
!endif
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  DebugAgentLib|SourceLevelDebugPkg/Library/DebugAgent/DxeDebugAgentLib.inf
!endif
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
  MpInitLib|UefiCpuPkg/Library/MpInitLib/DxeMpInitLib.inf
  NestedInterruptTplLib|OvmfPkg/Library/NestedInterruptTplLib/NestedInterruptTplLib.inf
  QemuFwCfgS3Lib|OvmfPkg/Library/QemuFwCfgS3Lib/DxeQemuFwCfgS3LibFwCfg.inf
  QemuLoadImageLib|OvmfPkg/Library/X86QemuLoadImageLib/X86QemuLoadImageLib.inf

!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

[LibraryClasses.common.UEFI_APPLICATION]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

[LibraryClasses.common.DXE_SMM_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  MemoryAllocationLib|MdePkg/Library/SmmMemoryAllocationLib/SmmMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  SmmMemLib|MdePkg/Library/SmmMemLib/SmmMemLib.inf
  MmServicesTableLib|MdePkg/Library/MmServicesTableLib/MmServicesTableLib.inf
  SmmServicesTableLib|MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/SmmCpuExceptionHandlerLib.inf
!if $(SOURCE_DEBUG_ENABLE) == TRUE
  DebugAgentLib|SourceLevelDebugPkg/Library/DebugAgent/SmmDebugAgentLib.inf
!endif
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/SmmCryptLib.inf
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
  SmmCpuRendezvousLib|UefiCpuPkg/Library/SmmCpuRendezvousLib/SmmCpuRendezvousLib.inf
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
  #
  # SMIBVS — inert in smm=off builds (gSmst is NULL, constructor
  # bails early). Activates when OVMF is rebuilt with SMM_REQUIRE=
  # TRUE and QEMU launched with smm=on. Rejects CommBuffer pointers
  # into SMRAM — the classic SMM privilege-escalation pattern.
  #
  NULL|MdeModulePkg/Library/SmmBufValLib/SmmBufValLib.inf
!endif
!endif

[LibraryClasses.common.SMM_CORE]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  TimerLib|OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib.inf
  ResetSystemLib|OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib.inf
  SmmCorePlatformHookLib|MdeModulePkg/Library/SmmCorePlatformHookLibNull/SmmCorePlatformHookLibNull.inf
  MemoryAllocationLib|MdeModulePkg/Library/PiSmmCoreMemoryAllocationLib/PiSmmCoreMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  SmmMemLib|MdePkg/Library/SmmMemLib/SmmMemLib.inf
  SmmServicesTableLib|MdeModulePkg/Library/PiSmmCoreSmmServicesTableLib/PiSmmCoreSmmServicesTableLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
  PciLib|OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35.inf
!if $(SYZ_AGENT_ENABLE) == TRUE
  NULL|OvmfPkg/Library/SyzCoverLib/SyzCoverLibNull.inf
!if $(ASAN_INSTRUMENT) == TRUE
  NULL|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
!endif

################################################################################
#
# Pcd Section - list of all EDK II PCD Entries defined by this Platform.
#
################################################################################
[PcdsFeatureFlag]
  gEfiMdeModulePkgTokenSpaceGuid.PcdHiiOsRuntimeSupport|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeIplSupportUefiDecompress|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeIplSwitchToLongMode|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutGopSupport|TRUE
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutUgaSupport|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdInstallAcpiSdtProtocol|TRUE
!ifdef $(CSM_ENABLE)
  gUefiOvmfPkgTokenSpaceGuid.PcdCsmEnable|TRUE
!endif
!if $(SMM_REQUIRE) == TRUE
  gUefiOvmfPkgTokenSpaceGuid.PcdSmmSmramRequire|TRUE
  gUefiCpuPkgTokenSpaceGuid.PcdCpuHotPlugSupport|TRUE
  gEfiMdeModulePkgTokenSpaceGuid.PcdEnableVariableRuntimeCache|FALSE
!endif
!if $(SECURE_BOOT_ENABLE) == TRUE
  gEfiMdeModulePkgTokenSpaceGuid.PcdRequireSelfSignedPk|TRUE
!endif

[PcdsFixedAtBuild]
!if $(ASAN_INSTRUMENT) == TRUE
  #
  # ASan-instrumented DXE drivers turn OVMF's per-page memory
  # protection pass (ProtectUefiImageCommon → SetMemoryAttributes
  # loop) into a catastrophic per-access shadow-check storm under
  # TCG. Disable image protection and NX policy entirely so boot
  # skips that loop. We don't need them for firmware fuzzing — the
  # guest is throwaway and NX would otherwise break KASAN's own
  # shadow writes anyway.
  #
  gEfiMdeModulePkgTokenSpaceGuid.PcdImageProtectionPolicy|0x00000000
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy|0x0000000000000000
!endif
  gEfiMdeModulePkgTokenSpaceGuid.PcdStatusCodeMemorySize|1
!if $(SMM_REQUIRE) == FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange|FALSE
!endif
  gEfiMdePkgTokenSpaceGuid.PcdMaximumGuidedExtractHandler|0x10
  gEfiMdePkgTokenSpaceGuid.PcdMaximumLinkedListLength|0
!if ($(FD_SIZE_IN_KB) == 1024) || ($(FD_SIZE_IN_KB) == 2048)
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVariableSize|0x2000
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxAuthVariableSize|0x2800
!if $(NETWORK_TLS_ENABLE) == FALSE
  # match PcdFlashNvStorageVariableSize purely for convenience
  gEfiMdeModulePkgTokenSpaceGuid.PcdVariableStoreSize|0xe000
!endif
!endif
!if $(FD_SIZE_IN_KB) == 4096
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVariableSize|0x8400
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxAuthVariableSize|0x8400
!if $(NETWORK_TLS_ENABLE) == FALSE
  # match PcdFlashNvStorageVariableSize purely for convenience
  gEfiMdeModulePkgTokenSpaceGuid.PcdVariableStoreSize|0x40000
!endif
!endif
!if $(FD_SIZE_IN_KB) == 8192
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVariableSize|0x8400
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxAuthVariableSize|0x8400
!if $(NETWORK_TLS_ENABLE) == FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdVariableStoreSize|0x40000
!endif
!endif
!if $(NETWORK_TLS_ENABLE) == TRUE
  gEfiMdeModulePkgTokenSpaceGuid.PcdVariableStoreSize|0x80000
  gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVolatileVariableSize|0x40000
!endif

  gEfiMdeModulePkgTokenSpaceGuid.PcdVpdBaseAddress|0x0
  gEfiMdeModulePkgTokenSpaceGuid.PcdStatusCodeUseSerial|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdStatusCodeUseMemory|TRUE

  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x07

  # DEBUG_INIT      0x00000001  // Initialization
  # DEBUG_WARN      0x00000002  // Warnings
  # DEBUG_LOAD      0x00000004  // Load events
  # DEBUG_FS        0x00000008  // EFI File system
  # DEBUG_POOL      0x00000010  // Alloc & Free (pool)
  # DEBUG_PAGE      0x00000020  // Alloc & Free (page)
  # DEBUG_INFO      0x00000040  // Informational debug messages
  # DEBUG_DISPATCH  0x00000080  // PEI/DXE/SMM Dispatchers
  # DEBUG_VARIABLE  0x00000100  // Variable
  # DEBUG_BM        0x00000400  // Boot Manager
  # DEBUG_BLKIO     0x00001000  // BlkIo Driver
  # DEBUG_NET       0x00004000  // SNP Driver
  # DEBUG_UNDI      0x00010000  // UNDI Driver
  # DEBUG_LOADFILE  0x00020000  // LoadFile
  # DEBUG_EVENT     0x00080000  // Event messages
  # DEBUG_GCD       0x00100000  // Global Coherency Database changes
  # DEBUG_CACHE     0x00200000  // Memory range cachability changes
  # DEBUG_VERBOSE   0x00400000  // Detailed debug messages that may
  #                             // significantly impact boot performance
  # DEBUG_ERROR     0x80000000  // Error
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x8000004F

!if $(SOURCE_DEBUG_ENABLE) == TRUE
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17
!else
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F
!endif

  # This PCD is used to set the base address of the PCI express hierarchy. It
  # is only consulted when OVMF runs on Q35. In that case it is programmed into
  # the PCIEXBAR register.
  #
  # On Q35 machine types that QEMU intends to support in the long term, QEMU
  # never lets the RAM below 4 GB exceed 2816 MB.
  gEfiMdePkgTokenSpaceGuid.PcdPciExpressBaseAddress|0xB0000000

!if $(SOURCE_DEBUG_ENABLE) == TRUE
  gEfiSourceLevelDebugPkgTokenSpaceGuid.PcdDebugLoadImageMethod|0x2
!endif

  #
  # The NumberOfPages values below are ad-hoc. They are updated sporadically at
  # best (please refer to git-blame for past updates). The values capture a set
  # of BIN hints that made sense at a particular time, for some (now likely
  # unknown) workloads / boot paths.
  #
  gEmbeddedTokenSpaceGuid.PcdMemoryTypeEfiACPIMemoryNVS|0x80
  gEmbeddedTokenSpaceGuid.PcdMemoryTypeEfiACPIReclaimMemory|0x12
  gEmbeddedTokenSpaceGuid.PcdMemoryTypeEfiReservedMemoryType|0x80
  gEmbeddedTokenSpaceGuid.PcdMemoryTypeEfiRuntimeServicesCode|0x100
  gEmbeddedTokenSpaceGuid.PcdMemoryTypeEfiRuntimeServicesData|0x100

  #
  # TDX need 1G PageTable support
  gEfiMdeModulePkgTokenSpaceGuid.PcdUse1GPageTable|TRUE

  #
  # Network Pcds
  #
!include NetworkPkg/NetworkPcds.dsc.inc

  gEfiShellPkgTokenSpaceGuid.PcdShellFileOperationSize|0x20000

!if $(SMM_REQUIRE) == TRUE
  gUefiCpuPkgTokenSpaceGuid.PcdCpuSmmStackSize|0x4000
!endif

  # IRQs 5, 9, 10, 11 are level-triggered
  gUefiOvmfPkgTokenSpaceGuid.Pcd8259LegacyModeEdgeLevel|0x0E20

  # Point to the MdeModulePkg/Application/UiApp/UiApp.inf
  gEfiMdeModulePkgTokenSpaceGuid.PcdBootManagerMenuFile|{ 0x21, 0xaa, 0x2c, 0x46, 0x14, 0x76, 0x03, 0x45, 0x83, 0x6e, 0x8a, 0xb6, 0xf4, 0x66, 0x23, 0x31 }

################################################################################
#
# Pcd Dynamic Section - list of all EDK II PCD Entries defined by this Platform
#
################################################################################

[PcdsDynamicDefault]
  # only set when
  #   ($(SMM_REQUIRE) == FALSE)
  gEfiMdeModulePkgTokenSpaceGuid.PcdEmuVariableNvStoreReserved|0

!if $(SMM_REQUIRE) == FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageVariableBase64|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwWorkingBase64|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwSpareBase64|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwWorkingBase|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdFlashNvStorageFtwSpareBase|0
!endif
  gEfiMdeModulePkgTokenSpaceGuid.PcdVideoHorizontalResolution|1280
  gEfiMdeModulePkgTokenSpaceGuid.PcdVideoVerticalResolution|800
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutRow|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutColumn|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdAcpiS3Enable|FALSE
  gUefiOvmfPkgTokenSpaceGuid.PcdVideoResolutionSource|0
  gUefiOvmfPkgTokenSpaceGuid.PcdOvmfHostBridgePciDevId|0
  gUefiOvmfPkgTokenSpaceGuid.PcdPciIoBase|0x0
  gUefiOvmfPkgTokenSpaceGuid.PcdPciIoSize|0x0
  gUefiOvmfPkgTokenSpaceGuid.PcdPciMmio32Base|0x0
  gUefiOvmfPkgTokenSpaceGuid.PcdPciMmio32Size|0x0
  gUefiOvmfPkgTokenSpaceGuid.PcdPciMmio64Base|0x0
!ifdef $(CSM_ENABLE)
  gUefiOvmfPkgTokenSpaceGuid.PcdPciMmio64Size|0x0
!else
  gUefiOvmfPkgTokenSpaceGuid.PcdPciMmio64Size|0x800000000
!endif

  gEfiMdePkgTokenSpaceGuid.PcdPlatformBootTimeOut|0

  # Set video resolution for text setup.
  gEfiMdeModulePkgTokenSpaceGuid.PcdSetupVideoHorizontalResolution|640
  gEfiMdeModulePkgTokenSpaceGuid.PcdSetupVideoVerticalResolution|480

  gEfiMdeModulePkgTokenSpaceGuid.PcdSmbiosVersion|0x0208
  gEfiMdeModulePkgTokenSpaceGuid.PcdSmbiosDocRev|0x0
  gUefiOvmfPkgTokenSpaceGuid.PcdQemuSmbiosValidated|FALSE

  # Noexec settings for DXE.
  gEfiMdeModulePkgTokenSpaceGuid.PcdSetNxForStack|FALSE

  # UefiCpuPkg PCDs related to initial AP bringup and general AP management.
  gUefiCpuPkgTokenSpaceGuid.PcdCpuMaxLogicalProcessorNumber|64
  gUefiCpuPkgTokenSpaceGuid.PcdCpuBootLogicalProcessorNumber|0

  # Set memory encryption mask
  gEfiMdeModulePkgTokenSpaceGuid.PcdPteMemoryEncryptionAddressOrMask|0x0

  # Set Tdx shared bit mask
  gEfiMdeModulePkgTokenSpaceGuid.PcdTdxSharedBitMask|0x0

  # Set SEV-ES defaults
  gEfiMdeModulePkgTokenSpaceGuid.PcdGhcbBase|0
  gEfiMdeModulePkgTokenSpaceGuid.PcdGhcbSize|0
  gUefiCpuPkgTokenSpaceGuid.PcdSevEsIsEnabled|0

!if $(SMM_REQUIRE) == TRUE
  gUefiOvmfPkgTokenSpaceGuid.PcdQ35TsegMbytes|8
  gUefiOvmfPkgTokenSpaceGuid.PcdQ35SmramAtDefaultSmbase|FALSE
  gUefiCpuPkgTokenSpaceGuid.PcdCpuSmmSyncMode|0x01
  gUefiCpuPkgTokenSpaceGuid.PcdCpuSmmApSyncTimeout|100000
!endif

  gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00

!include OvmfPkg/Include/Dsc/OvmfTpmPcds.dsc.inc

  # IPv4 and IPv6 PXE Boot support.
  gEfiNetworkPkgTokenSpaceGuid.PcdIPv4PXESupport|0x01
  gEfiNetworkPkgTokenSpaceGuid.PcdIPv6PXESupport|0x01

  # Set ConfidentialComputing defaults
  gEfiMdePkgTokenSpaceGuid.PcdConfidentialComputingGuestAttr|0

!if $(CSM_ENABLE) == FALSE
  gEfiMdePkgTokenSpaceGuid.PcdFSBClock|1000000000
!endif

[PcdsDynamicHii]
!include OvmfPkg/Include/Dsc/OvmfTpmPcdsHii.dsc.inc

################################################################################
#
# Components Section - list of all EDK II Modules needed by this Platform.
#
################################################################################
[Components]
  OvmfPkg/ResetVector/ResetVector.inf

  #
  # SEC Phase modules
  #
  OvmfPkg/Sec/SecMain.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
      NULL|OvmfPkg/IntelTdx/TdxHelperLib/SecTdxHelperLib.inf
      BaseCryptLib|CryptoPkg/Library/BaseCryptLib/SecCryptLib.inf
  }

  #
  # PEI Phase modules
  #
  MdeModulePkg/Core/Pei/PeiMain.inf
  MdeModulePkg/Universal/PCD/Pei/Pcd.inf  {
    <LibraryClasses>
      PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  }
  MdeModulePkg/Universal/ReportStatusCodeRouter/Pei/ReportStatusCodeRouterPei.inf {
    <LibraryClasses>
      PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  }
  MdeModulePkg/Universal/StatusCodeHandler/Pei/StatusCodeHandlerPei.inf {
    <LibraryClasses>
      PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  }
  MdeModulePkg/Core/DxeIplPeim/DxeIpl.inf

  OvmfPkg/PlatformPei/PlatformPei.inf {
    <LibraryClasses>
      NULL|OvmfPkg/IntelTdx/TdxHelperLib/PeiTdxHelperLib.inf
  }
  UefiCpuPkg/Universal/Acpi/S3Resume2Pei/S3Resume2Pei.inf {
    <LibraryClasses>
!if $(SMM_REQUIRE) == TRUE
      LockBoxLib|MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxPeiLib.inf
!endif
  }
!if $(SMM_REQUIRE) == TRUE
  MdeModulePkg/Universal/FaultTolerantWritePei/FaultTolerantWritePei.inf
  MdeModulePkg/Universal/Variable/Pei/VariablePei.inf
  OvmfPkg/SmmAccess/SmmAccessPei.inf
!endif

  UefiCpuPkg/CpuMpPei/CpuMpPei.inf {
    <LibraryClasses>
      #
      # Directly use PeiMpInitLib. It depends on PeiMpInitLibMpDepLib which
      # checks the PPI of gEfiPeiMpInitLibMpDepPpiGuid.
      #
      MpInitLib|UefiCpuPkg/Library/MpInitLib/PeiMpInitLib.inf
      NULL|OvmfPkg/Library/MpInitLibDepLib/PeiMpInitLibMpDepLib.inf
  }

  UefiCpuPkg/CpuMpPei/CpuMpPei.inf {
    <Defines>
      FILE_GUID = $(UP_CPU_PEI_GUID)

    <LibraryClasses>
      #
      # Directly use MpInitLibUp. It depends on PeiMpInitLibUpDepLib which
      # checks the PPI of gEfiPeiMpInitLibUpDepPpiGuid.
      #
      MpInitLib|UefiCpuPkg/Library/MpInitLibUp/MpInitLibUp.inf
      NULL|OvmfPkg/Library/MpInitLibDepLib/PeiMpInitLibUpDepLib.inf
  }

!include OvmfPkg/Include/Dsc/OvmfTpmComponentsPei.dsc.inc

  #
  # DXE Phase modules
  #
  MdeModulePkg/Core/Dxe/DxeMain.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
      DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
!if $(ASAN_INSTRUMENT) == TRUE
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -DASAN_ENABLE
!endif
  }

  MdeModulePkg/Universal/ReportStatusCodeRouter/RuntimeDxe/ReportStatusCodeRouterRuntimeDxe.inf
  MdeModulePkg/Universal/StatusCodeHandler/RuntimeDxe/StatusCodeHandlerRuntimeDxe.inf
  MdeModulePkg/Universal/PCD/Dxe/Pcd.inf  {
   <LibraryClasses>
      PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  }

  MdeModulePkg/Core/RuntimeDxe/RuntimeDxe.inf

  MdeModulePkg/Universal/SecurityStubDxe/SecurityStubDxe.inf {
    <LibraryClasses>
!if $(SECURE_BOOT_ENABLE) == TRUE
      NULL|SecurityPkg/Library/DxeImageVerificationLib/DxeImageVerificationLib.inf
!endif
!include OvmfPkg/Include/Dsc/OvmfTpmSecurityStub.dsc.inc
  }

  MdeModulePkg/Universal/EbcDxe/EbcDxe.inf
  UefiCpuPkg/CpuIo2Dxe/CpuIo2Dxe.inf

  UefiCpuPkg/CpuDxe/CpuDxe.inf {
    <LibraryClasses>
      #
      # Directly use DxeMpInitLib. It depends on DxeMpInitLibMpDepLib which
      # checks the Protocol of gEfiMpInitLibMpDepProtocolGuid.
      #
      MpInitLib|UefiCpuPkg/Library/MpInitLib/DxeMpInitLib.inf
      NULL|OvmfPkg/Library/MpInitLibDepLib/DxeMpInitLibMpDepLib.inf
  }

  UefiCpuPkg/CpuDxe/CpuDxe.inf {
    <Defines>
      FILE_GUID = $(UP_CPU_DXE_GUID)

    <LibraryClasses>
      #
      # Directly use MpInitLibUp. It depends on DxeMpInitLibUpDepLib which
      # checks the Protocol of gEfiMpInitLibUpDepProtocolGuid.
      #
      MpInitLib|UefiCpuPkg/Library/MpInitLibUp/MpInitLibUp.inf
      NULL|OvmfPkg/Library/MpInitLibDepLib/DxeMpInitLibUpDepLib.inf
  }

!ifdef $(CSM_ENABLE)
  OvmfPkg/8259InterruptControllerDxe/8259.inf
  OvmfPkg/8254TimerDxe/8254Timer.inf
!else
  OvmfPkg/LocalApicTimerDxe/LocalApicTimerDxe.inf
!endif
  OvmfPkg/IncompatiblePciDeviceSupportDxe/IncompatiblePciDeviceSupport.inf
  OvmfPkg/PciHotPlugInitDxe/PciHotPlugInit.inf
  MdeModulePkg/Bus/Pci/PciHostBridgeDxe/PciHostBridgeDxe.inf {
    <LibraryClasses>
      PciHostBridgeLib|OvmfPkg/Library/PciHostBridgeLib/PciHostBridgeLib.inf
      PciHostBridgeUtilityLib|OvmfPkg/Library/PciHostBridgeUtilityLib/PciHostBridgeUtilityLib.inf
      NULL|OvmfPkg/Library/PlatformHasIoMmuLib/PlatformHasIoMmuLib.inf
!if $(ASAN_INSTRUMENT) == TRUE
      AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf
    <BuildOptions>
      #
      # PCI enumeration storms the ASan runtime with O(devices * MMIO)
      # shadow checks during root-bridge setup. Under TCG that stalls
      # boot for minutes and prevents the snapshot VM from ever
      # reaching SyzFwfuzzTrigger. Opt this component out so the
      # enumeration runs at native speed; we lose ASan coverage on
      # PciHostBridgeDxe (mature EDK2 code) but gain the ability to
      # attach devices the fuzzer actually needs (virtio-net,
      # virtio-blk).
      #
      GCC:*_*_*_CC_FLAGS = -fno-sanitize-coverage=trace-pc -fno-sanitize=undefined -fno-sanitize=kernel-address
!endif
  }
  MdeModulePkg/Bus/Pci/PciBusDxe/PciBusDxe.inf {
    <LibraryClasses>
      PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
!if $(ASAN_INSTRUMENT) == TRUE
      AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf
    <BuildOptions>
      # Same rationale as PciHostBridgeDxe — PCI enumeration is
      # massively MMIO-heavy and ASan-instrumenting it creates a
      # TCG boot storm. Target drivers (Ip4Dxe, Fat, etc.) remain
      # fully instrumented.
      GCC:*_*_*_CC_FLAGS = -fno-sanitize-coverage=trace-pc -fno-sanitize=undefined -fno-sanitize=kernel-address
!endif
  }
  MdeModulePkg/Universal/ResetSystemRuntimeDxe/ResetSystemRuntimeDxe.inf
  MdeModulePkg/Universal/Metronome/Metronome.inf
  PcAtChipsetPkg/PcatRealTimeClockRuntimeDxe/PcatRealTimeClockRuntimeDxe.inf
  MdeModulePkg/Universal/DriverHealthManagerDxe/DriverHealthManagerDxe.inf
  MdeModulePkg/Universal/BdsDxe/BdsDxe.inf {
    <LibraryClasses>
      XenPlatformLib|OvmfPkg/Library/XenPlatformLib/XenPlatformLib.inf
!ifdef $(CSM_ENABLE)
      NULL|OvmfPkg/Csm/CsmSupportLib/CsmSupportLib.inf
      NULL|OvmfPkg/Csm/LegacyBootManagerLib/LegacyBootManagerLib.inf
!endif
  }
  MdeModulePkg/Logo/LogoDxe.inf
  MdeModulePkg/Application/UiApp/UiApp.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/DeviceManagerUiLib/DeviceManagerUiLib.inf
      NULL|MdeModulePkg/Library/BootManagerUiLib/BootManagerUiLib.inf
      NULL|MdeModulePkg/Library/BootMaintenanceManagerUiLib/BootMaintenanceManagerUiLib.inf
!ifdef $(CSM_ENABLE)
      NULL|OvmfPkg/Csm/LegacyBootManagerLib/LegacyBootManagerLib.inf
      NULL|OvmfPkg/Csm/LegacyBootMaintUiLib/LegacyBootMaintUiLib.inf
!endif
  }
  OvmfPkg/QemuKernelLoaderFsDxe/QemuKernelLoaderFsDxe.inf {
    <LibraryClasses>
      NULL|OvmfPkg/Library/BlobVerifierLibNull/BlobVerifierLibNull.inf
  }
  OvmfPkg/VirtioPciDeviceDxe/VirtioPciDeviceDxe.inf
  OvmfPkg/Virtio10Dxe/Virtio10.inf
  OvmfPkg/VirtioBlkDxe/VirtioBlk.inf
  OvmfPkg/VirtioScsiDxe/VirtioScsi.inf
  OvmfPkg/VirtioRngDxe/VirtioRng.inf
!if $(PVSCSI_ENABLE) == TRUE
  OvmfPkg/PvScsiDxe/PvScsiDxe.inf
!endif
!if $(MPT_SCSI_ENABLE) == TRUE
  OvmfPkg/MptScsiDxe/MptScsiDxe.inf
!endif
!if $(LSI_SCSI_ENABLE) == TRUE
  OvmfPkg/LsiScsiDxe/LsiScsiDxe.inf
!endif
  MdeModulePkg/Universal/WatchdogTimerDxe/WatchdogTimer.inf
  MdeModulePkg/Universal/MonotonicCounterRuntimeDxe/MonotonicCounterRuntimeDxe.inf
  MdeModulePkg/Universal/CapsuleRuntimeDxe/CapsuleRuntimeDxe.inf
  MdeModulePkg/Universal/Console/ConPlatformDxe/ConPlatformDxe.inf
  MdeModulePkg/Universal/Console/ConSplitterDxe/ConSplitterDxe.inf
  MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsoleDxe.inf {
    <LibraryClasses>
      PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  }
  MdeModulePkg/Universal/Console/TerminalDxe/TerminalDxe.inf
  MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf {
    <LibraryClasses>
      DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
      PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  }
  MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf
  MdeModulePkg/Universal/Disk/PartitionDxe/PartitionDxe.inf
  MdeModulePkg/Universal/Disk/RamDiskDxe/RamDiskDxe.inf
  MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/EnglishDxe.inf
  FatPkg/EnhancedFatDxe/Fat.inf
  MdeModulePkg/Universal/Disk/UdfDxe/UdfDxe.inf
  OvmfPkg/VirtioFsDxe/VirtioFsDxe.inf
  MdeModulePkg/Bus/Scsi/ScsiBusDxe/ScsiBusDxe.inf
  MdeModulePkg/Bus/Scsi/ScsiDiskDxe/ScsiDiskDxe.inf
  OvmfPkg/SataControllerDxe/SataControllerDxe.inf
  MdeModulePkg/Bus/Ata/AtaAtapiPassThru/AtaAtapiPassThru.inf
  MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBusDxe.inf
  MdeModulePkg/Bus/Pci/NvmExpressDxe/NvmExpressDxe.inf
  MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf
  MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf
  MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf
  MdeModulePkg/Universal/MemoryTest/NullMemoryTestDxe/NullMemoryTestDxe.inf

!ifndef $(CSM_ENABLE)
  OvmfPkg/QemuVideoDxe/QemuVideoDxe.inf
!endif
  OvmfPkg/QemuRamfbDxe/QemuRamfbDxe.inf
  OvmfPkg/VirtioGpuDxe/VirtioGpu.inf

  #
  # ISA Support
  #
  OvmfPkg/SioBusDxe/SioBusDxe.inf
  MdeModulePkg/Bus/Pci/PciSioSerialDxe/PciSioSerialDxe.inf
  MdeModulePkg/Bus/Isa/Ps2KeyboardDxe/Ps2KeyboardDxe.inf

  #
  # SMBIOS Support
  #
  MdeModulePkg/Universal/SmbiosDxe/SmbiosDxe.inf {
    <LibraryClasses>
      NULL|OvmfPkg/Library/SmbiosVersionLib/DetectSmbiosVersionLib.inf
  }
  OvmfPkg/SmbiosPlatformDxe/SmbiosPlatformDxe.inf

  #
  # ACPI Support
  #
  MdeModulePkg/Universal/Acpi/AcpiTableDxe/AcpiTableDxe.inf
  OvmfPkg/AcpiPlatformDxe/AcpiPlatformDxe.inf
  MdeModulePkg/Universal/Acpi/S3SaveStateDxe/S3SaveStateDxe.inf
  MdeModulePkg/Universal/Acpi/BootScriptExecutorDxe/BootScriptExecutorDxe.inf
  MdeModulePkg/Universal/Acpi/BootGraphicsResourceTableDxe/BootGraphicsResourceTableDxe.inf

  #
  # Network Support
  #
!include NetworkPkg/NetworkComponents.dsc.inc
!include OvmfPkg/Include/Dsc/NetworkComponents.dsc.inc

  OvmfPkg/VirtioNetDxe/VirtioNet.inf

  #
  # Usb Support
  #
  MdeModulePkg/Bus/Pci/UhciDxe/UhciDxe.inf
  MdeModulePkg/Bus/Pci/EhciDxe/EhciDxe.inf
  MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf
  MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
  MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf
  MdeModulePkg/Bus/Usb/UsbMassStorageDxe/UsbMassStorageDxe.inf

!ifdef $(CSM_ENABLE)
  OvmfPkg/Csm/BiosThunk/VideoDxe/VideoDxe.inf {
    <LibraryClasses>
      PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  }
  OvmfPkg/Csm/LegacyBiosDxe/LegacyBiosDxe.inf
  OvmfPkg/Csm/Csm16/Csm16.inf
!endif

!if $(TOOL_CHAIN_TAG) != "XCODE5" && $(BUILD_SHELL) == TRUE
  ShellPkg/DynamicCommand/TftpDynamicCommand/TftpDynamicCommand.inf {
    <PcdsFixedAtBuild>
      gEfiShellPkgTokenSpaceGuid.PcdShellLibAutoInitialize|FALSE
  }
  ShellPkg/DynamicCommand/HttpDynamicCommand/HttpDynamicCommand.inf {
    <PcdsFixedAtBuild>
      gEfiShellPkgTokenSpaceGuid.PcdShellLibAutoInitialize|FALSE
  }
  OvmfPkg/LinuxInitrdDynamicShellCommand/LinuxInitrdDynamicShellCommand.inf {
    <PcdsFixedAtBuild>
      gEfiShellPkgTokenSpaceGuid.PcdShellLibAutoInitialize|FALSE
  }
!endif
!if $(BUILD_SHELL) == TRUE
  ShellPkg/Application/Shell/Shell.inf {
    <LibraryClasses>
      ShellCommandLib|ShellPkg/Library/UefiShellCommandLib/UefiShellCommandLib.inf
      NULL|ShellPkg/Library/UefiShellLevel2CommandsLib/UefiShellLevel2CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellLevel1CommandsLib/UefiShellLevel1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellLevel3CommandsLib/UefiShellLevel3CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellDriver1CommandsLib/UefiShellDriver1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellDebug1CommandsLib/UefiShellDebug1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellInstall1CommandsLib/UefiShellInstall1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellNetwork1CommandsLib/UefiShellNetwork1CommandsLib.inf
!if $(NETWORK_IP6_ENABLE) == TRUE
      NULL|ShellPkg/Library/UefiShellNetwork2CommandsLib/UefiShellNetwork2CommandsLib.inf
!endif
      HandleParsingLib|ShellPkg/Library/UefiHandleParsingLib/UefiHandleParsingLib.inf
      PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
      BcfgCommandLib|ShellPkg/Library/UefiShellBcfgCommandLib/UefiShellBcfgCommandLib.inf

    <PcdsFixedAtBuild>
      gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0xFF
      gEfiShellPkgTokenSpaceGuid.PcdShellLibAutoInitialize|FALSE
      gEfiMdePkgTokenSpaceGuid.PcdUefiLibMaxPrintBufferSize|8000
  }
!endif

!if $(SECURE_BOOT_ENABLE) == TRUE
  SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigDxe.inf
  OvmfPkg/EnrollDefaultKeys/EnrollDefaultKeys.inf
!endif

  OvmfPkg/PlatformDxe/Platform.inf
  OvmfPkg/AmdSevDxe/AmdSevDxe.inf {
    <LibraryClasses>
    PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  }
  OvmfPkg/IoMmuDxe/IoMmuDxe.inf

!if $(SYZ_AGENT_ENABLE) == TRUE
  OvmfPkg/SyzAgentDxe/SyzAgentDxe.inf {
    <BuildOptions>
      #
      # SyzAgentDxe must not be instrumented. The per-MODULE_TYPE block
      # applies -fsanitize-coverage=trace-pc, -fsanitize=undefined, and
      # (under ASAN_INSTRUMENT=TRUE) -fsanitize=kernel-address +
      # -fasan-shadow-offset. gcc-wrap strips -fasan-shadow-offset and
      # --param asan-* when it sees -fno-sanitize=kernel-address, so we
      # can just append the disable flags below.
      #
      GCC:*_*_*_CC_FLAGS = -fno-sanitize-coverage=trace-pc,trace-cmp -fno-sanitize=undefined -fno-sanitize=kernel-address -DSYZ_AGENT_NO_ASAN_RUNTIME=1
    <LibraryClasses>
      AsanLib|MdeModulePkg/Library/AsanLibNull/AsanLibNull.inf
  }
!if $(ASAN_INSTRUMENT) == TRUE
  #
  # Phase 1 of the "instrument everything" rollout: wildcard ASan is
  # now applied at the MODULE_TYPE level in
  # [BuildOptions.common.EDKII.DXE_DRIVER]. The SyzAsanTestDxe
  # per-component override below is no longer required (it just
  # duplicates the wildcard) and is retained purely as a quick
  # compile-time sanity check that the wildcard matches the legacy
  # flags verbatim — if you ever want a distinct flag set for the
  # test module, modify this override.
  #
  OvmfPkg/SyzAsanTestDxe/SyzAsanTestDxe.inf
  #
  # SyzBugsDxe canary — triggers one bug of every class ASan + UBSan
  # can detect. Inherits wildcard ASan + (if UBSAN_INSTRUMENT=TRUE)
  # wildcard UBSan. Used to verify each phase of the rollout.
  #
  OvmfPkg/SyzBugsDxe/SyzBugsDxe.inf
!endif
!endif

  OvmfPkg/TdxDxe/TdxDxe.inf

!if $(SMM_REQUIRE) == TRUE
  OvmfPkg/SmmAccess/SmmAccess2Dxe.inf
  OvmfPkg/SmmControl2Dxe/SmmControl2Dxe.inf
  OvmfPkg/CpuS3DataDxe/CpuS3DataDxe.inf

  #
  # SMM Initial Program Load (a DXE_RUNTIME_DRIVER)
  #
  MdeModulePkg/Core/PiSmmCore/PiSmmIpl.inf

  #
  # SMM_CORE
  #
  MdeModulePkg/Core/PiSmmCore/PiSmmCore.inf

  #
  # Privileged drivers (DXE_SMM_DRIVER modules)
  #
  OvmfPkg/CpuHotplugSmm/CpuHotplugSmm.inf
  UefiCpuPkg/CpuIo2Smm/CpuIo2Smm.inf
  MdeModulePkg/Universal/LockBox/SmmLockBox/SmmLockBox.inf {
    <LibraryClasses>
      LockBoxLib|MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxSmmLib.inf
  }
  UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.inf {
    <LibraryClasses>
      SmmCpuPlatformHookLib|OvmfPkg/Library/SmmCpuPlatformHookLibQemu/SmmCpuPlatformHookLibQemu.inf
      SmmCpuFeaturesLib|OvmfPkg/Library/SmmCpuFeaturesLib/SmmCpuFeaturesLib.inf
  }

  #
  # Variable driver stack (SMM)
  #
  OvmfPkg/QemuFlashFvbServicesRuntimeDxe/FvbServicesSmm.inf {
    <LibraryClasses>
    CcExitLib|UefiCpuPkg/Library/CcExitLibNull/CcExitLibNull.inf
  }
  MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteSmm.inf
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/VarCheckUefiLib/VarCheckUefiLib.inf
      NULL|MdeModulePkg/Library/VarCheckPolicyLib/VarCheckPolicyLib.inf
  }
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmmRuntimeDxe.inf

!else

  #
  # Variable driver stack (non-SMM)
  #
  OvmfPkg/QemuFlashFvbServicesRuntimeDxe/FvbServicesRuntimeDxe.inf
  OvmfPkg/EmuVariableFvbRuntimeDxe/Fvb.inf {
    <LibraryClasses>
      PlatformFvbLib|OvmfPkg/Library/EmuVariableFvbLib/EmuVariableFvbLib.inf
  }
  MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteDxe.inf
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/VarCheckUefiLib/VarCheckUefiLib.inf
!if $(ASAN_INSTRUMENT) == TRUE
      #
      # Phase 1: ASan flags come from the wildcard DXE_RUNTIME_DRIVER
      # BuildOptions block. We only need the named AsanLib instance
      # here so the module's explicit AsanLib reference resolves.
      #
      AsanLib|MdeModulePkg/Library/AsanLib/AsanLibFull.inf
!endif
  }
!endif

  #
  # Cc Measurement Protocol for Td guest
  #
!if $(CC_MEASUREMENT_ENABLE) == TRUE
  SecurityPkg/Tcg/TdTcg2Dxe/TdTcg2Dxe.inf {
    <LibraryClasses>
      HashLib|SecurityPkg/Library/HashLibTdx/HashLibTdx.inf
      NULL|SecurityPkg/Library/HashInstanceLibSha384/HashInstanceLibSha384.inf
  }
!endif

  #
  # TPM support
  #
!include OvmfPkg/Include/Dsc/OvmfTpmComponentsDxe.dsc.inc

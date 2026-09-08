/** @file
  What an OS needs to reach an SMI handler, for fuzzing from a kernel driver.

  Calling an SMI handler is not just a write to the SMI command port. EDK2's DXE side
  stores the buffer in the SMM Core private data first, and the SMM entry point reads it
  back from there, so a driver running after ExitBootServices needs the addresses of
  those two fields. Nothing publishes them: the PI spec's SMM Communication ACPI Table
  would, and this tree does not implement it.

  PiSmmIpl writes this as a VOLATILE runtime UEFI variable, so it never touches flash and
  Linux surfaces it under /sys/firmware/efi/efivars. A configuration table with a private
  GUID would be invisible to an OS.

Copyright (c) 2026, Firness contributors. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef FIRNESS_SMM_FUZZ_INFO_H_
#define FIRNESS_SMM_FUZZ_INFO_H_

#define FIRNESS_SMM_FUZZ_INFO_GUID \
  { 0x6a1f6c2b, 0x9d54, 0x4f7e, { 0x8c, 0x31, 0x2b, 0x77, 0x0e, 0x4d, 0xa9, 0x15 } }

#define FIRNESS_SMM_FUZZ_INFO_VARIABLE   L"FirnessSmmInfo"
#define FIRNESS_SMM_FUZZ_INFO_SIGNATURE  SIGNATURE_32 ('F', 'R', 'N', 'S')
#define FIRNESS_SMM_FUZZ_INFO_REVISION   1

#pragma pack(1)
typedef struct {
  UINT32    Signature;
  UINT32    Revision;
  ///
  /// The communication region SmmCommunicationBufferDxe reserved, or zero when that
  /// driver is not in the platform. Zero is not a failure: the handlers still work,
  /// the caller just has to supply a buffer of its own.
  ///
  UINT64    CommRegionPhysical;
  UINT64    CommRegionSize;
  ///
  /// Addresses of gSmmCorePrivate->CommunicationBuffer and ->BufferSize. Write the
  /// buffer's physical address and total size here before raising the SMI, exactly as
  /// SmmCommunicationCommunicate does.
  ///
  UINT64    CommunicationBufferAddress;
  UINT64    BufferSizeAddress;
  UINT16    SmiCommandPort;
  UINT16    SmiCommandValue;
} FIRNESS_SMM_FUZZ_INFO;
#pragma pack()

extern EFI_GUID  gFirnessSmmFuzzInfoGuid;

#endif

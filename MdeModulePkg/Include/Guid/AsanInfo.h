/** @file
  GUID for an event that is signaled on the first attempt to check for a keystroke 
  from the ConIn device.

  Copyright (c) 2012, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ASAN_INFO_GUID_H__
#define __ASAN_INFO_GUID_H__

#define ASAN_INFO_GUID \
          { 0xac0634da, 0x320e, 0x4f1d, { 0x8d, 0xc, 0x2e, 0x99, 0x1e, 0xab, 0xe5, 0xae } };

typedef struct {
  UINT64       AsanShadowMemorySize;
  UINT64       AsanShadowMemoryStart;
  UINT32       AsanInited;
  UINT32       AsanActivated;
} ASAN_INFO;

extern EFI_GUID gAsanInfoGuid;

//
// Late-binding shadow rendezvous (see MdeModulePkg.dec for the matching
// gAsanShadowReadyProtocolGuid). The producer (SyzAgentDxe) allocates
// one ASAN_SHADOW_INFO and installs it as the protocol interface; each
// per-module AsanLib instance reads it from its notify callback.
//
typedef struct {
  UINT64       ShadowMemoryStart;   ///< CPU-virtual base of the shadow window
  UINT64       ShadowMemorySize;    ///< byte length of the shadow window
} ASAN_SHADOW_INFO;

extern EFI_GUID gAsanShadowReadyProtocolGuid;

//
// AsanLib direct activation entry point. A module that explicitly
// wants its own per-instance asan checks turned on calls this from
// its entry point with a directly-mapped CPU pointer to the shadow
// region (i.e. the BAR base + 0x200000 the agent published). The
// per-module AsanLib copy then starts checking every instrumented
// load/store. No protocol notify, no fan-out — exactly the calling
// module's instance is affected.
//
VOID
EFIAPI
AsanLibActivate (
  IN VOID    *ShadowBase,
  IN UINTN   ShadowSize
  );

#endif

/** @file
  SyzAgentDxe - in-firmware dispatcher for syzkaller's edk2 fuzzing target.

  Copyright (c) 2026, syzkaller project authors. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SYZ_AGENT_DXE_H_
#define SYZ_AGENT_DXE_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Wire format constants. These MUST stay in lockstep with
// syzkaller's executor/common_edk2.h. The transport channel is a 2 MiB
// shared memory region (the QEMU ivshmem-plain BAR) laid out as:
//
//   [0x0000]  UINT32   Magic ('SYZE' = 0x53595A45)
//   [0x0004]  UINT32   NumCalls
//   [0x0008]  ...      packed array of SYZ_EDK2_CALL records
//   [0x1000]  UINT32   HostSeq    (host -> guest doorbell)
//   [0x1004]  UINT32   GuestSeq   (guest -> host ack)
//   [0x1008]  UINT32   GuestStatus (0 = OK, non-zero = agent error)
//   [0x2000]  UINT32   PcCount; UINT64 Pcs[PcCount]   (coverage ring)
//
#define SYZ_EDK2_PROGRAM_MAGIC      0x53595A45U

#define SYZ_EDK2_OFF_MAGIC          0x0000U
#define SYZ_EDK2_OFF_NCALLS         0x0004U
#define SYZ_EDK2_OFF_CALLS          0x0008U
#define SYZ_EDK2_OFF_HOST_SEQ       0x1000U
#define SYZ_EDK2_OFF_GUEST_SEQ      0x1004U
#define SYZ_EDK2_OFF_GUEST_STATUS   0x1008U
#define SYZ_EDK2_OFF_COVER          0x2000U

#define SYZ_EDK2_MAX_CALLS          32U
#define SYZ_EDK2_MAX_PROGRAM_BYTES  (SYZ_EDK2_OFF_HOST_SEQ - SYZ_EDK2_OFF_CALLS)
#define SYZ_EDK2_MAX_COVER_PCS      (((2U * 1024U * 1024U) - SYZ_EDK2_OFF_COVER - 4U) / sizeof (UINT64))

//
// SyzAgent API IDs. These numeric tags MUST match the ones in the
// sys/edk2/edk2.txt syzlang description file on the syzkaller side.
//
typedef enum {
  SyzEdk2ApiNop                      = 1,
  SyzEdk2ApiSetVariable              = 100,
  SyzEdk2ApiGetVariable              = 101,
  SyzEdk2ApiQueryVariableInfo        = 102,
  SyzEdk2ApiAllocatePool             = 200,
  SyzEdk2ApiFreePool                 = 201,
  SyzEdk2ApiAllocatePages            = 202,
  SyzEdk2ApiFreePages                = 203,
  SyzEdk2ApiLocateProtocol           = 300,
  SyzEdk2ApiLocateHandleBuffer       = 301,
  SyzEdk2ApiHiiNewPackageList        = 400,
  SyzEdk2ApiHiiRemovePackageList     = 401,
  SyzEdk2ApiAsanPoisonAlloc          = 500,
  SyzEdk2ApiAsanUnpoisonAlloc        = 501,
  SyzEdk2ApiAsanReportAlloc          = 502,
} SYZ_EDK2_API_ID;

//
// Symbolic protocol identifiers exposed to the fuzzer (avoids dragging
// 16-byte EFI_GUID values through syzlang). The agent maps each one to
// the corresponding gEfi*Guid via gSyzEdk2ProtocolTable.
//
typedef enum {
  SyzEdk2ProtoBlockIo            = 100,
  SyzEdk2ProtoDevicePath         = 101,
  SyzEdk2ProtoDiskIo             = 102,
  SyzEdk2ProtoLoadedImage        = 103,
  SyzEdk2ProtoSerialIo           = 104,
  SyzEdk2ProtoSimpleFs           = 105,
  SyzEdk2ProtoSimpleNetwork      = 106,
  SyzEdk2ProtoSimpleTextOut      = 107,
  SyzEdk2ProtoHiiDatabase        = 200,
  SyzEdk2ProtoHiiString          = 201,
  SyzEdk2ProtoHiiFont            = 202,
} SYZ_EDK2_PROTO_ID;

//
// On-wire record format: each call is prefixed with (Call, Size) where
// Size is the byte length of the entire record including this header.
// All payload structs must be packed and live in the SYZ_EDK2_CALL union.
//
#pragma pack (1)

typedef struct {
  UINT32    Call;     ///< SYZ_EDK2_API_ID
  UINT32    Size;     ///< total record bytes incl. header
} SYZ_EDK2_CALL_HDR;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_NOP_PAYLOAD;

typedef struct {
  UINT16    NameSize;     ///< bytes of unicode Name (does not include the trailing UINT8 array offset)
  UINT32    Attributes;
  UINT16    DataSize;
  // CHAR16 Name[NameSize / 2];
  // UINT8  Data[DataSize];
} SYZ_EDK2_SET_VARIABLE_PAYLOAD;

typedef struct {
  UINT16    NameSize;
  UINT16    MaxData;
  // CHAR16 Name[NameSize / 2];
} SYZ_EDK2_GET_VARIABLE_PAYLOAD;

typedef struct {
  UINT32    Attributes;
} SYZ_EDK2_QUERY_VARIABLE_INFO_PAYLOAD;

typedef struct {
  UINT32    MemType;
  UINT32    Size;
} SYZ_EDK2_ALLOCATE_POOL_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;
} SYZ_EDK2_FREE_POOL_PAYLOAD;

typedef struct {
  UINT32    AllocType;
  UINT32    MemType;
  UINT32    Pages;
} SYZ_EDK2_ALLOCATE_PAGES_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;
} SYZ_EDK2_FREE_PAGES_PAYLOAD;

typedef struct {
  UINT32    ProtocolId;
} SYZ_EDK2_LOCATE_PROTOCOL_PAYLOAD;

typedef struct {
  UINT32    SearchType;
  UINT32    ProtocolId;
} SYZ_EDK2_LOCATE_HANDLE_BUFFER_PAYLOAD;

typedef struct {
  UINT16    PackageSize;
  // UINT8 Data[PackageSize];
} SYZ_EDK2_HII_NEW_PACKAGE_LIST_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
} SYZ_EDK2_HII_REMOVE_PACKAGE_LIST_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;     ///< slot in gSyzEdk2Agent.Allocs
  UINT32    Offset;         ///< byte offset within the allocation
  UINT32    Length;         ///< bytes to poison / unpoison
  UINT8     IsWrite;        ///< only used by AsanReportAlloc
  UINT8     Pad[3];
} SYZ_EDK2_ASAN_PAYLOAD;

#pragma pack ()

//
// The agent maintains a small per-program allocation table so the fuzzer
// can hand back opaque indices to FreePool / FreePages instead of raw
// pointers.
//
#define SYZ_EDK2_MAX_ALLOCS  32U

typedef enum {
  SyzEdk2AllocSlotEmpty = 0,
  SyzEdk2AllocSlotPool,
  SyzEdk2AllocSlotPages,
} SYZ_EDK2_ALLOC_SLOT_KIND;

typedef struct {
  SYZ_EDK2_ALLOC_SLOT_KIND  Kind;
  VOID                      *Pointer;
  UINTN                     Pages;
} SYZ_EDK2_ALLOC_SLOT;

#define SYZ_EDK2_MAX_HII_HANDLES  16U

typedef struct {
  EFI_HII_HANDLE  Handle;
} SYZ_EDK2_HII_SLOT;

//
// Per-agent global state.
//
typedef struct {
  VOID                  *SharedBase;
  UINTN                 SharedSize;
  UINT32                LastSeq;
  SYZ_EDK2_ALLOC_SLOT   Allocs[SYZ_EDK2_MAX_ALLOCS];
  SYZ_EDK2_HII_SLOT     HiiHandles[SYZ_EDK2_MAX_HII_HANDLES];
  EFI_GUID              SyzEdk2VendorGuid;
} SYZ_EDK2_AGENT;

extern SYZ_EDK2_AGENT  gSyzEdk2Agent;

//
// SyzAgentTransport.c — discovers the ivshmem region and provides the
// host<->guest doorbell helpers.
//
EFI_STATUS
EFIAPI
SyzEdk2TransportInit (
  OUT VOID    **SharedBase,
  OUT UINTN   *SharedSize
  );

VOID
EFIAPI
SyzEdk2TransportAck (
  IN UINT32  Status
  );

BOOLEAN
EFIAPI
SyzEdk2TransportPoll (
  OUT UINT32  *HostSeq
  );

//
// SyzAgentDispatch.c — interprets a single program from the shared
// region. Returns EFI_SUCCESS if the program executed cleanly, regardless
// of whether individual calls succeeded.
//
EFI_STATUS
EFIAPI
SyzEdk2Dispatch (
  IN CONST UINT8  *Program,
  IN UINTN        ProgramSize
  );

//
// Look up a SYZ_EDK2_PROTO_ID and return its EFI_GUID, or NULL if the
// id is unknown.
//
CONST EFI_GUID *
EFIAPI
SyzEdk2LookupProtocolGuid (
  IN UINT32  ProtocolId
  );

#endif // SYZ_AGENT_DXE_H_

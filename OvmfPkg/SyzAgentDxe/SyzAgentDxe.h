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
//
// Everything from SYZ_EDK2_OFF_SHADOW onwards is reserved for the
// AddressSanitizer shadow window. The host backs the ivshmem file
// with a region large enough that the shadow can cover the DXE
// physical-memory range we care about (256 MiB host file ⇒ 254 MiB
// shadow ⇒ ~2 GiB of shadowed addresses at SHADOW_SCALE=3).
//
#define SYZ_EDK2_OFF_SHADOW         0x200000U

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
  SyzEdk2ApiGetNextVariableName      = 103,
  SyzEdk2ApiCopyMem                  = 204,
  SyzEdk2ApiSetMem                   = 205,
  SyzEdk2ApiCalculateCrc32           = 206,
  SyzEdk2ApiGetTime                  = 230,
  SyzEdk2ApiSetTime                  = 231,
  SyzEdk2ApiStall                    = 232,
  SyzEdk2ApiSetWatchdogTimer         = 233,
  SyzEdk2ApiGetMonotonicCount        = 234,
  SyzEdk2ApiCreateEvent              = 250,
  SyzEdk2ApiCloseEvent               = 251,
  SyzEdk2ApiSignalEvent              = 252,
  SyzEdk2ApiRaiseTpl                 = 253,
  SyzEdk2ApiInstallConfigTable       = 302,
  SyzEdk2ApiHiiNewPackageList        = 400,
  SyzEdk2ApiHiiRemovePackageList     = 401,
  SyzEdk2ApiAsanPoisonAlloc          = 500,
  SyzEdk2ApiAsanUnpoisonAlloc        = 501,
  SyzEdk2ApiAsanReportAlloc          = 502,
  // Protocol method calls (600+)
  SyzEdk2ApiBlockIoReadBlocks      = 600,
  SyzEdk2ApiBlockIoWriteBlocks     = 601,
  SyzEdk2ApiDiskIoReadDisk         = 610,
  SyzEdk2ApiPciIoMemRead           = 620,
  SyzEdk2ApiPciIoPciRead           = 621,
  SyzEdk2ApiSnpTransmit            = 630,
  SyzEdk2ApiUsbIoControlTransfer   = 640,
  SyzEdk2ApiGopBlt                 = 650,
  SyzEdk2ApiHiiUpdatePackageList   = 660,
  SyzEdk2ApiHiiExportPackageLists  = 661,
} SYZ_EDK2_API_ID;

//
// Symbolic variable namespace identifiers. The agent maps each id back
// to a real EFI_GUID via the gSyzEdk2VariableNamespaceTable lookup.
//
typedef enum {
  SyzEdk2VarNsSyz              = 0,
  SyzEdk2VarNsGlobal           = 1,
  SyzEdk2VarNsImageSecurityDb  = 2,
  SyzEdk2VarNsImageSecurityDbx = 3,
  SyzEdk2VarNsImageSecurityDbt = 4,
} SYZ_EDK2_VAR_NS_ID;

//
// Symbolic protocol identifiers exposed to the fuzzer (avoids dragging
// 16-byte EFI_GUID values through syzlang). The agent maps each one to
// the corresponding gEfi*Guid via gSyzEdk2ProtocolTable.
//
typedef enum {
  // --- Storage ---
  SyzEdk2ProtoBlockIo            = 100,
  SyzEdk2ProtoDevicePath         = 101,
  SyzEdk2ProtoDiskIo             = 102,
  SyzEdk2ProtoLoadedImage        = 103,
  SyzEdk2ProtoSerialIo           = 104,
  SyzEdk2ProtoSimpleFs           = 105,
  SyzEdk2ProtoSimpleNetwork      = 106,
  SyzEdk2ProtoSimpleTextOut      = 107,
  SyzEdk2ProtoBlockIo2           = 108,
  SyzEdk2ProtoDiskIo2            = 109,
  SyzEdk2ProtoScsiIo             = 110,
  SyzEdk2ProtoExtScsiPassThru    = 111,
  SyzEdk2ProtoAtaPassThru        = 112,
  SyzEdk2ProtoNvmePassThru       = 113,
  // --- Network ---
  SyzEdk2ProtoManagedNetwork     = 150,
  SyzEdk2ProtoIp4                = 151,
  SyzEdk2ProtoIp6                = 152,
  SyzEdk2ProtoTcp4               = 153,
  SyzEdk2ProtoTcp6               = 154,
  SyzEdk2ProtoUdp4               = 155,
  SyzEdk2ProtoUdp6               = 156,
  SyzEdk2ProtoDhcp4              = 157,
  SyzEdk2ProtoDhcp6              = 158,
  SyzEdk2ProtoDns4               = 159,
  SyzEdk2ProtoDns6               = 160,
  SyzEdk2ProtoHttp               = 161,
  SyzEdk2ProtoMtftp4             = 162,
  SyzEdk2ProtoMtftp6             = 163,
  SyzEdk2ProtoArp                = 164,
  SyzEdk2ProtoIp4Config2         = 165,
  SyzEdk2ProtoIp6Config          = 166,
  // --- HII ---
  SyzEdk2ProtoHiiDatabase        = 200,
  SyzEdk2ProtoHiiString          = 201,
  SyzEdk2ProtoHiiFont            = 202,
  // --- Graphics + Input ---
  SyzEdk2ProtoGraphicsOutput     = 210,
  SyzEdk2ProtoSimpleTextIn       = 211,
  // --- USB ---
  SyzEdk2ProtoUsbIo              = 220,
  SyzEdk2ProtoUsb2Hc             = 221,
  // --- PCI ---
  SyzEdk2ProtoPciIo              = 230,
  SyzEdk2ProtoPciRootBridgeIo    = 231,
  // --- ACPI ---
  SyzEdk2ProtoAcpiSdt            = 240,
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
  UINT32    Namespace;    ///< SYZ_EDK2_VAR_NS_ID
  // CHAR16 Name[NameSize / 2];
  // UINT8  Data[DataSize];
} SYZ_EDK2_SET_VARIABLE_PAYLOAD;

typedef struct {
  UINT16    NameSize;
  UINT16    MaxData;
  UINT32    Namespace;    ///< SYZ_EDK2_VAR_NS_ID
  // CHAR16 Name[NameSize / 2];
} SYZ_EDK2_GET_VARIABLE_PAYLOAD;

typedef struct {
  UINT16    MaxName;
  UINT8     Reset;
  UINT8     Pad0;
  UINT8     Pad1;
  UINT8     Pad2;
} SYZ_EDK2_GET_NEXT_VARIABLE_NAME_PAYLOAD;

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
  UINT32    DstIndex;
  UINT32    SrcIndex;
  UINT32    DstOffset;
  UINT32    SrcOffset;
  UINT32    Length;
} SYZ_EDK2_COPY_MEM_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;
  UINT32    Offset;
  UINT32    Length;
  UINT8     Value;
  UINT8     Pad0;
  UINT8     Pad1;
  UINT8     Pad2;
} SYZ_EDK2_SET_MEM_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;
  UINT32    Offset;
  UINT32    Length;
} SYZ_EDK2_CALC_CRC_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_GET_TIME_PAYLOAD;

//
// Wire-format EFI_TIME (16 bytes packed). Matches the syzlang
// edk2_api_set_time struct.
//
typedef struct {
  UINT16    Year;
  UINT8     Month;
  UINT8     Day;
  UINT8     Hour;
  UINT8     Minute;
  UINT8     Second;
  UINT8     Pad0;
  UINT32    Nanosecond;
  INT16     TimeZone;
  UINT8     Daylight;
  UINT8     Pad1;
} SYZ_EDK2_SET_TIME_PAYLOAD;

typedef struct {
  UINT32    Microseconds;
} SYZ_EDK2_STALL_PAYLOAD;

typedef struct {
  UINT32    TimeoutSecs;
  UINT64    Code;
  UINT32    DataSize;
} SYZ_EDK2_SET_WATCHDOG_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_MONOTONIC_PAYLOAD;

typedef struct {
  UINT32    Type;
  UINT32    Tpl;
} SYZ_EDK2_CREATE_EVENT_PAYLOAD;

typedef struct {
  UINT32    EventIndex;
} SYZ_EDK2_EVENT_INDEX_PAYLOAD;

typedef struct {
  UINT32    Tpl;
} SYZ_EDK2_RAISE_TPL_PAYLOAD;

typedef struct {
  UINT32    GuidId;
  UINT64    Value;
} SYZ_EDK2_INSTALL_CONFIG_PAYLOAD;

typedef struct {
  UINT32    AllocIndex;     ///< slot in gSyzEdk2Agent.Allocs
  UINT32    Offset;         ///< byte offset within the allocation
  UINT32    Length;         ///< bytes to poison / unpoison
  UINT8     IsWrite;        ///< only used by AsanReportAlloc
  UINT8     Pad[3];
} SYZ_EDK2_ASAN_PAYLOAD;

typedef struct {
  UINT32    MediaId;
  UINT64    Lba;
  UINT32    BufferSize;
  UINT32    DstIndex;
} SYZ_EDK2_BLOCK_IO_READ_PAYLOAD;

typedef struct {
  UINT32    MediaId;
  UINT64    Lba;
  UINT32    BufferSize;
  UINT32    SrcIndex;
} SYZ_EDK2_BLOCK_IO_WRITE_PAYLOAD;

typedef struct {
  UINT32    MediaId;
  UINT64    Offset;
  UINT32    BufferSize;
  UINT32    DstIndex;
} SYZ_EDK2_DISK_IO_READ_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    BarIndex;
  UINT64    Offset;
  UINT32    Count;
  UINT32    DstIndex;
} SYZ_EDK2_PCI_IO_MEM_READ_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    PciOffset;
  UINT32    Count;
  UINT32    DstIndex;
} SYZ_EDK2_PCI_IO_PCI_READ_PAYLOAD;

typedef struct {
  UINT32    HeaderSize;
  UINT32    BufferSize;
  UINT32    SrcIndex;
  UINT8     SrcAddr[6];
  UINT8     DestAddr[6];
  UINT16    Protocol;
  UINT16    Pad0;
} SYZ_EDK2_SNP_TRANSMIT_PAYLOAD;

typedef struct {
  UINT8     RequestType;
  UINT8     Request;
  UINT16    Value;
  UINT16    Index;
  UINT16    Pad0;
  UINT32    Direction;
  UINT32    Timeout;
  UINT32    DataIndex;
  UINT16    DataLength;
  UINT16    Pad1;
} SYZ_EDK2_USB_IO_CONTROL_TRANSFER_PAYLOAD;

typedef struct {
  UINT32    SrcIndex;
  UINT32    BltOp;
  UINT32    SrcX;
  UINT32    SrcY;
  UINT32    DstX;
  UINT32    DstY;
  UINT32    Width;
  UINT32    Height;
  UINT32    Delta;
} SYZ_EDK2_GOP_BLT_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
  UINT16    PackageSize;
  UINT16    Pad0;
  // UINT8  Data[PackageSize];
} SYZ_EDK2_HII_UPDATE_PACKAGE_LIST_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
  UINT32    BufferSize;
  UINT32    DstIndex;
} SYZ_EDK2_HII_EXPORT_PACKAGE_LISTS_PAYLOAD;

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
  UINTN                     Pages;  ///< only for SyzEdk2AllocSlotPages
  UINTN                     Bytes;  ///< exact byte length for both kinds
} SYZ_EDK2_ALLOC_SLOT;

#define SYZ_EDK2_MAX_HII_HANDLES  16U

typedef struct {
  EFI_HII_HANDLE  Handle;
} SYZ_EDK2_HII_SLOT;

#define SYZ_EDK2_MAX_EVENTS  16U

typedef struct {
  EFI_EVENT  Event;
} SYZ_EDK2_EVENT_SLOT;

#define SYZ_EDK2_MAX_VARNAME  256U

//
// Per-agent global state.
//
typedef struct {
  VOID                  *SharedBase;
  UINTN                 SharedSize;
  UINT32                LastSeq;
  SYZ_EDK2_ALLOC_SLOT   Allocs[SYZ_EDK2_MAX_ALLOCS];
  SYZ_EDK2_HII_SLOT     HiiHandles[SYZ_EDK2_MAX_HII_HANDLES];
  SYZ_EDK2_EVENT_SLOT   Events[SYZ_EDK2_MAX_EVENTS];
  EFI_GUID              SyzEdk2VendorGuid;
  // Saved iterator for SyzEdk2ApiGetNextVariableName.
  CHAR16                NextVarName[SYZ_EDK2_MAX_VARNAME / sizeof (CHAR16)];
  EFI_GUID              NextVarGuid;
  BOOLEAN               NextVarValid;
  // BAR-backed asan shadow region — discovered at PciIo time but the
  // actual gAsanShadowReadyProtocolGuid install is deferred so the
  // dispatcher can choose when to activate asan checks system-wide.
  VOID                  *AsanShadowBase;
  UINTN                 AsanShadowSize;
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

VOID
EFIAPI
SyzEdk2TransportReadBytes (
  IN UINT32  Offset,
  OUT VOID   *Dest,
  IN UINT32  Length
  );

EFI_STATUS
EFIAPI
SyzEdk2TransportGetShadowRegion (
  OUT VOID    **ShadowBase,
  OUT UINTN   *ShadowSize
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
  IN UINTN        ProgramSize,
  IN UINT32       NumCalls
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

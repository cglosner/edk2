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
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>

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
  SyzEdk2ApiSetVariableAuth          = 104,
  SyzEdk2ApiSetVariableDelete        = 105,
  SyzEdk2ApiSetVariableAppend        = 106,
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
  // Event / Timer extensions
  SyzEdk2ApiSetTimer               = 254,
  SyzEdk2ApiWaitForEvent           = 255,
  // Protocol method calls (600+)
  SyzEdk2ApiBlockIoReadBlocks      = 600,
  SyzEdk2ApiBlockIoWriteBlocks     = 601,
  SyzEdk2ApiDiskIoReadDisk         = 610,
  SyzEdk2ApiDiskIoWriteDisk        = 611,
  // PCI (620-629)
  SyzEdk2ApiPciIoMemRead           = 620,
  SyzEdk2ApiPciIoPciRead           = 621,
  SyzEdk2ApiPciIoMemWrite          = 622,
  SyzEdk2ApiPciIoPciWrite          = 623,
  SyzEdk2ApiPciIoIoRead            = 624,
  SyzEdk2ApiPciIoIoWrite           = 625,
  SyzEdk2ApiPciRbIoMemRead         = 626,
  SyzEdk2ApiPciRbIoMemWrite        = 627,
  SyzEdk2ApiPciRbIoPciRead         = 628,
  SyzEdk2ApiPciRbIoPciWrite        = 629,
  // SNP (630-639)
  SyzEdk2ApiSnpTransmit            = 630,
  SyzEdk2ApiSnpReceive             = 631,
  SyzEdk2ApiSnpGetStatus           = 632,
  SyzEdk2ApiSnpInitialize          = 633,
  // USB (640-649)
  SyzEdk2ApiUsbIoControlTransfer   = 640,
  SyzEdk2ApiUsbIoBulkTransfer      = 641,
  // GOP (650-659)
  SyzEdk2ApiGopBlt                 = 650,
  SyzEdk2ApiGopSetMode             = 651,
  SyzEdk2ApiGopQueryMode           = 652,
  // HII (660-669)
  SyzEdk2ApiHiiUpdatePackageList   = 660,
  SyzEdk2ApiHiiExportPackageLists  = 661,
  SyzEdk2ApiHiiNewString           = 662,
  SyzEdk2ApiHiiGetString           = 663,
  SyzEdk2ApiHiiSetString           = 664,
  SyzEdk2ApiHiiGetLanguages        = 665,
  // Network (670-699)
  SyzEdk2ApiIp4Configure           = 670,
  SyzEdk2ApiIp4Transmit            = 671,
  SyzEdk2ApiIp4GetModeData         = 672,
  SyzEdk2ApiUdp4Configure          = 673,
  SyzEdk2ApiUdp4Transmit           = 674,
  SyzEdk2ApiUdp4GetModeData        = 675,
  SyzEdk2ApiTcp4Configure          = 676,
  SyzEdk2ApiTcp4Connect            = 677,
  SyzEdk2ApiTcp4Transmit           = 678,
  SyzEdk2ApiTcp4GetModeData        = 679,
  SyzEdk2ApiDhcp4Configure         = 680,
  SyzEdk2ApiDhcp4Start             = 681,
  SyzEdk2ApiDhcp4GetModeData       = 682,
  SyzEdk2ApiArpConfigure           = 683,
  SyzEdk2ApiArpAdd                 = 684,
  SyzEdk2ApiArpRequest             = 685,
  SyzEdk2ApiMnpConfigure           = 686,
  SyzEdk2ApiMnpTransmit            = 687,
  // File System (700-709)
  SyzEdk2ApiSimpleFsOpenVolume     = 700,
  SyzEdk2ApiFileOpen               = 701,
  SyzEdk2ApiFileRead               = 702,
  SyzEdk2ApiFileWrite              = 703,
  SyzEdk2ApiFileGetInfo            = 704,
  SyzEdk2ApiFileSetInfo            = 705,
  SyzEdk2ApiFileClose              = 706,
  SyzEdk2ApiFileDelete             = 707,
  // Device Path (710-719)
  SyzEdk2ApiDevicePathFromText     = 710,
  SyzEdk2ApiDevicePathToText       = 711,
  // Console (720-729)
  SyzEdk2ApiTextOutOutputString    = 720,
  SyzEdk2ApiTextOutSetMode         = 721,
  SyzEdk2ApiTextOutSetAttribute    = 722,
  SyzEdk2ApiTextOutClearScreen     = 723,
  SyzEdk2ApiTextInReset            = 724,
  SyzEdk2ApiTextInReadKeyStroke    = 725,
  // ACPI (730-739)
  SyzEdk2ApiAcpiGetTable           = 730,
  SyzEdk2ApiAcpiInstallTable       = 731,
  // Network IPv6 (740-759)
  SyzEdk2ApiIp6Configure           = 740,
  SyzEdk2ApiIp6Transmit            = 741,
  SyzEdk2ApiIp6GetModeData         = 742,
  SyzEdk2ApiUdp6Configure          = 743,
  SyzEdk2ApiUdp6Transmit           = 744,
  SyzEdk2ApiUdp6GetModeData        = 745,
  SyzEdk2ApiTcp6Configure          = 746,
  SyzEdk2ApiTcp6Connect            = 747,
  SyzEdk2ApiTcp6Transmit           = 748,
  SyzEdk2ApiTcp6GetModeData        = 749,
  SyzEdk2ApiDhcp6Configure         = 750,
  SyzEdk2ApiDhcp6Start             = 751,
  SyzEdk2ApiDhcp6GetModeData       = 752,
  SyzEdk2ApiDns4HostNameToIp       = 753,
  SyzEdk2ApiDns4Configure          = 754,
  SyzEdk2ApiDns6HostNameToIp       = 755,
  SyzEdk2ApiDns6Configure          = 756,
  SyzEdk2ApiMtftp4ReadFile         = 757,
  SyzEdk2ApiMtftp4GetInfo          = 758,
  // Application layer (759-769)
  SyzEdk2ApiHttpConfigure          = 759,
  SyzEdk2ApiHttpRequest            = 760,
  SyzEdk2ApiHttpResponse           = 761,
  SyzEdk2ApiHttpPoll               = 762,
  // Crypto / Security (770-789)
  SyzEdk2ApiHash2GetHashSize       = 770,
  SyzEdk2ApiHash2Hash              = 771,
  SyzEdk2ApiRngGetInfo             = 772,
  SyzEdk2ApiRngGetRng              = 773,
  SyzEdk2ApiTcg2GetCapability      = 774,
  SyzEdk2ApiTcg2HashLogExtendEvent = 775,
  SyzEdk2ApiTcg2SubmitCommand      = 776,
  SyzEdk2ApiTcg2GetEventLog        = 777,
  SyzEdk2ApiPkcs7Verify            = 778,
  // Storage passthrough (780-789)
  SyzEdk2ApiAtaPassThru            = 780,
  SyzEdk2ApiAtaPassThruGetNextDev  = 781,
  SyzEdk2ApiExtScsiPassThru        = 782,
  SyzEdk2ApiExtScsiGetNextDevice   = 783,
  SyzEdk2ApiNvmePassThru           = 784,
  SyzEdk2ApiNvmePassThruGetNextNs  = 785,
  // Boot dispatcher (790-799)
  SyzEdk2ApiLoadImage              = 790,
  SyzEdk2ApiStartImage             = 791,
  SyzEdk2ApiUnloadImage            = 792,
  SyzEdk2ApiConnectController      = 793,
  SyzEdk2ApiDisconnectController   = 794,
  SyzEdk2ApiLoadImagePe            = 795,   // inline PE/COFF image
  //
  // Hardware-level / low-level protocols (800-819).
  //
  SyzEdk2ApiSmiTrigger             = 800,   // SW-SMI via port 0xB2
  SyzEdk2ApiSmmCommunicate         = 801,   // EfiSmmCommunicationProtocol
  SyzEdk2ApiCpuIoPortRead          = 810,   // EfiCpuIo2Protocol IO read
  SyzEdk2ApiCpuIoPortWrite         = 811,   // EfiCpuIo2Protocol IO write
  SyzEdk2ApiCpuIoMemRead           = 812,   // EfiCpuIo2Protocol MEM read
  SyzEdk2ApiCpuIoMemWrite          = 813,   // EfiCpuIo2Protocol MEM write
  SyzEdk2ApiMsrRead                = 814,   // rdmsr (fuzzer-chosen MSR)
  SyzEdk2ApiMsrWrite               = 815,   // wrmsr (fuzzer-chosen MSR+value)
  //
  // SMBIOS protocol — add malformed entries, iterate.
  //
  SyzEdk2ApiSmbiosAdd              = 820,
  SyzEdk2ApiSmbiosGetNext          = 821,
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

// --- SetTimer / WaitForEvent ---

typedef struct {
  UINT32    EventIndex;
  UINT32    Type;           ///< EFI_TIMER_DELAY (0=Cancel, 1=Periodic, 2=Relative)
  UINT64    TriggerTime;    ///< 100ns units
} SYZ_EDK2_SET_TIMER_PAYLOAD;

typedef struct {
  UINT32    EventIndex;     ///< which event slot to wait on
  UINT32    Timeout;        ///< milliseconds (0 = poll once)
} SYZ_EDK2_WAIT_FOR_EVENT_PAYLOAD;

// --- DiskIo Write ---

typedef struct {
  UINT32    MediaId;
  UINT64    Offset;
  UINT32    BufferSize;
  UINT32    SrcIndex;
} SYZ_EDK2_DISK_IO_WRITE_PAYLOAD;

// --- PCI extensions ---

typedef struct {
  UINT32    Width;
  UINT32    BarIndex;
  UINT64    Offset;
  UINT32    Count;
  UINT32    SrcIndex;
} SYZ_EDK2_PCI_IO_MEM_WRITE_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    PciOffset;
  UINT32    Count;
  UINT32    SrcIndex;
} SYZ_EDK2_PCI_IO_PCI_WRITE_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    BarIndex;
  UINT64    Offset;
  UINT32    Count;
  UINT32    DstIndex;
} SYZ_EDK2_PCI_IO_IO_READ_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    BarIndex;
  UINT64    Offset;
  UINT32    Count;
  UINT32    SrcIndex;
} SYZ_EDK2_PCI_IO_IO_WRITE_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT64    Offset;
  UINT32    Count;
  UINT32    DstIndex;
} SYZ_EDK2_PCI_RB_IO_MEM_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT64    Offset;
  UINT32    Count;
  UINT32    SrcIndex;
} SYZ_EDK2_PCI_RB_IO_MEM_WRITE_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    PciOffset;
  UINT32    Count;
  UINT32    DstIndex;
} SYZ_EDK2_PCI_RB_IO_PCI_PAYLOAD;

typedef struct {
  UINT32    Width;
  UINT32    PciOffset;
  UINT32    Count;
  UINT32    SrcIndex;
} SYZ_EDK2_PCI_RB_IO_PCI_WRITE_PAYLOAD;

// --- SNP extensions ---

typedef struct {
  UINT32    BufferSize;
  UINT32    DstIndex;
} SYZ_EDK2_SNP_RECEIVE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_SNP_GET_STATUS_PAYLOAD;

typedef struct {
  UINT32    RxBufSize;
  UINT32    TxBufSize;
} SYZ_EDK2_SNP_INITIALIZE_PAYLOAD;

// --- USB Bulk Transfer ---

typedef struct {
  UINT8     EndpointAddr;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT32    DataIndex;
  UINT32    DataLength;
  UINT32    Timeout;
} SYZ_EDK2_USB_IO_BULK_TRANSFER_PAYLOAD;

// --- GOP extensions ---

typedef struct {
  UINT32    ModeNumber;
} SYZ_EDK2_GOP_SET_MODE_PAYLOAD;

typedef struct {
  UINT32    ModeNumber;
} SYZ_EDK2_GOP_QUERY_MODE_PAYLOAD;

// --- HII String ---

typedef struct {
  UINT32    HandleIndex;
  UINT16    StringSize;     ///< bytes of string data following
  UINT16    Pad0;
  // CHAR16 String[StringSize / 2];
} SYZ_EDK2_HII_NEW_STRING_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
  UINT32    StringId;
  UINT32    MaxSize;
  UINT32    DstIndex;
} SYZ_EDK2_HII_GET_STRING_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
  UINT32    StringId;
  UINT16    StringSize;
  UINT16    Pad0;
  // CHAR16 String[StringSize / 2];
} SYZ_EDK2_HII_SET_STRING_PAYLOAD;

typedef struct {
  UINT32    HandleIndex;
  UINT32    MaxSize;
  UINT32    DstIndex;
} SYZ_EDK2_HII_GET_LANGUAGES_PAYLOAD;

// --- Network: IP4 ---

typedef struct {
  UINT8     DefaultProtocol;
  UINT8     AcceptAnyProtocol;
  UINT8     AcceptIcmpErrors;
  UINT8     AcceptBroadcast;
  UINT8     UseDefaultAddress;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT8     StationAddress[4];
  UINT8     SubnetMask[4];
  UINT32    TypeOfService;
  UINT32    TimeToLive;
} SYZ_EDK2_IP4_CONFIGURE_PAYLOAD;

typedef struct {
  UINT8     DstAddress[4];
  UINT8     Protocol;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT32    DataIndex;
  UINT32    DataLength;
} SYZ_EDK2_IP4_TRANSMIT_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_IP4_GET_MODE_DATA_PAYLOAD;

// --- Network: UDP4 ---

typedef struct {
  UINT8     AcceptBroadcast;
  UINT8     AcceptPromiscuous;
  UINT8     AcceptAnyPort;
  UINT8     AllowDuplicatePort;
  UINT8     UseDefaultAddress;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT8     StationAddress[4];
  UINT8     SubnetMask[4];
  UINT16    StationPort;
  UINT16    RemotePort;
  UINT8     RemoteAddress[4];
} SYZ_EDK2_UDP4_CONFIGURE_PAYLOAD;

typedef struct {
  UINT8     DstAddress[4];
  UINT16    DstPort;
  UINT16    Pad0;
  UINT32    DataIndex;
  UINT32    DataLength;
} SYZ_EDK2_UDP4_TRANSMIT_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_UDP4_GET_MODE_DATA_PAYLOAD;

// --- Network: TCP4 ---

typedef struct {
  UINT8     UseDefaultAddress;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT8     StationAddress[4];
  UINT8     SubnetMask[4];
  UINT16    StationPort;
  UINT16    Pad2;
  UINT8     RemoteAddress[4];
  UINT16    RemotePort;
  UINT8     ActiveFlag;       ///< TRUE = active open
  UINT8     Pad3;
} SYZ_EDK2_TCP4_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TCP4_CONNECT_PAYLOAD;

typedef struct {
  UINT32    DataIndex;
  UINT32    DataLength;
  UINT8     Push;
  UINT8     Urgent;
  UINT16    Pad0;
} SYZ_EDK2_TCP4_TRANSMIT_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TCP4_GET_MODE_DATA_PAYLOAD;

// --- Network: DHCP4 ---

typedef struct {
  UINT32    DiscoverTryCount;
  UINT32    RequestTryCount;
} SYZ_EDK2_DHCP4_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_DHCP4_START_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_DHCP4_GET_MODE_DATA_PAYLOAD;

// --- Network: ARP ---

typedef struct {
  UINT16    SwAddressLength;
  UINT16    Pad0;
  UINT32    RetryCount;
  UINT32    RetryTimeoutMs;
} SYZ_EDK2_ARP_CONFIGURE_PAYLOAD;

typedef struct {
  UINT8     DenyFlag;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT8     SwAddress[4];       ///< IPv4 address
  UINT8     HwAddress[6];       ///< MAC address
  UINT16    Pad2;
} SYZ_EDK2_ARP_ADD_PAYLOAD;

typedef struct {
  UINT8     TargetSwAddress[4];
  UINT32    DstIndex;           ///< buffer for resolved HW address
} SYZ_EDK2_ARP_REQUEST_PAYLOAD;

// --- Network: MNP ---

typedef struct {
  UINT32    ReceivedQueueTimeoutMs;
  UINT32    TransmitQueueTimeoutMs;
  UINT16    ProtocolTypeFilter;
  UINT8     EnableUnicastReceive;
  UINT8     EnableMulticastReceive;
  UINT8     EnableBroadcastReceive;
  UINT8     EnablePromiscuousReceive;
  UINT8     FlushQueuesOnReset;
  UINT8     DisableBackgroundPolling;
} SYZ_EDK2_MNP_CONFIGURE_PAYLOAD;

typedef struct {
  UINT32    DataIndex;
  UINT32    DataLength;
  UINT8     DestAddr[6];
  UINT8     SrcAddr[6];
  UINT16    Protocol;
  UINT16    Pad0;
} SYZ_EDK2_MNP_TRANSMIT_PAYLOAD;

// --- File System ---

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_SIMPLEFS_OPEN_VOLUME_PAYLOAD;

#define SYZ_EDK2_MAX_FILE_HANDLES  8U

typedef struct {
  UINT32    FileHandleIndex;  ///< parent directory handle (0 = root)
  UINT64    Mode;             ///< EFI_FILE_MODE_* bitmask
  UINT64    Attributes;       ///< EFI_FILE_ATTRIBUTE_* bitmask
  UINT16    NameSize;         ///< bytes of CHAR16 filename
  UINT16    Pad0;
  // CHAR16 Name[NameSize / 2];
} SYZ_EDK2_FILE_OPEN_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
  UINT32    BufferSize;
  UINT32    DstIndex;
} SYZ_EDK2_FILE_READ_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
  UINT32    DataIndex;
  UINT32    DataLength;
} SYZ_EDK2_FILE_WRITE_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
  UINT32    DstIndex;         ///< buffer for EFI_FILE_INFO
  UINT32    BufferSize;
} SYZ_EDK2_FILE_GET_INFO_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
  UINT32    DataIndex;        ///< buffer with fuzzed EFI_FILE_INFO
  UINT32    DataLength;
} SYZ_EDK2_FILE_SET_INFO_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
} SYZ_EDK2_FILE_CLOSE_PAYLOAD;

typedef struct {
  UINT32    FileHandleIndex;
} SYZ_EDK2_FILE_DELETE_PAYLOAD;

// --- Device Path ---

typedef struct {
  UINT16    TextSize;         ///< bytes of ASCII text (null-terminated)
  UINT16    Pad0;
  // CHAR8  Text[TextSize];
} SYZ_EDK2_DEVICE_PATH_FROM_TEXT_PAYLOAD;

typedef struct {
  UINT32    DstIndex;         ///< buffer for text output
  UINT32    MaxSize;
  UINT8     DisplayOnly;
  UINT8     AllowShortcuts;
  UINT16    Pad0;
} SYZ_EDK2_DEVICE_PATH_TO_TEXT_PAYLOAD;

// --- Console ---

typedef struct {
  UINT16    StringSize;       ///< bytes of CHAR16 string
  UINT16    Pad0;
  // CHAR16 String[StringSize / 2];
} SYZ_EDK2_TEXT_OUT_OUTPUT_STRING_PAYLOAD;

typedef struct {
  UINT32    ModeNumber;
} SYZ_EDK2_TEXT_OUT_SET_MODE_PAYLOAD;

typedef struct {
  UINT32    Attribute;
} SYZ_EDK2_TEXT_OUT_SET_ATTRIBUTE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TEXT_OUT_CLEAR_SCREEN_PAYLOAD;

typedef struct {
  UINT8     ExtendedVerification;
  UINT8     Pad0;
  UINT16    Pad1;
} SYZ_EDK2_TEXT_IN_RESET_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TEXT_IN_READ_KEY_STROKE_PAYLOAD;

// --- ACPI ---

typedef struct {
  UINT32    Index;            ///< table index
  UINT32    DstIndex;         ///< alloc slot for returned table pointer
} SYZ_EDK2_ACPI_GET_TABLE_PAYLOAD;

typedef struct {
  UINT32    DataIndex;        ///< alloc slot with fuzzed ACPI table
  UINT32    DataLength;
} SYZ_EDK2_ACPI_INSTALL_TABLE_PAYLOAD;

// ======================================================================
// Network IPv6
// ======================================================================

typedef struct {
  UINT8     DefaultProtocol;
  UINT8     AcceptAnyProtocol;
  UINT8     AcceptIcmpErrors;
  UINT8     AcceptPromiscuous;
  UINT8     DestinationAddress[16];
  UINT8     StationAddress[16];
  UINT32    TrafficClass;
  UINT32    HopLimit;
} SYZ_EDK2_IP6_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_IP6_GET_MODE_DATA_PAYLOAD;

typedef struct {
  UINT8     StationAddress[16];
  UINT16    StationPort;
  UINT16    RemotePort;
  UINT8     RemoteAddress[16];
  UINT8     AcceptPromiscuous;
  UINT8     AcceptAnyPort;
  UINT8     AllowDuplicatePort;
  UINT8     UseDefaultAddress;
} SYZ_EDK2_UDP6_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_UDP6_GET_MODE_DATA_PAYLOAD;

typedef struct {
  UINT8     StationAddress[16];
  UINT16    StationPort;
  UINT16    RemotePort;
  UINT8     RemoteAddress[16];
  UINT8     ActiveFlag;
  UINT8     Pad0;
  UINT16    Pad1;
} SYZ_EDK2_TCP6_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TCP6_GET_MODE_DATA_PAYLOAD;

typedef struct {
  UINT32    IaType;
  UINT32    OptionCount;
} SYZ_EDK2_DHCP6_CONFIGURE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_DHCP6_GET_MODE_DATA_PAYLOAD;

typedef struct {
  UINT32    EnableDnsCache;
  UINT32    Protocol;
  UINT8     StationIp[4];
  UINT8     SubnetMask[4];
  UINT16    LocalPort;
  UINT16    Pad0;
} SYZ_EDK2_DNS4_CONFIGURE_PAYLOAD;

typedef struct {
  UINT16    HostNameSize;     ///< bytes of CHAR16 host name
  UINT16    Pad0;
  // CHAR16 HostName[HostNameSize / 2];
} SYZ_EDK2_DNS4_HOST_NAME_TO_IP_PAYLOAD;

typedef struct {
  UINT32    EnableDnsCache;
  UINT32    Protocol;
  UINT8     StationIp[16];
  UINT16    LocalPort;
  UINT16    Pad0;
} SYZ_EDK2_DNS6_CONFIGURE_PAYLOAD;

typedef struct {
  UINT16    HostNameSize;
  UINT16    Pad0;
  // CHAR16 HostName[HostNameSize / 2];
} SYZ_EDK2_DNS6_HOST_NAME_TO_IP_PAYLOAD;

typedef struct {
  UINT16    FilenameSize;     ///< bytes of CHAR8 filename
  UINT16    Pad0;
  UINT32    DstIndex;         ///< alloc slot for read buffer
  UINT32    DstSize;
  // CHAR8  Filename[FilenameSize];
} SYZ_EDK2_MTFTP4_READ_FILE_PAYLOAD;

typedef struct {
  UINT16    FilenameSize;
  UINT16    Pad0;
  // CHAR8  Filename[FilenameSize];
} SYZ_EDK2_MTFTP4_GET_INFO_PAYLOAD;

// ======================================================================
// HTTP
// ======================================================================

typedef struct {
  UINT32    HttpVersion;       ///< 0=1.0, 1=1.1, 2=2.0
  UINT32    TimeoutMs;
  UINT8     UseHttps;
  UINT8     IsIPv6;
  UINT16    LocalPort;
  UINT8     LocalAddress[16];
} SYZ_EDK2_HTTP_CONFIGURE_PAYLOAD;

typedef struct {
  UINT32    Method;            ///< EFI_HTTP_METHOD enum
  UINT16    UrlSize;           ///< bytes of CHAR16 URL
  UINT16    HeaderCount;
  UINT32    DataIndex;         ///< alloc slot with body
  UINT32    DataLength;
  // CHAR16 Url[UrlSize / 2];
} SYZ_EDK2_HTTP_REQUEST_PAYLOAD;

typedef struct {
  UINT32    DataIndex;         ///< alloc slot for body
  UINT32    DataLength;
} SYZ_EDK2_HTTP_RESPONSE_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_HTTP_POLL_PAYLOAD;

// ======================================================================
// Crypto / Security
// ======================================================================

typedef struct {
  UINT32    Algorithm;         ///< 0=sha1, 1=sha256, 2=sha384, 3=sha512
} SYZ_EDK2_HASH2_GET_HASH_SIZE_PAYLOAD;

typedef struct {
  UINT32    Algorithm;
  UINT32    DataIndex;         ///< alloc slot with input
  UINT32    DataLength;
  UINT32    DstIndex;          ///< alloc slot for output
} SYZ_EDK2_HASH2_HASH_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_RNG_GET_INFO_PAYLOAD;

typedef struct {
  UINT32    DstIndex;          ///< alloc slot for random bytes
  UINT32    NumBytes;
} SYZ_EDK2_RNG_GET_RNG_PAYLOAD;

typedef struct {
  UINT64    Cookie;
} SYZ_EDK2_TCG2_GET_CAPABILITY_PAYLOAD;

typedef struct {
  UINT32    Flags;
  UINT32    DataIndex;         ///< alloc slot with event data
  UINT32    DataLength;
  UINT32    EventType;
  UINT32    PcrIndex;
} SYZ_EDK2_TCG2_HASH_LOG_EXTEND_EVENT_PAYLOAD;

typedef struct {
  UINT32    DataIndex;         ///< alloc slot with TPM command
  UINT32    DataLength;
  UINT32    DstIndex;          ///< alloc slot for response
  UINT32    DstLength;
} SYZ_EDK2_TCG2_SUBMIT_COMMAND_PAYLOAD;

typedef struct {
  UINT32    EventLogFormat;    ///< 0=TCG1.2, 1=TCG2
} SYZ_EDK2_TCG2_GET_EVENT_LOG_PAYLOAD;

typedef struct {
  UINT32    SignedDataIndex;   ///< alloc slot with signed content
  UINT32    SignedDataLength;
  UINT32    SignatureIndex;    ///< alloc slot with signature
  UINT32    SignatureLength;
  UINT32    InDataIndex;       ///< alloc slot with input data
  UINT32    InDataLength;
} SYZ_EDK2_PKCS7_VERIFY_PAYLOAD;

// ======================================================================
// Storage passthrough
// ======================================================================

typedef struct {
  UINT16    Port;
  UINT16    PortMultiplierPort;
  UINT32    Protocol;          ///< ATA_PASS_THRU_PROTOCOL_*
  UINT8     Cdb[16];
  UINT32    InTransferLength;
  UINT32    OutTransferLength;
  UINT32    InBufferIndex;     ///< alloc slot
  UINT32    OutBufferIndex;
} SYZ_EDK2_ATA_PASSTHRU_PAYLOAD;

typedef struct {
  UINT16    Port;
  UINT16    Pad0;
} SYZ_EDK2_ATA_GET_NEXT_DEV_PAYLOAD;

typedef struct {
  UINT8     Target[16];
  UINT64    Lun;
  UINT32    DataDirection;
  UINT32    CdbLength;
  UINT8     Cdb[16];
  UINT32    InTransferLength;
  UINT32    OutTransferLength;
  UINT32    InBufferIndex;
  UINT32    OutBufferIndex;
} SYZ_EDK2_EXT_SCSI_PASSTHRU_PAYLOAD;

typedef struct {
  UINT8     PrevTarget[16];
} SYZ_EDK2_EXT_SCSI_GET_NEXT_DEV_PAYLOAD;

typedef struct {
  UINT32    NamespaceId;
  UINT32    QueueType;
  UINT32    Opcode;
  UINT32    Flags;
  UINT32    CdwArr[6];
  UINT32    TransferLength;
  UINT32    DataIndex;
} SYZ_EDK2_NVME_PASSTHRU_PAYLOAD;

typedef struct {
  UINT32    PrevNamespaceId;
} SYZ_EDK2_NVME_GET_NEXT_NS_PAYLOAD;

// ======================================================================
// Boot dispatcher
// ======================================================================

typedef struct {
  UINT8     BootPolicy;
  UINT8     Pad0;
  UINT16    Pad1;
  UINT32    DataIndex;         ///< alloc slot with PE/COFF image
  UINT32    DataLength;
} SYZ_EDK2_LOAD_IMAGE_PAYLOAD;

typedef struct {
  UINT32    ImageHandleIndex;  ///< slot in gSyzEdk2Agent.ImageHandles
} SYZ_EDK2_START_IMAGE_PAYLOAD;

typedef struct {
  UINT32    ImageHandleIndex;
} SYZ_EDK2_UNLOAD_IMAGE_PAYLOAD;

typedef struct {
  UINT32    ProtocolId;        ///< SYZ_EDK2_PROTO_ID to look up controller handle
  UINT8     Recursive;
  UINT8     Pad0;
  UINT16    Pad1;
} SYZ_EDK2_CONNECT_CONTROLLER_PAYLOAD;

typedef struct {
  UINT32    ProtocolId;
} SYZ_EDK2_DISCONNECT_CONTROLLER_PAYLOAD;

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
  EFI_FILE_PROTOCOL     *Handle;
} SYZ_EDK2_FILE_SLOT;

#define SYZ_EDK2_MAX_IMAGE_HANDLES  8U

typedef struct {
  EFI_HANDLE  Handle;
} SYZ_EDK2_IMAGE_SLOT;

typedef struct {
  VOID                  *SharedBase;
  UINTN                 SharedSize;
  UINT32                LastSeq;
  SYZ_EDK2_ALLOC_SLOT   Allocs[SYZ_EDK2_MAX_ALLOCS];
  SYZ_EDK2_HII_SLOT     HiiHandles[SYZ_EDK2_MAX_HII_HANDLES];
  SYZ_EDK2_EVENT_SLOT   Events[SYZ_EDK2_MAX_EVENTS];
  SYZ_EDK2_FILE_SLOT    FileHandles[SYZ_EDK2_MAX_FILE_HANDLES];
  EFI_FILE_PROTOCOL     *RootFile;   ///< root directory opened by SimpleFs
  SYZ_EDK2_IMAGE_SLOT   ImageHandles[SYZ_EDK2_MAX_IMAGE_HANDLES];
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

//
// SyzFwfuzzTrigger.c — trigger shim for qemu-fwfuzz snapshot fuzzing.
// SyzFwfuzzRegister() installs a configuration table with the input
// buffer physical address and symbols. SyzFwfuzzTrigger() is the
// static-PC entry point the fwsnap plugin snapshots at.
//
VOID
EFIAPI
SyzFwfuzzRegister (
  VOID
  );

VOID
EFIAPI
SyzFwfuzzTrigger (
  VOID
  );

#endif // SYZ_AGENT_DXE_H_

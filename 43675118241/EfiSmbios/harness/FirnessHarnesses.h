#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#ifndef NULL
#define NULL ((VOID *) 0)
#endif

__attribute__((weak)) VOID AsanSetFuzzingActive(BOOLEAN Active)
{
    (VOID)Active;
}
__attribute__((weak)) VOID AsanSetRegionChecks(BOOLEAN Active)
{
    (VOID)Active;
}
__attribute__((weak)) VOID AsanRegisterUntrusted(UINT64 Base, UINT64 Size)
{
    (VOID)Base;
    (VOID)Size;
}
static inline VOID FirnessUntrusted(VOID *Buffer, UINTN Size)
{
    if ((Buffer != NULL) && (AsanRegisterUntrusted != NULL)) {
        AsanRegisterUntrusted((UINT64)(UINTN)Buffer, (UINT64)Size);
    }
}
static VOID FirnessMarkFuzzStart(VOID)
{
    STATIC BOOLEAN Announced = FALSE;
    STATIC CONST CHAR8 Marker[] = "FIRNESS: fuzzing starts\n";
    UINTN Index;

    if (Announced) {
        return;
    }
    Announced = TRUE;
    for (Index = 0; Marker[Index] != 0; Index++) {
        __asm__ __volatile__ ("outb %%al, %%dx"
                              :: "a" (Marker[Index]), "d" ((UINT16)0x3F8));
    }
}
static inline VOID FirnessReportInput(CONST UINT8 *Bytes, UINTN Length)
{
    STATIC CONST CHAR8 Hex[] = "0123456789abcdef";
    CHAR8 Line[32];
    UINTN At = 0;
    UINTN Index;

    Line[At++] = 'I'; Line[At++] = 'N'; Line[At++] = '=';
    for (Index = 4; Index > 0; Index--) {
        Line[At++] = Hex[(Length >> ((Index - 1) * 4)) & 0xF];
    }
    Line[At++] = ':';
    for (Index = 0; Index < 6; Index++) {
        UINT8 Value = (Index < Length) ? Bytes[Index] : 0;
        Line[At++] = Hex[(Value >> 4) & 0xF];
        Line[At++] = Hex[Value & 0xF];
    }
    Line[At++] = '\n';

    for (Index = 0; Index < At; Index++) {
        __asm__ __volatile__ ("outb %%al, %%dx"
                              :: "a" (Line[Index]), "d" ((UINT16)0x3F8));
    }
}
static inline VOID FirnessSanitizer(BOOLEAN Active)
{
    if (Active) {
        FirnessMarkFuzzStart();
    }
    if (AsanSetFuzzingActive != NULL) {
        AsanSetFuzzingActive(Active);
    }
    if (AsanSetRegionChecks != NULL) {
        AsanSetRegionChecks(Active);
    }
    if (!Active && (AsanRegisterUntrusted != NULL)) {
        AsanRegisterUntrusted(0, 0);
    }
}

extern EFI_GUID gEfiSmbiosProtocolGuid;

EFI_STATUS
EFIAPI
FuzzGetNext(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzAdd(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzUpdateString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzRemove(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__

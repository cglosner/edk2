#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_FONT_DISPLAY_INFO * FirnessLive_EFI_FONT_DISPLAY_INFO__[4];
UINTN FirnessLive_EFI_FONT_DISPLAY_INFO___Count = 0;
EFI_IMAGE_OUTPUT * FirnessLive_EFI_IMAGE_OUTPUT__[4];
UINTN FirnessLive_EFI_IMAGE_OUTPUT___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called StringToImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStringToImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_OUT_FLAGS StringToImage_Arg_1 = {0};
    CHAR16 * StringToImage_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_FONT_DISPLAY_INFO * StringToImage_Arg_3 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    EFI_IMAGE_OUTPUT * StringToImage_Arg_4 = NULL;
    UINTN StringToImage_Arg_5 = {0};
    UINTN StringToImage_Arg_6 = {0};
    
    UINT8* StringToImage_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_1_choice), (VOID *)StringToImage_Arg_1_choice);
    switch(*StringToImage_Arg_1_choice % 2) {
        case 0:
        {
        // Constant Variable Initialization
        StringToImage_Arg_1 = EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_DIRECT_TO_SCREEN | EFI_HII_IGNORE_LINE_BREAK;
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(StringToImage_Arg_1), (VOID *)&StringToImage_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 StringToImage_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_2_choice), (VOID *)&StringToImage_Arg_2_choice);
    switch(StringToImage_Arg_2_choice % 1) {
        case 0:
            if (StringToImage_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StringToImage_Arg_2), (VOID *)StringToImage_Arg_2);
                StringToImage_Arg_2[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_3->ForegroundColor), (VOID *)&(StringToImage_Arg_3->ForegroundColor));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->BackgroundColor), (VOID *)&(StringToImage_Arg_3->BackgroundColor));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->FontInfoMask), (VOID *)&(StringToImage_Arg_3->FontInfoMask));
    ReadBytes(Input, sizeof(StringToImage_Arg_3->FontInfo), (VOID *)&(StringToImage_Arg_3->FontInfo));
    
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_5), (VOID *)&StringToImage_Arg_5);
    StringToImage_Arg_5 = StringToImage_Arg_5 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringToImage_Arg_6), (VOID *)&StringToImage_Arg_6);
    StringToImage_Arg_6 = StringToImage_Arg_6 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringToImage_Arg_7 = NULL;
    UINT8* StringToImage_Arg_7_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_7_OutputChoice), (VOID *)StringToImage_Arg_7_OutputChoice);
    if(*StringToImage_Arg_7_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_7), (VOID *)StringToImage_Arg_7);
    }
    UINTN * StringToImage_Arg_8 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringToImage_Arg_8_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_8_OutputChoice), (VOID *)StringToImage_Arg_8_OutputChoice);
    if(*StringToImage_Arg_8_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_8), (VOID *)StringToImage_Arg_8);
    }
    UINTN * StringToImage_Arg_9 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringToImage_Arg_9_OutputChoice), (VOID *)StringToImage_Arg_9_OutputChoice);
    if(*StringToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringToImage_Arg_9), (VOID *)StringToImage_Arg_9);
    }
    UINT8 StringToImage_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_3_LiveChoice), (VOID *)&StringToImage_Arg_3_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (StringToImage_Arg_3_LiveChoice & 1)) {
        StringToImage_Arg_3 = FirnessLive_EFI_FONT_DISPLAY_INFO__[StringToImage_Arg_3_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    UINT8 StringToImage_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringToImage_Arg_4_LiveChoice), (VOID *)&StringToImage_Arg_4_LiveChoice);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count > 0 && (StringToImage_Arg_4_LiveChoice & 1)) {
        StringToImage_Arg_4 = FirnessLive_EFI_IMAGE_OUTPUT__[StringToImage_Arg_4_LiveChoice % FirnessLive_EFI_IMAGE_OUTPUT___Count];
    }
    FirnessUntrusted(StringToImage_Arg_2, 4096);
    FirnessUntrusted(StringToImage_Arg_3, 4096);
    FirnessUntrusted(StringToImage_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->StringToImage(
        ProtocolVariable,
        StringToImage_Arg_1,
        StringToImage_Arg_2,
        StringToImage_Arg_3,
        (EFI_IMAGE_OUTPUT **)&StringToImage_Arg_4,
        StringToImage_Arg_5,
        StringToImage_Arg_6,
        (EFI_HII_ROW_INFO **)&StringToImage_Arg_7,
        StringToImage_Arg_8,
        StringToImage_Arg_9
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count < 4 && StringToImage_Arg_4 != NULL) {
        FirnessLive_EFI_IMAGE_OUTPUT__[FirnessLive_EFI_IMAGE_OUTPUT___Count++] = StringToImage_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetGlyph.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetGlyph(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 GetGlyph_Arg_1 = {0};
    EFI_FONT_DISPLAY_INFO * GetGlyph_Arg_2 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetGlyph_Arg_1), (VOID *)&GetGlyph_Arg_1);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->ForegroundColor), (VOID *)&(GetGlyph_Arg_2->ForegroundColor));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->BackgroundColor), (VOID *)&(GetGlyph_Arg_2->BackgroundColor));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->FontInfoMask), (VOID *)&(GetGlyph_Arg_2->FontInfoMask));
    ReadBytes(Input, sizeof(GetGlyph_Arg_2->FontInfo), (VOID *)&(GetGlyph_Arg_2->FontInfo));
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_OUTPUT * GetGlyph_Arg_3 = NULL;
    UINT8* GetGlyph_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGlyph_Arg_3_OutputChoice), (VOID *)GetGlyph_Arg_3_OutputChoice);
    if(*GetGlyph_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_3), (VOID *)GetGlyph_Arg_3);
    }
    UINTN * GetGlyph_Arg_4 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetGlyph_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetGlyph_Arg_4_OutputChoice), (VOID *)GetGlyph_Arg_4_OutputChoice);
    if(*GetGlyph_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetGlyph_Arg_4), (VOID *)GetGlyph_Arg_4);
    }
    UINT8 GetGlyph_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetGlyph_Arg_2_LiveChoice), (VOID *)&GetGlyph_Arg_2_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (GetGlyph_Arg_2_LiveChoice & 1)) {
        GetGlyph_Arg_2 = FirnessLive_EFI_FONT_DISPLAY_INFO__[GetGlyph_Arg_2_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessUntrusted(GetGlyph_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetGlyph(
        ProtocolVariable,
        GetGlyph_Arg_1,
        GetGlyph_Arg_2,
        (EFI_IMAGE_OUTPUT **)&GetGlyph_Arg_3,
        GetGlyph_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_IMAGE_OUTPUT___Count < 4 && GetGlyph_Arg_3 != NULL) {
        FirnessLive_EFI_IMAGE_OUTPUT__[FirnessLive_EFI_IMAGE_OUTPUT___Count++] = GetGlyph_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StringIdToImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStringIdToImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_OUT_FLAGS StringIdToImage_Arg_1 = {0};
    EFI_HII_HANDLE StringIdToImage_Arg_2 = {0};
    EFI_STRING_ID StringIdToImage_Arg_3 = {0};
    CHAR8 * StringIdToImage_Arg_4 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_FONT_DISPLAY_INFO * StringIdToImage_Arg_5 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    UINTN StringIdToImage_Arg_7 = {0};
    UINTN StringIdToImage_Arg_8 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_1), (VOID *)&StringIdToImage_Arg_1);
    
    UINT8* StringIdToImage_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_2_choice), (VOID *)StringIdToImage_Arg_2_choice);
    switch(*StringIdToImage_Arg_2_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_3), (VOID *)&StringIdToImage_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 StringIdToImage_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(StringIdToImage_Arg_4_choice), (VOID *)&StringIdToImage_Arg_4_choice);
    switch(StringIdToImage_Arg_4_choice % 1) {
        case 0:
            if (StringIdToImage_Arg_4 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StringIdToImage_Arg_4), (VOID *)StringIdToImage_Arg_4);
                StringIdToImage_Arg_4[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->ForegroundColor), (VOID *)&(StringIdToImage_Arg_5->ForegroundColor));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->BackgroundColor), (VOID *)&(StringIdToImage_Arg_5->BackgroundColor));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->FontInfoMask), (VOID *)&(StringIdToImage_Arg_5->FontInfoMask));
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5->FontInfo), (VOID *)&(StringIdToImage_Arg_5->FontInfo));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_7), (VOID *)&StringIdToImage_Arg_7);
    StringIdToImage_Arg_7 = StringIdToImage_Arg_7 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StringIdToImage_Arg_8), (VOID *)&StringIdToImage_Arg_8);
    StringIdToImage_Arg_8 = StringIdToImage_Arg_8 % (4096 + 1);
    
    /*
        Output Variable(s)
    */
    EFI_HII_ROW_INFO * StringIdToImage_Arg_9 = NULL;
    UINT8* StringIdToImage_Arg_9_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_9_OutputChoice), (VOID *)StringIdToImage_Arg_9_OutputChoice);
    if(*StringIdToImage_Arg_9_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_9), (VOID *)StringIdToImage_Arg_9);
    }
    UINTN * StringIdToImage_Arg_10 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringIdToImage_Arg_10_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_10_OutputChoice), (VOID *)StringIdToImage_Arg_10_OutputChoice);
    if(*StringIdToImage_Arg_10_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_10), (VOID *)StringIdToImage_Arg_10);
    }
    UINTN * StringIdToImage_Arg_11 = (UINTN *)AllocateZeroPool(4096);
    UINT8* StringIdToImage_Arg_11_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StringIdToImage_Arg_11_OutputChoice), (VOID *)StringIdToImage_Arg_11_OutputChoice);
    if(*StringIdToImage_Arg_11_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StringIdToImage_Arg_11), (VOID *)StringIdToImage_Arg_11);
    }
    VOID *StringIdToImage_Arg_6 = AllocateZeroPool(4096);
    UINT8 StringIdToImage_Arg_5_LiveChoice = 0;
    ReadBytes(Input, sizeof(StringIdToImage_Arg_5_LiveChoice), (VOID *)&StringIdToImage_Arg_5_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (StringIdToImage_Arg_5_LiveChoice & 1)) {
        StringIdToImage_Arg_5 = FirnessLive_EFI_FONT_DISPLAY_INFO__[StringIdToImage_Arg_5_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessUntrusted(StringIdToImage_Arg_4, 4096);
    FirnessUntrusted(StringIdToImage_Arg_5, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->StringIdToImage(
        ProtocolVariable,
        StringIdToImage_Arg_1,
        StringIdToImage_Arg_2,
        StringIdToImage_Arg_3,
        StringIdToImage_Arg_4,
        StringIdToImage_Arg_5,
        StringIdToImage_Arg_6,
        StringIdToImage_Arg_7,
        StringIdToImage_Arg_8,
        (EFI_HII_ROW_INFO **)&StringIdToImage_Arg_9,
        StringIdToImage_Arg_10,
        StringIdToImage_Arg_11
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetFontInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetFontInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_FONT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiFontProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_FONT_DISPLAY_INFO * GetFontInfo_Arg_2 = (EFI_FONT_DISPLAY_INFO *)AllocateZeroPool(sizeof(EFI_FONT_DISPLAY_INFO));
    EFI_STRING GetFontInfo_Arg_4 = {0};
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->ForegroundColor), (VOID *)&(GetFontInfo_Arg_2->ForegroundColor));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->BackgroundColor), (VOID *)&(GetFontInfo_Arg_2->BackgroundColor));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->FontInfoMask), (VOID *)&(GetFontInfo_Arg_2->FontInfoMask));
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2->FontInfo), (VOID *)&(GetFontInfo_Arg_2->FontInfo));
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    /*
        Output Variable(s)
    */
    EFI_FONT_DISPLAY_INFO * GetFontInfo_Arg_3 = NULL;
    UINT8* GetFontInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetFontInfo_Arg_3_OutputChoice), (VOID *)GetFontInfo_Arg_3_OutputChoice);
    if(*GetFontInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetFontInfo_Arg_3), (VOID *)GetFontInfo_Arg_3);
    }
    VOID *GetFontInfo_Arg_1 = AllocateZeroPool(4096);
    UINT8 GetFontInfo_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetFontInfo_Arg_2_LiveChoice), (VOID *)&GetFontInfo_Arg_2_LiveChoice);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count > 0 && (GetFontInfo_Arg_2_LiveChoice & 1)) {
        GetFontInfo_Arg_2 = FirnessLive_EFI_FONT_DISPLAY_INFO__[GetFontInfo_Arg_2_LiveChoice % FirnessLive_EFI_FONT_DISPLAY_INFO___Count];
    }
    FirnessUntrusted(GetFontInfo_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetFontInfo(
        ProtocolVariable,
        GetFontInfo_Arg_1,
        GetFontInfo_Arg_2,
        (EFI_FONT_DISPLAY_INFO **)&GetFontInfo_Arg_3,
        GetFontInfo_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_FONT_DISPLAY_INFO___Count < 4 && GetFontInfo_Arg_3 != NULL) {
        FirnessLive_EFI_FONT_DISPLAY_INFO__[FirnessLive_EFI_FONT_DISPLAY_INFO___Count++] = GetFontInfo_Arg_3;
    }
    return Status;
}


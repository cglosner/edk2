#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CHAR8 * FirnessLive_CHAR8__[4];
UINTN FirnessLive_CHAR8___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called NewString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE NewString_Arg_1 = {0};
    EFI_STRING_ID * NewString_Arg_2 = (EFI_STRING_ID *)AllocateZeroPool(sizeof(EFI_STRING_ID));
    CHAR8 * NewString_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    CHAR16 * NewString_Arg_4 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_STRING NewString_Arg_5 = {0};
    EFI_FONT_INFO * NewString_Arg_6 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 NewString_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_2_choice), (VOID *)&NewString_Arg_2_choice);
    switch(NewString_Arg_2_choice % 1) {
        case 0:
            if (NewString_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*NewString_Arg_2), (VOID *)NewString_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 NewString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_3_choice), (VOID *)&NewString_Arg_3_choice);
    switch(NewString_Arg_3_choice % 1) {
        case 0:
            if (NewString_Arg_3 != NULL) {
                ReadBytes(Input, 31 * sizeof(*NewString_Arg_3), (VOID *)NewString_Arg_3);
                NewString_Arg_3[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 NewString_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(NewString_Arg_4_choice), (VOID *)&NewString_Arg_4_choice);
    switch(NewString_Arg_4_choice % 2) {
        case 0:
            if (NewString_Arg_4 != NULL) {
                ReadBytes(Input, 31 * sizeof(*NewString_Arg_4), (VOID *)NewString_Arg_4);
                NewString_Arg_4[31] = 0;
            }
            break;
        case 1:
        {
            gBS->FreePool(NewString_Arg_4);
            NewString_Arg_4 = NULL;
            break;
        }
    }
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(NewString_Arg_6->FontStyle), (VOID *)&(NewString_Arg_6->FontStyle));
    NewString_Arg_6->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(NewString_Arg_6->FontName), (VOID *)&(NewString_Arg_6->FontName));
    
    FirnessUntrusted(NewString_Arg_2, 4096);
    FirnessUntrusted(NewString_Arg_3, 4096);
    FirnessUntrusted(NewString_Arg_4, 4096);
    FirnessUntrusted(NewString_Arg_6, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->NewString(
        ProtocolVariable,
        NewString_Arg_1,
        NewString_Arg_2,
        NewString_Arg_3,
        NewString_Arg_4,
        NewString_Arg_5,
        NewString_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE SetString_Arg_1 = {0};
    EFI_STRING_ID SetString_Arg_2 = {0};
    CHAR8 * SetString_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_STRING SetString_Arg_4 = {0};
    EFI_FONT_INFO * SetString_Arg_5 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_2), (VOID *)&SetString_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 SetString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetString_Arg_3_choice), (VOID *)&SetString_Arg_3_choice);
    switch(SetString_Arg_3_choice % 1) {
        case 0:
            if (SetString_Arg_3 != NULL) {
                ReadBytes(Input, 31 * sizeof(*SetString_Arg_3), (VOID *)SetString_Arg_3);
                SetString_Arg_3[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(SetString_Arg_5->FontStyle), (VOID *)&(SetString_Arg_5->FontStyle));
    SetString_Arg_5->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(SetString_Arg_5->FontName), (VOID *)&(SetString_Arg_5->FontName));
    
    FirnessUntrusted(SetString_Arg_3, 4096);
    FirnessUntrusted(SetString_Arg_5, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetString(
        ProtocolVariable,
        SetString_Arg_1,
        SetString_Arg_2,
        SetString_Arg_3,
        SetString_Arg_4,
        SetString_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR8 * GetString_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    EFI_HII_HANDLE GetString_Arg_2 = {0};
    EFI_STRING_ID GetString_Arg_3 = {0};
    CHAR16 * GetString_Arg_4 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINTN * GetString_Arg_5 = (UINTN *)AllocateZeroPool(4096);
    EFI_FONT_INFO * GetString_Arg_6 = (EFI_FONT_INFO *)AllocateZeroPool(sizeof(EFI_FONT_INFO));
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_1_choice), (VOID *)&GetString_Arg_1_choice);
    switch(GetString_Arg_1_choice % 1) {
        case 0:
            if (GetString_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetString_Arg_1), (VOID *)GetString_Arg_1);
                GetString_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_3), (VOID *)&GetString_Arg_3);
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_4_choice), (VOID *)&GetString_Arg_4_choice);
    switch(GetString_Arg_4_choice % 1) {
        case 0:
            if (GetString_Arg_4 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetString_Arg_4), (VOID *)GetString_Arg_4);
                GetString_Arg_4[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetString_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(GetString_Arg_5_choice), (VOID *)&GetString_Arg_5_choice);
    switch(GetString_Arg_5_choice % 1) {
        case 0:
            if (GetString_Arg_5 != NULL) {
                ReadBytes(Input, sizeof(*GetString_Arg_5), (VOID *)GetString_Arg_5);
                *GetString_Arg_5 = *GetString_Arg_5 % ((32 * sizeof(CHAR16)) + 1);
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(GetString_Arg_6->FontStyle), (VOID *)&(GetString_Arg_6->FontStyle));
    GetString_Arg_6->FontSize = sizeof(EFI_FONT_INFO);
    ReadBytes(Input, sizeof(GetString_Arg_6->FontName), (VOID *)&(GetString_Arg_6->FontName));
    
    FirnessUntrusted(GetString_Arg_1, 4096);
    FirnessUntrusted(GetString_Arg_4, 4096);
    FirnessUntrusted(GetString_Arg_5, 4096);
    FirnessUntrusted(GetString_Arg_6, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetString(
        ProtocolVariable,
        GetString_Arg_1,
        GetString_Arg_2,
        GetString_Arg_3,
        GetString_Arg_4,
        GetString_Arg_5,
        (EFI_FONT_INFO **)&GetString_Arg_6
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && GetString_Arg_5 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetString_Arg_5;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetLanguages.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetLanguages(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetLanguages_Arg_1 = {0};
    CHAR8 * GetLanguages_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    UINTN * GetLanguages_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 GetLanguages_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_2_choice), (VOID *)&GetLanguages_Arg_2_choice);
    switch(GetLanguages_Arg_2_choice % 1) {
        case 0:
            if (GetLanguages_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetLanguages_Arg_2), (VOID *)GetLanguages_Arg_2);
                GetLanguages_Arg_2[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetLanguages_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetLanguages_Arg_3_choice), (VOID *)&GetLanguages_Arg_3_choice);
    switch(GetLanguages_Arg_3_choice % 1) {
        case 0:
            if (GetLanguages_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*GetLanguages_Arg_3), (VOID *)GetLanguages_Arg_3);
                *GetLanguages_Arg_3 = *GetLanguages_Arg_3 % ((32 * sizeof(CHAR8)) + 1);
            }
            break;
    }
    
    FirnessUntrusted(GetLanguages_Arg_2, 4096);
    FirnessUntrusted(GetLanguages_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetLanguages(
        ProtocolVariable,
        GetLanguages_Arg_1,
        GetLanguages_Arg_2,
        GetLanguages_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetSecondaryLanguages.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSecondaryLanguages(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_STRING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiStringProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetSecondaryLanguages_Arg_1 = {0};
    CHAR8 * GetSecondaryLanguages_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    CHAR8 * GetSecondaryLanguages_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    UINTN * GetSecondaryLanguages_Arg_4 = (UINTN *)AllocateZeroPool(4096);
    
    UINT8* GetSecondaryLanguages_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetSecondaryLanguages_Arg_1_choice), (VOID *)GetSecondaryLanguages_Arg_1_choice);
    switch(*GetSecondaryLanguages_Arg_1_choice % 2) {
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
    UINT8 GetSecondaryLanguages_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_2_choice), (VOID *)&GetSecondaryLanguages_Arg_2_choice);
    switch(GetSecondaryLanguages_Arg_2_choice % 1) {
        case 0:
            if (GetSecondaryLanguages_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetSecondaryLanguages_Arg_2), (VOID *)GetSecondaryLanguages_Arg_2);
                GetSecondaryLanguages_Arg_2[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSecondaryLanguages_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_3_choice), (VOID *)&GetSecondaryLanguages_Arg_3_choice);
    switch(GetSecondaryLanguages_Arg_3_choice % 1) {
        case 0:
            if (GetSecondaryLanguages_Arg_3 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetSecondaryLanguages_Arg_3), (VOID *)GetSecondaryLanguages_Arg_3);
                GetSecondaryLanguages_Arg_3[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetSecondaryLanguages_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetSecondaryLanguages_Arg_4_choice), (VOID *)&GetSecondaryLanguages_Arg_4_choice);
    switch(GetSecondaryLanguages_Arg_4_choice % 1) {
        case 0:
            if (GetSecondaryLanguages_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*GetSecondaryLanguages_Arg_4), (VOID *)GetSecondaryLanguages_Arg_4);
                *GetSecondaryLanguages_Arg_4 = *GetSecondaryLanguages_Arg_4 % ((32 * sizeof(CHAR8)) + 1);
            }
            break;
    }
    
    FirnessUntrusted(GetSecondaryLanguages_Arg_2, 4096);
    FirnessUntrusted(GetSecondaryLanguages_Arg_3, 4096);
    FirnessUntrusted(GetSecondaryLanguages_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetSecondaryLanguages(
        ProtocolVariable,
        GetSecondaryLanguages_Arg_1,
        GetSecondaryLanguages_Arg_2,
        GetSecondaryLanguages_Arg_3,
        GetSecondaryLanguages_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR8___Count < 4 && GetSecondaryLanguages_Arg_3 != NULL) {
        FirnessLive_CHAR8__[FirnessLive_CHAR8___Count++] = GetSecondaryLanguages_Arg_3;
    }
    if (FirnessLive_UINTN___Count < 4 && GetSecondaryLanguages_Arg_4 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetSecondaryLanguages_Arg_4;
    }
    return Status;
}


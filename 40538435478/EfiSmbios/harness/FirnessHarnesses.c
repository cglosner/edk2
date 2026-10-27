#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_SMBIOS_HANDLE * FirnessLive_EFI_SMBIOS_HANDLE__[4];
UINTN FirnessLive_EFI_SMBIOS_HANDLE___Count = 0;
EFI_SMBIOS_TABLE_HEADER * FirnessLive_EFI_SMBIOS_TABLE_HEADER__[4];
UINTN FirnessLive_EFI_SMBIOS_TABLE_HEADER___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called GetNext.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNext(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE * GetNext_Arg_1 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    EFI_SMBIOS_TYPE * GetNext_Arg_2 = (EFI_SMBIOS_TYPE *)AllocateZeroPool(sizeof(EFI_SMBIOS_TYPE));
    
    // Fuzzable Variable Initialization
    UINT8 GetNext_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_1_choice), (VOID *)&GetNext_Arg_1_choice);
    switch(GetNext_Arg_1_choice % 1) {
        case 0:
            if (GetNext_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetNext_Arg_1), (VOID *)GetNext_Arg_1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetNext_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_2_choice), (VOID *)&GetNext_Arg_2_choice);
    switch(GetNext_Arg_2_choice % 1) {
        case 0:
            if (GetNext_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*GetNext_Arg_2), (VOID *)GetNext_Arg_2);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_SMBIOS_TABLE_HEADER * GetNext_Arg_3 = NULL;
    UINT8* GetNext_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetNext_Arg_3_OutputChoice), (VOID *)GetNext_Arg_3_OutputChoice);
    if(*GetNext_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNext_Arg_3), (VOID *)GetNext_Arg_3);
    }
    EFI_HANDLE * GetNext_Arg_4 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* GetNext_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetNext_Arg_4_OutputChoice), (VOID *)GetNext_Arg_4_OutputChoice);
    if(*GetNext_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetNext_Arg_4), (VOID *)GetNext_Arg_4);
    }
    UINT8 GetNext_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetNext_Arg_1_LiveChoice), (VOID *)&GetNext_Arg_1_LiveChoice);
    if (FirnessLive_EFI_SMBIOS_HANDLE___Count > 0 && (GetNext_Arg_1_LiveChoice & 1)) {
        GetNext_Arg_1 = FirnessLive_EFI_SMBIOS_HANDLE__[GetNext_Arg_1_LiveChoice % FirnessLive_EFI_SMBIOS_HANDLE___Count];
    }
    FirnessUntrusted(GetNext_Arg_1, 4096);
    FirnessUntrusted(GetNext_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetNext(
        ProtocolVariable,
        GetNext_Arg_1,
        GetNext_Arg_2,
        (EFI_SMBIOS_TABLE_HEADER **)&GetNext_Arg_3,
        GetNext_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_SMBIOS_HANDLE___Count < 4 && GetNext_Arg_1 != NULL) {
        FirnessLive_EFI_SMBIOS_HANDLE__[FirnessLive_EFI_SMBIOS_HANDLE___Count++] = GetNext_Arg_1;
    }
    if (FirnessLive_EFI_SMBIOS_TABLE_HEADER___Count < 4 && GetNext_Arg_3 != NULL) {
        FirnessLive_EFI_SMBIOS_TABLE_HEADER__[FirnessLive_EFI_SMBIOS_TABLE_HEADER___Count++] = GetNext_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Add.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAdd(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Add_Arg_1 = (UINTN* )AllocateZeroPool(4096);
    EFI_SMBIOS_HANDLE * Add_Arg_2 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    EFI_SMBIOS_TABLE_HEADER * Add_Arg_3 = (EFI_SMBIOS_TABLE_HEADER *)AllocateZeroPool(sizeof(EFI_SMBIOS_TABLE_HEADER));
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_1_choice), (VOID *)&Add_Arg_1_choice);
    switch(Add_Arg_1_choice % 1) {
        case 0:
            if (Add_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*Add_Arg_1), (VOID *)Add_Arg_1);
                *Add_Arg_1 = *Add_Arg_1 % (4096 + 1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Add_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Add_Arg_2_choice), (VOID *)&Add_Arg_2_choice);
    switch(Add_Arg_2_choice % 1) {
        case 0:
            if (Add_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*Add_Arg_2), (VOID *)Add_Arg_2);
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(Add_Arg_3->Type), (VOID *)&(Add_Arg_3->Type));
    Add_Arg_3->Length = sizeof(SMBIOS_STRUCTURE);
    // SMBIOS_HANDLE is a pointer behind an opaque name: left as allocated
    
    UINT8 Add_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(Add_Arg_2_LiveChoice), (VOID *)&Add_Arg_2_LiveChoice);
    if (FirnessLive_EFI_SMBIOS_HANDLE___Count > 0 && (Add_Arg_2_LiveChoice & 1)) {
        Add_Arg_2 = FirnessLive_EFI_SMBIOS_HANDLE__[Add_Arg_2_LiveChoice % FirnessLive_EFI_SMBIOS_HANDLE___Count];
    }
    UINT8 Add_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(Add_Arg_3_LiveChoice), (VOID *)&Add_Arg_3_LiveChoice);
    if (FirnessLive_EFI_SMBIOS_TABLE_HEADER___Count > 0 && (Add_Arg_3_LiveChoice & 1)) {
        Add_Arg_3 = FirnessLive_EFI_SMBIOS_TABLE_HEADER__[Add_Arg_3_LiveChoice % FirnessLive_EFI_SMBIOS_TABLE_HEADER___Count];
    }
    FirnessUntrusted(Add_Arg_1, 4096);
    FirnessUntrusted(Add_Arg_2, 4096);
    FirnessUntrusted(Add_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Add(
        ProtocolVariable,
        (void *)Add_Arg_1,
        Add_Arg_2,
        Add_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_SMBIOS_HANDLE___Count < 4 && Add_Arg_2 != NULL) {
        FirnessLive_EFI_SMBIOS_HANDLE__[FirnessLive_EFI_SMBIOS_HANDLE___Count++] = Add_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdateString.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdateString(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE * UpdateString_Arg_1 = (EFI_SMBIOS_HANDLE *)AllocateZeroPool(sizeof(EFI_SMBIOS_HANDLE));
    UINTN * UpdateString_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    CHAR8 * UpdateString_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_1_choice), (VOID *)&UpdateString_Arg_1_choice);
    switch(UpdateString_Arg_1_choice % 1) {
        case 0:
            if (UpdateString_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*UpdateString_Arg_1), (VOID *)UpdateString_Arg_1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_2_choice), (VOID *)&UpdateString_Arg_2_choice);
    switch(UpdateString_Arg_2_choice % 1) {
        case 0:
            if (UpdateString_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*UpdateString_Arg_2), (VOID *)UpdateString_Arg_2);
                *UpdateString_Arg_2 = *UpdateString_Arg_2 % (4096 + 1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 UpdateString_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_3_choice), (VOID *)&UpdateString_Arg_3_choice);
    switch(UpdateString_Arg_3_choice % 1) {
        case 0:
            if (UpdateString_Arg_3 != NULL) {
                ReadBytes(Input, 31 * sizeof(*UpdateString_Arg_3), (VOID *)UpdateString_Arg_3);
                UpdateString_Arg_3[31] = 0;
            }
            break;
    }
    
    UINT8 UpdateString_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(UpdateString_Arg_1_LiveChoice), (VOID *)&UpdateString_Arg_1_LiveChoice);
    if (FirnessLive_EFI_SMBIOS_HANDLE___Count > 0 && (UpdateString_Arg_1_LiveChoice & 1)) {
        UpdateString_Arg_1 = FirnessLive_EFI_SMBIOS_HANDLE__[UpdateString_Arg_1_LiveChoice % FirnessLive_EFI_SMBIOS_HANDLE___Count];
    }
    FirnessUntrusted(UpdateString_Arg_1, 4096);
    FirnessUntrusted(UpdateString_Arg_2, 4096);
    FirnessUntrusted(UpdateString_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UpdateString(
        ProtocolVariable,
        UpdateString_Arg_1,
        UpdateString_Arg_2,
        UpdateString_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Remove.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemove(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMBIOS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_SMBIOS_HANDLE Remove_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_SMBIOS_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Remove(
        ProtocolVariable,
        Remove_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}


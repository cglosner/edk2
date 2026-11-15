#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called ConvertDeviceNodeToText.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConvertDeviceNodeToText(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * ConvertDeviceNodeToText_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (ConvertDeviceNodeToText_Arg_0, 4096);
    BOOLEAN ConvertDeviceNodeToText_Arg_1 = {0};
    BOOLEAN ConvertDeviceNodeToText_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        ConvertDeviceNodeToText_Arg_0->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        ConvertDeviceNodeToText_Arg_0->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(ConvertDeviceNodeToText_Arg_0->Length), (VOID *)&(ConvertDeviceNodeToText_Arg_0->Length));
    FirnessMakeDevicePath (ConvertDeviceNodeToText_Arg_0, 4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ConvertDeviceNodeToText_Arg_1), (VOID *)&ConvertDeviceNodeToText_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ConvertDeviceNodeToText_Arg_2), (VOID *)&ConvertDeviceNodeToText_Arg_2);
    
    FirnessUntrusted(ConvertDeviceNodeToText_Arg_0, 4096);
    FirnessSanitizer(TRUE);
    ProtocolVariable->ConvertDeviceNodeToText(
        ConvertDeviceNodeToText_Arg_0,
        ConvertDeviceNodeToText_Arg_1,
        ConvertDeviceNodeToText_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ConvertDevicePathToText.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConvertDevicePathToText(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * ConvertDevicePathToText_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (ConvertDevicePathToText_Arg_0, 4096);
    BOOLEAN ConvertDevicePathToText_Arg_1 = {0};
    BOOLEAN ConvertDevicePathToText_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        ConvertDevicePathToText_Arg_0->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        ConvertDevicePathToText_Arg_0->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(ConvertDevicePathToText_Arg_0->Length), (VOID *)&(ConvertDevicePathToText_Arg_0->Length));
    FirnessMakeDevicePath (ConvertDevicePathToText_Arg_0, 4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ConvertDevicePathToText_Arg_1), (VOID *)&ConvertDevicePathToText_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ConvertDevicePathToText_Arg_2), (VOID *)&ConvertDevicePathToText_Arg_2);
    
    FirnessUntrusted(ConvertDevicePathToText_Arg_0, 4096);
    FirnessSanitizer(TRUE);
    ProtocolVariable->ConvertDevicePathToText(
        ConvertDevicePathToText_Arg_0,
        ConvertDevicePathToText_Arg_1,
        ConvertDevicePathToText_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}


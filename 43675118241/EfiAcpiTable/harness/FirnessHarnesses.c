#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called InstallAcpiTable.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzInstallAcpiTable(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_TABLE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  InstallAcpiTable_Arg_1 = (UINTN* )AllocateZeroPool(4096);
    UINTN InstallAcpiTable_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 InstallAcpiTable_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(InstallAcpiTable_Arg_1_choice), (VOID *)&InstallAcpiTable_Arg_1_choice);
    switch(InstallAcpiTable_Arg_1_choice % 1) {
        case 0:
            if (InstallAcpiTable_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*InstallAcpiTable_Arg_1), (VOID *)InstallAcpiTable_Arg_1);
                *InstallAcpiTable_Arg_1 = *InstallAcpiTable_Arg_1 % (4096 + 1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(InstallAcpiTable_Arg_2), (VOID *)&InstallAcpiTable_Arg_2);
    InstallAcpiTable_Arg_2 = InstallAcpiTable_Arg_2 % (4096 + 1);
    if (InstallAcpiTable_Arg_1 != NULL) {
        FreePool(InstallAcpiTable_Arg_1);
    }
    InstallAcpiTable_Arg_1 = (UINTN* )AllocateZeroPool(InstallAcpiTable_Arg_2 > 0 ? InstallAcpiTable_Arg_2 : 1);
    if (InstallAcpiTable_Arg_1 == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    /*
        Output Variable(s)
    */
    UINTN * InstallAcpiTable_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    UINT8* InstallAcpiTable_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*InstallAcpiTable_Arg_3_OutputChoice), (VOID *)InstallAcpiTable_Arg_3_OutputChoice);
    if(*InstallAcpiTable_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*InstallAcpiTable_Arg_3), (VOID *)InstallAcpiTable_Arg_3);
    }
    FirnessUntrusted(InstallAcpiTable_Arg_1, InstallAcpiTable_Arg_2);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->InstallAcpiTable(
        ProtocolVariable,
        (void *)InstallAcpiTable_Arg_1,
        InstallAcpiTable_Arg_2,
        InstallAcpiTable_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UninstallAcpiTable.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUninstallAcpiTable(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_TABLE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN UninstallAcpiTable_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(UninstallAcpiTable_Arg_1), (VOID *)&UninstallAcpiTable_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UninstallAcpiTable(
        ProtocolVariable,
        UninstallAcpiTable_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}


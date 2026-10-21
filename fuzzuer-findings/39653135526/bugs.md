# edk2 6157c2c7d7b9f9d18c5dcc6ab27eff2633abbac4



40 report rows from the campaigns, clustered into 9 distinct sites.

1 further cluster(s) were the harness itself, a library linked into it that the firmware never calls, or code whose reports are inherent to what it does. Run `bug_report.py --show-filtered` to see them with the reason for each.

## Firmware, provoked by an input

Reached because a testcase drove it there. Ordered by severity.

| module | source | location | bug type | hits | reached by | detail |
|---|---|---|---|---|---|---|
| AcpiTableDxe.efi | `asan-outline-instrumentation` | asan-outline-instrumentation:479700441 | heap-buffer-overflow (read) | 1124 | EfiAcpiTable | read of 4 bytes at 0x000000001C78232C input driven, in firmware code |
| SetupBrowser.efi | `fwsan` | fwsan:477185447 | fwsan-double-fetch (read) | 1431 | EdkiiFormBrowserEx | read of 2 bytes at 0x000000001C782328 input driven, in firmware code |
| AcpiTableDxe.efi | `MdePkg/Library/UefiLib/UefiDriverModel.c` | UefiDriverModel.c:731 | [ASan] | 1124 | EfiAcpiTable | ip 0x000000001C97A5D9 input driven, in firmware code |
| DxeCore.efi | `fwsan` | fwsan:482722276 | fwsan-double-fetch (read) | 649 | EfiHiiFont | read of 2 bytes at 0x000000001C86853C input driven, in firmware code |
| HiiDatabase.efi | `fwsan` | fwsan:482645001 | fwsan-double-fetch (read) | 271 | EfiHiiFont | read of 4 bytes at 0x000000001C868530 input driven, in firmware code |
| HiiDatabase.efi | `fwsan` | fwsan:482722565 | fwsan-double-fetch (read) | 198 | EfiHiiFont | read of 2 bytes at 0x000000001C86853A input driven, in firmware code |
| HiiDatabase.efi | `fwsan` | fwsan:530572356 | fwsan-double-fetch (read) | 100 | EfiHiiFont | read of 4 bytes at 0x000000001C294780 input driven, in firmware code |
| (unattributed) | `fwsan` | fwsan:477912604 | fwsan-double-fetch (read) | 1 | EfiSmbios | read of 2 bytes at 0x000000001C868528 input driven, in firmware code |

## Firmware, present on every run

In firmware code but not provoked by any input -- they fire on a plain boot. A real defect can sit here; confirm by reading the source.

None.


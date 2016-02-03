#ifndef __SDBOOT_MEASURE_H
#define __SDBOOT_MEASURE_H

#ifndef SD_TPM_PCR
#define SD_TPM_PCR 8
#endif

EFI_STATUS tpm_log_event(UINT32 pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, CHAR16 *description);
#endif

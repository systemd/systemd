/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 */
#ifndef __SDBOOT_MEASURE_H
#define __SDBOOT_MEASURE_H

#ifndef SD_TPM_PCR
#define SD_TPM_PCR 8
#endif

EFI_STATUS tpm_log_event(UINT32 pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, CHAR16 *description);
#endif

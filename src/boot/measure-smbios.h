/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Measures SMBIOS type 1 (system information, with the volatile "Wake-up Type" field masked) and all
 * type 11 (OEM strings) structures into PCR 1, and records the PCR index in the transient
 * LoaderPcrSMBIOS EFI variable. Called by both sd-boot and sd-stub; the presence of LoaderPcrSMBIOS
 * suppresses a redundant second measurement when both run during the same boot. */
void measure_smbios(void);

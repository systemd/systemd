/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "recovery.h"
#include "util.h"

#define FALLBACK_BOOT_ENTRY L"ostree-1-lmp.conf\0"

bool recovery_check_firmware_failure(void) {
        EFI_SYSTEM_RESOURCE_TABLE *esrt_table = NULL;
        EFI_SYSTEM_RESOURCE_ENTRY *esrt_entry = NULL;

        esrt_table = find_configuration_table(MAKE_GUID_PTR(EFI_SYSTEM_RESOURCE_TABLE));
        if (esrt_table) {
                esrt_entry = (void *)(esrt_table + 1);
                for (uint32_t i = 0; i < esrt_table->FwResourceCount; i++, esrt_entry++) {
                        if (esrt_entry->FwType == ESRT_FW_TYPE_SYSTEMFIRMWARE) {
                                return (esrt_entry->LastAttemptStatus != LAST_ATTEMPT_STATUS_SUCCESS);
                        }
                }
        }

        return false;
}
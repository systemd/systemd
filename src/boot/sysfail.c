/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysfail.h"
#include "util.h"


static bool check_firmware_update_failure(void) {
        const EFI_SYSTEM_RESOURCE_TABLE *esrt_table = NULL;
        const EFI_SYSTEM_RESOURCE_ENTRY *esrt_entry = NULL;

        esrt_table = find_configuration_table(MAKE_GUID_PTR(EFI_SYSTEM_RESOURCE_TABLE));
        if (!esrt_table)
                return false;

        esrt_entry = (const EFI_SYSTEM_RESOURCE_ENTRY*) ((const uint8_t*) esrt_table +
                        sizeof(EFI_SYSTEM_RESOURCE_TABLE));

        for (uint32_t i = 0; i < esrt_table->FwResourceCount; i++, esrt_entry++)
                        if (esrt_entry->FwType == ESRT_FW_TYPE_SYSTEMFIRMWARE)
                                return esrt_entry->LastAttemptStatus != LAST_ATTEMPT_STATUS_SUCCESS;

        return false;
}

SysFailType sysfail_check(SysFailConfig *sysfail_config) {
        if (sysfail_config->check_firmware_update && check_firmware_update_failure())
                return SYSFAIL_FIRMWARE_UPDATE;

        return SYSFAIL_OK;
}

const char16_t* sysfail_get_error_str(SysFailType fail_type) {
        switch (fail_type) {
        case SYSFAIL_FIRMWARE_UPDATE:
                return u"FirmwareUpdateFailed";
        default:
                return u"UnknownError";
        }
}

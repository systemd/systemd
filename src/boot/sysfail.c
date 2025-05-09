/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysfail.h"
#include "util.h"

static bool firmware_update_has_failed(void) {
        const EFI_SYSTEM_RESOURCE_TABLE *esrt_table;
        const EFI_SYSTEM_RESOURCE_ENTRY *esrt_entries;

        esrt_table = find_configuration_table(MAKE_GUID_PTR(EFI_SYSTEM_RESOURCE_TABLE));
        if (!esrt_table)
                return false;

        esrt_entries = esrt_table->Entries;

        FOREACH_ARRAY(esrt_entry, esrt_entries, esrt_table->FwResourceCount)
                if (esrt_entry->FwType == ESRT_FW_TYPE_SYSTEMFIRMWARE)
                        return esrt_entry->LastAttemptStatus != LAST_ATTEMPT_STATUS_SUCCESS;

        return false;
}

SysFailType sysfail_check(void) {
        if (firmware_update_has_failed())
                return SYSFAIL_FIRMWARE_UPDATE;

        return SYSFAIL_NO_FAILURE;
}

const char16_t* sysfail_get_error_str(SysFailType fail_type) {
        switch (fail_type) {
        case SYSFAIL_NO_FAILURE:
                return NULL;
        case SYSFAIL_FIRMWARE_UPDATE:
                return u"firmware-updare-failure";
        default:
                assert_not_reached();
        }
}

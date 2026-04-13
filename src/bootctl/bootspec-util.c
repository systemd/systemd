/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl.h"
#include "bootspec-util.h"
#include "devnum-util.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "log.h"
#include "strv.h"

int boot_config_load_and_select(
                BootConfig *config,
                const char *esp_path,
                dev_t esp_devid,
                const char *xbootldr_path,
                dev_t xbootldr_devid) {

        int r;

        /* If XBOOTLDR and ESP actually refer to the same block device, suppress XBOOTLDR, since it would
         * find the same entries twice. */
        bool same = esp_path && xbootldr_path && devnum_set_and_equal(esp_devid, xbootldr_devid);

        r = boot_config_load(config, esp_path, same ? NULL : xbootldr_path);
        if (r < 0)
                return r;

        if (!arg_root) {
                _cleanup_strv_free_ char **efi_entries = NULL;

                r = efi_loader_get_entries(&efi_entries);
                if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Boot loader reported no entries.");
                else if (r < 0)
                        log_warning_errno(r, "Failed to determine entries reported by boot loader, ignoring: %m");
                else
                        (void) boot_config_augment_from_loader(config, efi_entries, /* auto_only= */ false);
        }

        return boot_config_select_special_entries(config, /* skip_efivars= */ !!arg_root);
}

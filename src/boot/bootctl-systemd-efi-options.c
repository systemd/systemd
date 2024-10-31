/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-systemd-efi-options.h"
#include "efi-loader.h"

int verb_systemd_efi_options(int argc, char *argv[], void *userdata) {
        int r;

        /* This is obsolete and subject to removal */

        if (!arg_quiet)
                log_notice("Use of the SystemdOptions EFI variable is deprecated.");

        if (argc == 1) {
                _cleanup_free_ char *line = NULL, *new = NULL;

                r = systemd_efi_options_variable(&line);
                if (r == -ENODATA)
                        log_debug("No SystemdOptions EFI variable present in cache.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to read SystemdOptions EFI variable from cache: %m");
                else
                        puts(line);

                r = systemd_efi_options_efivarfs_if_newer(&new);
                if (r == -ENODATA) {
                        if (line)
                                log_notice("Note: SystemdOptions EFI variable has been removed since boot.");
                } else if (r < 0)
                        log_warning_errno(r, "Failed to check SystemdOptions EFI variable in efivarfs, ignoring: %m");
                else if (new && !streq_ptr(line, new))
                        log_notice("Note: SystemdOptions EFI variable has been modified since boot. New value: %s",
                                   new);
        } else {
                r = efi_set_variable_string(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions"), argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to set SystemdOptions EFI variable: %m");
        }

        return 0;
}

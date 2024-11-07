/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <uchar.h>
#include <unistd.h>

#include "bootctl.h"
#include "bootctl-set-efivar.h"
#include "efivars.h"
#include "efi-loader.h"
#include "stdio-util.h"
#include "utf8.h"
#include "virt.h"

static int parse_timeout(const char *arg1, char16_t **ret_timeout, size_t *ret_timeout_size) {
        char utf8[DECIMAL_STR_MAX(usec_t)];
        char16_t *encoded;
        usec_t timeout;
        bool menu_disabled = false;
        int r;

        assert(arg1);
        assert(ret_timeout);
        assert(ret_timeout_size);

        assert_cc(STRLEN("menu-disabled") < ELEMENTSOF(utf8));

        /* Note: Since there is no way to query if the bootloader supports the string tokens, we explicitly
         * set their numerical value(s) instead. This means that some of the sd-boot internal ABI has leaked
         * although the ship has sailed and the side-effects are self-contained.
         */
        if (streq(arg1, "menu-force"))
                timeout = USEC_INFINITY;
        else if (streq(arg1, "menu-hidden"))
                timeout = 0;
        else if (streq(arg1, "menu-disabled")) {
                uint64_t loader_features = 0;

                (void) efi_loader_get_features(&loader_features);
                if (!(loader_features & EFI_LOADER_FEATURE_MENU_DISABLE)) {
                        if (!arg_graceful)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Loader does not support 'menu-disabled'.");

                        log_warning("Loader does not support 'menu-disabled', setting anyway.");
                }
                menu_disabled = true;
        } else {
                r = parse_time(arg1, &timeout, USEC_PER_SEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse timeout '%s': %m", arg1);
                if (timeout != USEC_INFINITY && timeout > UINT32_MAX * USEC_PER_SEC)
                        log_warning("Timeout is too long and will be treated as 'menu-force' instead.");
        }

        if (menu_disabled)
                xsprintf(utf8, "menu-disabled");
        else
                xsprintf(utf8, USEC_FMT, MIN(timeout / USEC_PER_SEC, UINT32_MAX));

        encoded = utf8_to_utf16(utf8, SIZE_MAX);
        if (!encoded)
                return log_oom();

        *ret_timeout = encoded;
        *ret_timeout_size = char16_strlen(encoded) * 2 + 2;
        return 0;
}

static int parse_loader_entry_target_arg(const char *arg1, char16_t **ret_target, size_t *ret_target_size) {
        char16_t *encoded = NULL;
        int r;

        assert(arg1);
        assert(ret_target);
        assert(ret_target_size);

        if (streq(arg1, "@current")) {
                r = efi_get_variable(EFI_LOADER_VARIABLE_STR("LoaderEntrySelected"), NULL, (void *) ret_target, ret_target_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to get EFI variable 'LoaderEntrySelected': %m");

        } else if (streq(arg1, "@oneshot")) {
                r = efi_get_variable(EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"), NULL, (void *) ret_target, ret_target_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to get EFI variable 'LoaderEntryOneShot': %m");

        } else if (streq(arg1, "@default")) {
                r = efi_get_variable(EFI_LOADER_VARIABLE_STR("LoaderEntryDefault"), NULL, (void *) ret_target, ret_target_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to get EFI variable 'LoaderEntryDefault': %m");

        } else if (arg1[0] == '@' && !streq(arg1, "@saved"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unsupported special entry identifier: %s", arg1);
        else {
                encoded = utf8_to_utf16(arg1, SIZE_MAX);
                if (!encoded)
                        return log_oom();

                *ret_target = encoded;
                *ret_target_size = char16_strlen(encoded) * 2 + 2;
        }

        return 0;
}

int verb_set_efivar(int argc, char *argv[], void *userdata) {
        int r;

        if (arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Acting on %s, skipping EFI variable setup.",
                                       arg_image ? "image" : "root directory");

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Not booted with UEFI.");

        if (access(EFIVAR_PATH(EFI_LOADER_VARIABLE_STR("LoaderInfo")), F_OK) < 0) {
                if (errno == ENOENT) {
                        log_error_errno(errno, "Not booted with a supported boot loader.");
                        return -EOPNOTSUPP;
                }

                return log_error_errno(errno, "Failed to detect whether boot loader supports '%s' operation: %m", argv[0]);
        }

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "'%s' operation not supported in a container.",
                                       argv[0]);

        if (!arg_touch_variables)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' operation cannot be combined with --no-variables.",
                                       argv[0]);

        const char *variable;
        int (* arg_parser)(const char *, char16_t **, size_t *);

        if (streq(argv[0], "set-default")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderEntryDefault");
                arg_parser = parse_loader_entry_target_arg;
        } else if (streq(argv[0], "set-oneshot")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot");
                arg_parser = parse_loader_entry_target_arg;
        } else if (streq(argv[0], "set-timeout")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderConfigTimeout");
                arg_parser = parse_timeout;
        } else if (streq(argv[0], "set-timeout-oneshot")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot");
                arg_parser = parse_timeout;
        } else
                assert_not_reached();

        if (isempty(argv[1])) {
                r = efi_set_variable(variable, NULL, 0);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to remove EFI variable '%s': %m", variable);
        } else {
                _cleanup_free_ char16_t *value = NULL;
                size_t value_size = 0;

                r = arg_parser(argv[1], &value, &value_size);
                if (r < 0)
                        return r;
                r = efi_set_variable(variable, value, value_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to update EFI variable '%s': %m", variable);
        }

        return 0;
}

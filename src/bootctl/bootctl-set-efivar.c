/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <uchar.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-set-efivar.h"
#include "efi-loader.h"
#include "efivars.h"
#include "log.h"
#include "stdio-util.h"
#include "time-util.h"
#include "utf8.h"
#include "virt.h"

static int parse_timeout(const char *arg1, char16_t **ret_timeout, size_t *ret_timeout_size) {
        char buf[DECIMAL_STR_MAX(usec_t)];
        usec_t timeout;
        uint64_t loader_features = 0;
        int r;

        assert(arg1);
        assert(ret_timeout);
        assert(ret_timeout_size);

        assert_cc(STRLEN("menu-force") < ELEMENTSOF(buf));
        assert_cc(STRLEN("menu-hidden") < ELEMENTSOF(buf));
        assert_cc(STRLEN("menu-disabled") < ELEMENTSOF(buf));

        /* Use feature EFI_LOADER_FEATURE_MENU_DISABLE as a mark that the boot loader supports the other
         * string values too. When unsupported, convert to the timeout with the closest meaning.
         */

        if (streq(arg1, "menu-force")) {
                (void) efi_loader_get_features(&loader_features);

                if (!(loader_features & EFI_LOADER_FEATURE_MENU_DISABLE)) {
                        log_debug("Using maximum timeout instead of '%s'.", arg1);
                        timeout = USEC_INFINITY;
                        arg1 = NULL;
                }

        } else if (streq(arg1, "menu-hidden")) {
                (void) efi_loader_get_features(&loader_features);

                if (!(loader_features & EFI_LOADER_FEATURE_MENU_DISABLE)) {
                        log_debug("Using zero timeout instead of '%s'.", arg1);
                        timeout = 0;
                        arg1 = NULL;  /* replace the arg by printed timeout value later */
                }

        } else if (streq(arg1, "menu-disabled")) {
                (void) efi_loader_get_features(&loader_features);

                if (!(loader_features & EFI_LOADER_FEATURE_MENU_DISABLE)) {
                        if (arg_graceful() == ARG_GRACEFUL_NO)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Loader does not support '%s'.", arg1);
                        log_warning("Using zero timeout instead of '%s'.", arg1);
                        timeout = 0;
                        arg1 = NULL;
                }

        } else {
                r = parse_time(arg1, &timeout, USEC_PER_SEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse timeout '%s': %m", arg1);

                assert_cc(USEC_INFINITY > UINT32_MAX * USEC_PER_SEC);
                if (timeout > UINT32_MAX * USEC_PER_SEC && timeout != USEC_INFINITY)
                        log_debug("Timeout is too long and will be clamped to maximum timeout.");

                arg1 = NULL;
        }

        if (!arg1) {
                timeout = DIV_ROUND_UP(timeout, USEC_PER_SEC);
                xsprintf(buf, USEC_FMT, MIN(timeout, UINT32_MAX));
        }

        char16_t *encoded = utf8_to_utf16(arg1 ?: buf, SIZE_MAX);
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

        } else if (streq(arg1, "@sysfail")) {
                r = efi_get_variable(EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail"), NULL, (void *) ret_target, ret_target_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to get EFI variable 'LoaderEntrySysFail': %m");

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

        /* Note: changing EFI variables is the primary purpose of these verbs, hence unlike in the other
         * verbs that might touch EFI variables where we skip things gracefully, here we fail loudly if we
         * are not run on EFI or EFI variable modifications were turned off. */

        if (arg_touch_variables < 0) {
                if (arg_root)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Acting on %s, refusing EFI variable setup.",
                                               arg_image ? "image" : "root directory");

                if (detect_container() > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "'%s' operation not supported in a container.",
                                               argv[0]);
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

        } else if (!arg_touch_variables)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' operation cannot be combined with --variables=no.",
                                       argv[0]);

        const char *variable;
        int (* arg_parser)(const char *, char16_t **, size_t *);

        if (streq(argv[0], "set-default")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderEntryDefault");
                arg_parser = parse_loader_entry_target_arg;
        } else if (streq(argv[0], "set-preferred")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderEntryPreferred");
                arg_parser = parse_loader_entry_target_arg;
        } else if (streq(argv[0], "set-sysfail")) {
                variable = EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail");
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

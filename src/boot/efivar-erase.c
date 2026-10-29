/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "efi-string-table.h"
#include "efivar-erase.h"
#include "proto/simple-text-io.h"
#include "strv.h"
#include "util.h"

/* Upper limit on the number of variables we enumerate, as protection against firmware that never returns
 * EFI_NOT_FOUND from GetNextVariableName() */
#define ENUMERATE_VARIABLES_MAX 65536U

static const char *factory_reset_variables_mode_table[_FACTORY_RESET_VARIABLES_MAX] = {
        [FACTORY_RESET_VARIABLES_ASK] = "ask",
        [FACTORY_RESET_VARIABLES_YES] = "yes",
        [FACTORY_RESET_VARIABLES_NO]  = "no",
};

DEFINE_STRING_TABLE_LOOKUP(factory_reset_variables_mode, FactoryResetVariablesMode);

static EFI_STATUS collect_variables(const EFI_GUID *vendor, char16_t ***ret) {
        _cleanup_strv_free_ char16_t **l = NULL;
        size_t n = 0, buf_size = 256 * sizeof(char16_t);
        _cleanup_free_ char16_t *buf = NULL;
        EFI_GUID guid = {};
        EFI_STATUS err;

        assert(vendor);
        assert(ret);

        /* Note that the UEFI spec leaves undefined what happens if variables are deleted while they are
         * enumerated. Hence we first collect all names, and only delete them afterwards. */

        buf = xmalloc(buf_size);
        buf[0] = 0; /* Empty string starts enumeration */

        for (unsigned i = 0;; i++) {
                if (i >= ENUMERATE_VARIABLES_MAX)
                        return log_error_status(EFI_ABORTED, "Too many EFI variables, refusing to enumerate further.");

                size_t size = buf_size;
                err = RT->GetNextVariableName(&size, buf, &guid);
                if (err == EFI_NOT_FOUND)
                        break;
                if (err == EFI_BUFFER_TOO_SMALL) {
                        if (size <= buf_size)
                                return log_error_status(err, "Firmware reported invalid EFI variable name size.");

                        /* Retain the current name, enumeration continues from it */
                        buf = xrealloc(buf, buf_size, size);
                        buf_size = size;
                        continue;
                }
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to enumerate EFI variables: %m");

                if (!efi_guid_equal(&guid, vendor))
                        continue;

                l = xrealloc(l, n == 0 ? 0 : (n + 1) * sizeof(char16_t*), (n + 2) * sizeof(char16_t*));
                l[n++] = xstrdup16(buf);
                l[n] = NULL;
        }

        *ret = TAKE_PTR(l);
        return EFI_SUCCESS;
}

static EFI_STATUS erase_variable(const EFI_GUID *vendor, const char16_t *name) {
        uint32_t attributes;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        /* Some firmware implementations refuse deletion if the attributes don't match the existing
         * variable, hence query them first, and pass them along. */
        err = efivar_get_raw_full(vendor, name, &attributes, /* ret_data= */ NULL, /* ret_size= */ NULL);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to query EFI variable %ls: %m", name);

        err = RT->SetVariable((char16_t *) name, (EFI_GUID *) vendor, attributes, 0, NULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to erase EFI variable %ls: %m", name);

        log_debug("Erased EFI variable %ls.", name);
        return EFI_SUCCESS;
}

EFI_STATUS efivar_erase_namespace(const EFI_GUID *vendor, const char16_t *const *keep) {
        _cleanup_strv_free_ char16_t **l = NULL;
        EFI_STATUS err, ret = EFI_SUCCESS;

        assert(vendor);

        err = collect_variables(vendor, &l);
        if (err != EFI_SUCCESS)
                return err;

        STRV_FOREACH(i, l) {
                if (strv_contains((char16_t**) keep, *i))
                        continue;

                err = erase_variable(vendor, *i);
                if (err != EFI_SUCCESS && ret == EFI_SUCCESS)
                        ret = err;
        }

        return ret;
}

static EFI_STATUS ask_confirmation(bool *ret) {
        EFI_STATUS err;

        assert(ret);

        clear_screen(COLOR_NORMAL);

        printf("A factory reset has been requested.\n"
               "\n"
               "All EFI variables owned by the boot loader and by systemd are about to be erased,\n"
               "including boot menu defaults, one-shot entries and the system token. The system\n"
               "will reboot afterwards.\n"
               "\n"
               "Erase these EFI variables? (y/n) ");

        for (;;) {
                uint64_t key;

                err = console_key_read(&key, /* timeout_usec= */ UINT64_MAX);
                if (err == EFI_NOT_READY)
                        continue;
                if (err != EFI_SUCCESS) {
                        printf("\n");
                        return log_error_status(err, "Error waiting for user input: %m");
                }

                switch (key) {

                case KEYPRESS(0, 0, 'y'):
                case KEYPRESS(0, 0, 'Y'):
                        printf("y\n");
                        *ret = true;
                        return EFI_SUCCESS;

                case KEYPRESS(0, 0, 'n'):
                case KEYPRESS(0, 0, 'N'):
                case KEYPRESS(0, SCAN_ESC, 0):
                        printf("n\n");
                        *ret = false;
                        return EFI_SUCCESS;

                default:
                        /* Ignore anything else, the user has to make an explicit choice */
                        break;
                }
        }
}

EFI_STATUS factory_reset_variables_process(FactoryResetVariablesMode mode) {
        static const char16_t *const keep_loader[] = {
                u"LoaderFactoryResetVariables", /* erased last, see below */
                NULL,
        };
        static const char16_t *const keep_systemd[] = {
                /* The OS needs this on the next boot to reset its partitions, hence don't erase it */
                u"FactoryResetRequest",
                NULL,
        };
        bool b;
        EFI_STATUS err;

        err = efivar_get_boolean_str16(MAKE_GUID_PTR(LOADER), u"LoaderFactoryResetVariables", &b);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err == EFI_INVALID_PARAMETER) {
                /* Remove the invalid request, so that we don't complain about it on every boot */
                log_warning("Invalid LoaderFactoryResetVariables EFI variable, removing.");
                (void) erase_variable(MAKE_GUID_PTR(LOADER), u"LoaderFactoryResetVariables");
                return EFI_SUCCESS;
        }
        if (err != EFI_SUCCESS) {
                log_warning_status(err, "Failed to read LoaderFactoryResetVariables EFI variable, ignoring: %m");
                return EFI_SUCCESS;
        }
        if (!b)
                return EFI_SUCCESS;

        switch (mode) {

        case FACTORY_RESET_VARIABLES_NO:
                log_info("Erasing EFI variables requested, but disabled in configuration, ignoring.");
                break;

        case FACTORY_RESET_VARIABLES_ASK: {
                bool confirmed;

                err = ask_confirmation(&confirmed);
                if (err != EFI_SUCCESS)
                        /* Leave the request in place, so that we ask again on the next boot */
                        return err;
                if (!confirmed) {
                        log_info("Erasing EFI variables declined by user.");
                        break;
                }
        }

                _fallthrough_;

        case FACTORY_RESET_VARIABLES_YES:
                log_info("Erasing EFI variables of boot loader and systemd.");

                (void) efivar_erase_namespace(MAKE_GUID_PTR(LOADER), keep_loader);
                (void) efivar_erase_namespace(MAKE_GUID_PTR(SYSTEMD), keep_systemd);

                /* Erase the request itself last, so that if we are interrupted half-way we'll try again on
                 * the next boot. Do this also if erasing some variables failed, so that we don't end up in a
                 * reboot loop. */
                (void) erase_variable(MAKE_GUID_PTR(LOADER), u"LoaderFactoryResetVariables");

                log_wait();
                RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
                assert_not_reached();

        default:
                assert_not_reached();
        }

        /* Drop the request, so that we don't ask again on every boot */
        (void) erase_variable(MAKE_GUID_PTR(LOADER), u"LoaderFactoryResetVariables");
        return EFI_SUCCESS;
}

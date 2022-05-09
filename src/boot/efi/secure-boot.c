/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sbat.h"
#include "secure-boot.h"
#include "boot.h"
#include "console.h"
#include "util.h"

BOOLEAN secure_boot_enabled(void) {
        BOOLEAN secure;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);

        return !EFI_ERROR(err) && secure;
}

SecureBootMode secure_boot_mode(void) {
        BOOLEAN secure, audit = FALSE, deployed = FALSE, setup = FALSE;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);
        if (EFI_ERROR(err))
                return SECURE_BOOT_UNSUPPORTED;

        /* We can assume FALSE for all these if they are abscent (AuditMode and
         * DeployedMode may not exist on older firmware). */
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"AuditMode", &audit);
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"DeployedMode", &deployed);
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SetupMode", &setup);

        return decode_secure_boot_mode(secure, audit, deployed, setup);
}

#ifdef SBAT_DISTRO
static const char sbat[] _used_ _section_(".sbat") = SBAT_SECTION_TEXT;
#endif

EFI_STATUS secure_boot_enroll_at(EFI_FILE *root_dir, const CHAR16 *path) {
        assert(root_dir);
        assert(path);

        EFI_STATUS err = EFI_SUCCESS;

        clear_screen(COLOR_NORMAL);

        Print(L"Enrolling secure boot keys from directory: \\loader\\keys\\%s\n"
              L"Warning: Enrolling custom Secure Boot keys might soft-brick your machine!\n",
              path);

        UINT32 timeout_sec = 15;
        for(;;) {
                PrintAt(0, ST->ConOut->Mode->CursorRow, L"Enrolling in %2u s, press any key to abort.", timeout_sec);

                UINT64 key;
                err = console_key_read(&key, 1000 * 1000);
                if (err == EFI_NOT_READY)
                        continue;
                if (err == EFI_TIMEOUT) {
                        if (timeout_sec == 0) /* continue enrolling keys */
                                break;
                        timeout_sec--;
                        continue;
                }
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error waiting for user input to enroll Secure Boot keys: %r", err);

                /* user aborted */
                return EFI_SUCCESS;
        }

        _cleanup_(file_closep) EFI_FILE *dir = NULL;
        UINT32 sb_vars_opts =
                EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_RUNTIME_ACCESS |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

        err = open_directory(root_dir, path, &dir);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed opening keys directory %s: %r", path, err);

        struct {
                const CHAR16 *name;
                const CHAR16 *filename;
                const EFI_GUID vendor;
                CHAR8 *buffer;
                UINTN size;
        } sb_vars[] = {
                { L"db",  L"db.esl",  EFI_IMAGE_SECURITY_DATABASE_VARIABLE, NULL, 0 },
                { L"KEK", L"KEK.esl", EFI_GLOBAL_VARIABLE, NULL, 0 },
                { L"PK",  L"PK.esl",  EFI_GLOBAL_VARIABLE, NULL, 0 },
        };

        for (UINTN i = 0; i < ELEMENTSOF(sb_vars); i++) {
                err = file_read(dir, sb_vars[i].filename, 0, 0, &sb_vars[i].buffer, &sb_vars[i].size);
                if (EFI_ERROR(err)) {
                        log_error_stall(L"Failed reading file %s: %r", sb_vars[i].filename, err);
                        goto out_deallocate;
                }
        }

        for (UINTN i = 0; i < ELEMENTSOF(sb_vars); i++) {
                err = efivar_set_raw(&sb_vars[i].vendor, sb_vars[i].name, sb_vars[i].buffer, sb_vars[i].size, sb_vars_opts);
                if (EFI_ERROR(err)) {
                        log_error_stall(L"Failed to write %s secure boot variable: %r", sb_vars[i].name, err);
                        goto out_deallocate;
                }
        }

        /* if we loaded the signature keys successfully then we reboot
        as the system is now locked down. */
        err = RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

out_deallocate:
        for (UINTN i = 0; i < ELEMENTSOF(sb_vars); i++)
                FreePool(sb_vars[i].buffer);

        return err;
}

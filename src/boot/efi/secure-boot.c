/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "secure-boot.h"
#include "missing_efi.h"
#include "util.h"

#define EFI_IMAGE_SECURITY_DATABASE_GUID                               \
        &(const EFI_GUID) {                                            \
                0xd719b2cb, 0x3d3a, 0x4596, {                          \
                        0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f \
                }                                                      \
        }

BOOLEAN secure_boot_enabled(void) {
        BOOLEAN secure;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);

        return !EFI_ERROR(err) && secure;
}

static EFI_STATUS setup_mode_active(BOOLEAN *active) {
        BOOLEAN setup, audit, deployed;
        EFI_STATUS err;

        setup = audit = deployed = FALSE;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SetupMode", &setup);
        if (EFI_ERROR(err))
                return err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"AuditMode", &audit);
        if (EFI_ERROR(err) && err != EFI_NOT_FOUND)
                return err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"DeployedMode", &deployed);
        if (EFI_ERROR(err) && err != EFI_NOT_FOUND)
                return err;

        *active = setup && !audit && !deployed;

        return EFI_SUCCESS;
}

typedef enum { KEY_PK, KEY_KEK, KEY_DB, KEY_UNKNOWN } KEY_TYPE;

EFI_STATUS setup_secure_boot(EFI_FILE *root_dir) {
        BOOLEAN in_setup;
        EFI_FILE_HANDLE secure_boot_dir;
        EFI_STATUS err;
        KEY_TYPE type = KEY_UNKNOWN;

        err = setup_mode_active(&in_setup);
        if (EFI_ERROR(err)) {
                Print(L"secure-boot: Failed to query setup mode: %r", err);
                return err;
        }

        if (!in_setup)
                return EFI_SUCCESS;

        err = uefi_call_wrapper(
                root_dir->Open, 5, root_dir, &secure_boot_dir, L"\\loader\\secure-boot", EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err)) {
                Print(L"secure-boot: Failed to open loader/secure-boot directory: %r", err);
                return err;
        }

        for (;;) {
                CHAR16 buf[256];
                UINTN bufsize = sizeof(buf);
                EFI_FILE_INFO *f;
                _cleanup_freepool_ CHAR8 *content = NULL;
                UINTN content_size;

                err = uefi_call_wrapper(secure_boot_dir->Read, 3, secure_boot_dir, &bufsize, buf);
                if (bufsize == 0 || EFI_ERROR(err))
                        break;

                f = (EFI_FILE_INFO *) buf;
                if (f->FileName[0] == '.')
                        continue;
                if (f->Attribute & EFI_FILE_DIRECTORY)
                        continue;

                if (endswith(f->FileName, L".pk.esl"))
                        type = KEY_PK;
                else if (endswith(f->FileName, L".kek.esl"))
                        type = KEY_KEK;
                else if (endswith(f->FileName, L".db.esl"))
                        type = KEY_DB;
                else
                        continue;

                err = file_read(secure_boot_dir, f->FileName, 0, 0, &content, &content_size);
                if (EFI_ERROR(err)) {
                        Print(L"secure-boot: Failed to read file %s: %r", f->FileName, err);
                        return err;
                }

                switch (type) {
                case KEY_PK:
                        err = efivar_set_raw(
                                EFI_GLOBAL_GUID,
                                L"PK",
                                content,
                                content_size,
                                EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
                                        EFI_VARIABLE_APPEND_WRITE);
                        break;
                case KEY_KEK:
                        err = efivar_set_raw(
                                EFI_GLOBAL_GUID,
                                L"KEK",
                                content,
                                content_size,
                                EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
                                        EFI_VARIABLE_APPEND_WRITE);
                        break;
                case KEY_DB:
                        err = efivar_set_raw(
                                EFI_IMAGE_SECURITY_DATABASE_GUID,
                                L"db",
                                content,
                                content_size,
                                EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
                                        EFI_VARIABLE_APPEND_WRITE);
                        break;
                case KEY_UNKNOWN:
                        break;
                }

                Print(L"File: %s\n", f->FileName);

                if (EFI_ERROR(err)) {
                        Print(L"Size: %d", content_size);
                        Print(L"secure-boot: Failed to set UEFI variable: %r", err);
                        return err;
                }
        }

        return EFI_SUCCESS;
}

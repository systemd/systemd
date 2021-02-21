/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "secure-boot.h"
#include "util.h"

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
        &(const EFI_GUID) { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } }

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

typedef enum {
        SECURE_BOOT_KEY_PK,
        SECURE_BOOT_KEY_KEK,
        SECURE_BOOT_KEY_DB,
        _SECURE_BOOT_KEY_TYPE_MAX,
} SecureBootKeyType;

static const CHAR16 *const key_type_string[_SECURE_BOOT_KEY_TYPE_MAX] = {
        [SECURE_BOOT_KEY_PK] = L"PK",
        [SECURE_BOOT_KEY_KEK] = L"KEK",
        [SECURE_BOOT_KEY_DB] = L"db",
};

static const EFI_GUID *key_type_guid[_SECURE_BOOT_KEY_TYPE_MAX] = {
        [SECURE_BOOT_KEY_PK] = EFI_GLOBAL_GUID,
        [SECURE_BOOT_KEY_KEK] = EFI_GLOBAL_GUID,
        [SECURE_BOOT_KEY_DB] = EFI_IMAGE_SECURITY_DATABASE_GUID,
};

EFI_STATUS setup_secure_boot(EFI_FILE *root_dir) {
        BOOLEAN in_setup;
        EFI_FILE_HANDLE secure_boot_dir;
        EFI_STATUS err;

        err = setup_mode_active(&in_setup);
        if (EFI_ERROR(err)) {
                Print(L"secure-boot: Failed to query setup mode state: %r", err);
                return err;
        }

        if (!in_setup)
                return EFI_SUCCESS;

        err = uefi_call_wrapper(
                root_dir->Open, 5, root_dir, &secure_boot_dir, L"\\loader\\secure-boot", EFI_FILE_MODE_READ, 0ULL);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
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
                SecureBootKeyType type;

                err = uefi_call_wrapper(secure_boot_dir->Read, 3, secure_boot_dir, &bufsize, buf);
                if (bufsize == 0 || EFI_ERROR(err))
                        break;

                f = (EFI_FILE_INFO *) buf;
                if (f->FileName[0] == '.')
                        continue;
                if (f->Attribute & EFI_FILE_DIRECTORY)
                        continue;

                if (endswith(f->FileName, L".pk.esl"))
                        type = SECURE_BOOT_KEY_PK;
                else if (endswith(f->FileName, L".kek.esl"))
                        type = SECURE_BOOT_KEY_KEK;
                else if (endswith(f->FileName, L".db.esl"))
                        type = SECURE_BOOT_KEY_DB;
                else {
                        Print(L"secure-boot: %s has unknown extension, ignoring ...\n", f->FileName);
                        continue;
                }

                err = file_read(secure_boot_dir, f->FileName, 0, 0, &content, &content_size);
                if (EFI_ERROR(err)) {
                        Print(L"secure-boot: Failed to read file %s: %r\n", f->FileName, err);
                        return err;
                }

                err = efivar_set_raw(
                        key_type_guid[type],
                        key_type_string[type],
                        content,
                        content_size,
                        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS);

                if (EFI_ERROR(err)) {
                        Print(L"secure-boot: Failed to set UEFI variable \"%s\": %r\n",
                              key_type_string[type],
                              err);
                        return err;
                }
        }

        return EFI_SUCCESS;
}

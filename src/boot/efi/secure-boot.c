/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "proto/security-arch.h"
#include "secure-boot.h"
#include "util.h"
#include "vmm.h"

bool secure_boot_enabled(void) {
        bool secure = false;  /* avoid false maybe-uninitialized warning */
        EFI_STATUS err;

        err = efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"SecureBoot", &secure);

        return err == EFI_SUCCESS && secure;
}

SecureBootMode secure_boot_mode(void) {
        bool secure, audit = false, deployed = false, setup = false;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"SecureBoot", &secure);
        if (err != EFI_SUCCESS)
                return SECURE_BOOT_UNSUPPORTED;

        /* We can assume false for all these if they are abscent (AuditMode and
         * DeployedMode may not exist on older firmware). */
        (void) efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"AuditMode", &audit);
        (void) efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"DeployedMode", &deployed);
        (void) efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"SetupMode", &setup);

        return decode_secure_boot_mode(secure, audit, deployed, setup);
}

EFI_STATUS secure_boot_enroll_at(EFI_FILE *root_dir, const char16_t *path, bool force) {
        assert(root_dir);
        assert(path);

        EFI_STATUS err;

        clear_screen(COLOR_NORMAL);

        /* Enrolling secure boot keys is safe to do in virtualized environments as there is nothing
         * we can brick there. */
        bool is_safe = in_hypervisor();

        if (!is_safe && !force)
                return EFI_SUCCESS;

        printf("Enrolling secure boot keys from directory: %ls\n", path);

        if (!is_safe) {
                printf("Warning: Enrolling custom Secure Boot keys might soft-brick your machine!\n");

                unsigned timeout_sec = 15;
                for (;;) {
                        printf("\rEnrolling in %2u s, press any key to abort.", timeout_sec);

                        uint64_t key;
                        err = console_key_read(&key, 1000 * 1000);
                        if (err == EFI_NOT_READY)
                                continue;
                        if (err == EFI_TIMEOUT) {
                                if (timeout_sec == 0) /* continue enrolling keys */
                                        break;
                                timeout_sec--;
                                continue;
                        }
                        if (err != EFI_SUCCESS)
                                return log_error_status(
                                                err,
                                                "Error waiting for user input to enroll Secure Boot keys: %m");

                        /* user aborted, returning EFI_SUCCESS here allows the user to go back to the menu */
                        return EFI_SUCCESS;
                }

                printf("\n");
        }

        _cleanup_(file_closep) EFI_FILE *dir = NULL;

        err = open_directory(root_dir, path, &dir);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed opening keys directory %ls: %m", path);

        struct {
                const char16_t *name;
                const char16_t *filename;
                const EFI_GUID vendor;
                char *buffer;
                size_t size;
        } sb_vars[] = {
                { u"db",  u"db.auth",  EFI_IMAGE_SECURITY_DATABASE_GUID, NULL, 0 },
                { u"KEK", u"KEK.auth", EFI_GLOBAL_VARIABLE, NULL, 0 },
                { u"PK",  u"PK.auth",  EFI_GLOBAL_VARIABLE, NULL, 0 },
        };

        /* Make sure all keys files exist before we start enrolling them by loading them from the disk first. */
        for (size_t i = 0; i < ELEMENTSOF(sb_vars); i++) {
                err = file_read(dir, sb_vars[i].filename, 0, 0, &sb_vars[i].buffer, &sb_vars[i].size);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Failed reading file %ls\\%ls: %m", path, sb_vars[i].filename);
                        goto out_deallocate;
                }
        }

        for (size_t i = 0; i < ELEMENTSOF(sb_vars); i++) {
                uint32_t sb_vars_opts =
                        EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS |
                        EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

                err = efivar_set_raw(&sb_vars[i].vendor, sb_vars[i].name, sb_vars[i].buffer, sb_vars[i].size, sb_vars_opts);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Failed to write %ls secure boot variable: %m", sb_vars[i].name);
                        goto out_deallocate;
                }
        }

        printf("Custom Secure Boot keys successfully enrolled, rebooting the system now!\n");
        /* The system should be in secure boot mode now and we could continue a regular boot. But at least
         * TPM PCR7 measurements should change on next boot. Reboot now so that any OS we load does not end
         * up relying on the old PCR state. */
        RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        assert_not_reached();

out_deallocate:
        for (size_t i = 0; i < ELEMENTSOF(sb_vars); i++)
                free(sb_vars[i].buffer);

        return err;
}

static struct SecurityOverride {
        EFI_SECURITY_ARCH_PROTOCOL *security;
        EFI_SECURITY2_ARCH_PROTOCOL *security2;
        EFI_SECURITY_FILE_AUTHENTICATION_STATE original_hook;
        EFI_SECURITY2_FILE_AUTHENTICATION original_hook2;

        security_validator_t validator;
        const void *validator_ctx;
} security_override;

static EFIAPI EFI_STATUS security_hook(
                const EFI_SECURITY_ARCH_PROTOCOL *this,
                uint32_t authentication_status,
                const EFI_DEVICE_PATH *file) {

        assert(security_override.validator);
        assert(security_override.security);
        assert(security_override.original_hook);

        if (security_override.validator(security_override.validator_ctx, file, NULL, 0))
                return EFI_SUCCESS;

        return security_override.original_hook(security_override.security, authentication_status, file);
}

static EFIAPI EFI_STATUS security2_hook(
                const EFI_SECURITY2_ARCH_PROTOCOL *this,
                const EFI_DEVICE_PATH *device_path,
                void *file_buffer,
                size_t file_size,
                bool boot_policy) {

        assert(security_override.validator);
        assert(security_override.security2);
        assert(security_override.original_hook2);

        if (security_override.validator(security_override.validator_ctx, device_path, file_buffer, file_size))
                return EFI_SUCCESS;

        return security_override.original_hook2(
                        security_override.security2, device_path, file_buffer, file_size, boot_policy);
}

/* This replaces the platform provided security arch protocols hooks (defined in the UEFI Platform
 * Initialization Specification) with our own that uses the given validator to decide if a image is to be
 * trusted. If not running in secure boot or the protocols are not available nothing happens. The override
 * must be removed with uninstall_security_override() after LoadImage() has been called.
 *
 * This is a hack as we do not own the security protocol instances and modifying them is not an official part
 * of their spec. But there is little else we can do to circumvent secure boot short of implementing our own
 * PE loader. We could replace the firmware instances with our own instance using
 * ReinstallProtocolInterface(), but some firmware will still use the old ones. */
void install_security_override(security_validator_t validator, const void *validator_ctx) {
        EFI_STATUS err;

        assert(validator);

        if (!secure_boot_enabled())
                return;

        security_override = (struct SecurityOverride) {
                .validator = validator,
                .validator_ctx = validator_ctx,
        };

        EFI_SECURITY_ARCH_PROTOCOL *security;
        void *security_raw = NULL;
        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_SECURITY_ARCH_PROTOCOL), NULL, (void **) &security_raw);
        security = security_raw;
        if (err == EFI_SUCCESS) {
                security_override.security = security;
                security_override.original_hook = security->FileAuthenticationState;
                security->FileAuthenticationState = security_hook;
        }

        EFI_SECURITY2_ARCH_PROTOCOL *security2;
        security_raw = NULL;
        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_SECURITY2_ARCH_PROTOCOL), NULL, (void **) &security_raw);
        security2 = security_raw;
        if (err == EFI_SUCCESS) {
                security_override.security2 = security2;
                security_override.original_hook2 = security2->FileAuthentication;
                security2->FileAuthentication = security2_hook;
        }
}

void uninstall_security_override(void) {
        if (security_override.original_hook)
                security_override.security->FileAuthenticationState = security_override.original_hook;
        if (security_override.original_hook2)
                security_override.security2->FileAuthentication = security_override.original_hook2;
}

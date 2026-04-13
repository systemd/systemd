/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-secret.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "random-seed.h"
#include "sha256-fundamental.h"
#include "util.h"

#define BOOT_SECRET_MIXIN_PATH u"\\loader\\boot-secret-mixin"

/* This maintains a per-system secret that is stored in an EFI variable that is only accessible during EFI
 * boot, and becomes inaccessible afterwards, once ExitBootServices() is called. The variable is
 * automatically initialized if missing. A secret derived by hashing from this EFI variable secret is then
 * passed to the OS, in an initrd file inaccessible to unprivileged userspace. To make things a bit more
 * robust while hashing two more pieces of information are mixed in: a random "mixin" that is stored in the
 * ESP and is supposed to ensure that the passed boot secrets are distinct for each disk used on the system;
 * moreover an OS identifier derived from the UKI's .osrel field (ideally IMAGE_ID=, but if not defined ID=
 * will do, with a final fallback to "linux"). Note that these two additions are not supposed to enhance the
 * cryptographic quality of the secret, they are just supposed to make things more robust on systems with
 * multiple disks and OSes.
 *
 * The boot secret passed to the OS can be used to protect resources during OS runtime, from earliest boot
 * phases on, as a fallback for the usual TPM based protections.
 *
 * Note that this secret comes with much weaker protection than TPM backed secrets: there's no physical
 * isolation, there are no cryptographic access policies, there's just the hope the firmware reasonably
 * correctly implements boot-time-only EFI variable mechanism. (But then again, this is what mok/shim's
 * security also relies on, and hence this all is not too bad?) */

static EFI_STATUS random_seed_find_table(struct linux_efi_random_seed **ret) {
        assert(ret);

        /* We use the Linux random seed EFI table as our source of randomness, since there's reason to
         * believe it is as good as it possibly would get. Note that we ourselves might be the ones
         * initializing it, based on EFI RNG APIs, the monotonic boot counter, a random seed file on disk and
         * the clock. */

        struct linux_efi_random_seed *seed_table =
                find_configuration_table(MAKE_GUID_PTR(LINUX_EFI_RANDOM_SEED_TABLE));
        if (!seed_table)
                return log_debug_status(EFI_NOT_FOUND, "No random seed available, not creating a boot secret.");
        if (seed_table->size < BOOT_SECRET_SIZE)
                return log_debug_status(EFI_NOT_FOUND, "Random seed is available, but too short.");

        *ret = seed_table;
        return EFI_SUCCESS;
}

static void random_seed_evolve(struct linux_efi_random_seed *seed_table) {
        static const char label[] = "systemd-stub random seed evolve label v1";

        assert(seed_table);

        /* Whenever we derived something from the Linux random seed EFI table we evolve the secret in it, so
         * that the seed is never reused. */

        struct sha256_ctx hash;
        CLEANUP_ERASE(hash);
        sha256_init_ctx(&hash);
        sha256_process_bytes(label, sizeof(label) - 1, &hash);
        sha256_process_bytes(&seed_table->size, sizeof(seed_table->size), &hash);
        sha256_process_bytes(seed_table->seed, seed_table->size, &hash);
        assert(seed_table->size >= SHA256_DIGEST_SIZE);
        sha256_finish_ctx(&hash, seed_table->seed);
}

static void random_seed_make_secret(
                struct linux_efi_random_seed *seed_table,
                uint8_t ret_secret[static BOOT_SECRET_SIZE]) {

        static const char label[] = "systemd-stub random seed make secret label v1";

        assert(seed_table);
        assert(ret_secret);

        /* Derive a new secret from the Linux random seed EFI table data */

        struct sha256_ctx hash;
        CLEANUP_ERASE(hash);
        sha256_init_ctx(&hash);
        sha256_process_bytes(label, sizeof(label) - 1, &hash);
        sha256_process_bytes(&seed_table->size, sizeof(seed_table->size), &hash);
        sha256_process_bytes(seed_table->seed, seed_table->size, &hash);
        sha256_finish_ctx(&hash, ret_secret);

        random_seed_evolve(seed_table); /* ← ensure the same seed is not reused */
}

static EFI_STATUS read_efivar_secret(uint8_t ret_secret[static BOOT_SECRET_SIZE]) {
        EFI_STATUS err;

        assert(ret_secret);

        /* Reads the boot secret from the EFI variable, ensuring it's properly protected from the OS, as per
         * the attribute flags */

        _cleanup_free_ void* data = NULL;
        uint32_t attributes;
        size_t size = 0;
        err = efivar_get_raw_full(MAKE_GUID_PTR(LOADER), u"LoaderBootSecret", &attributes, &data, &size);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to read LoaderBootSecret EFI variable: %m");

        if (size != BOOT_SECRET_SIZE) {
                err = log_debug_status(EFI_PROTOCOL_ERROR, "Unexpected size of BootSecret EFI variable, ignoring.");
                goto finish;
        }

        if ((attributes & (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS)) !=
            (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS)) {
                err = log_debug_status(EFI_PROTOCOL_ERROR, "Unexpected attributes of BootSecret EFI variable, ignoring.");
                goto finish;
        }

        memcpy(ret_secret, data, size);
        err = EFI_SUCCESS;
finish:
        explicit_bzero_safe(data, size);
        return err;
}

static EFI_STATUS setup_efivar_secret(
                struct linux_efi_random_seed *seed_table,
                uint8_t ret_secret[static BOOT_SECRET_SIZE]) {

        EFI_STATUS err;

        assert(seed_table);
        assert(ret_secret);

        /* Generates a new EFI variable secret, and stores it in an EFI variable. */

        uint8_t secret[BOOT_SECRET_SIZE];
        CLEANUP_ERASE(secret);
        random_seed_make_secret(seed_table, secret);

        /* Set the variable with the EFI_VARIABLE_RUNTIME_ACCESS flag off (!), so that it's invisible after
         * ExitBootServices()! */
        err = RT->SetVariable(
                        (char16_t*) u"LoaderBootSecret",
                        MAKE_GUID_PTR(LOADER),
                        EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS, /* ← No EFI_VARIABLE_RUNTIME_ACCESS here */
                        sizeof(secret),
                        secret);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to set boot secret EFI variable: %m");

        memcpy(ret_secret, secret, sizeof(secret));
        return EFI_SUCCESS;
}

static EFI_STATUS acquire_efivar_secret(
                struct linux_efi_random_seed *seed_table,
                uint8_t ret_secret[static BOOT_SECRET_SIZE]) {

        EFI_STATUS err;

        assert(seed_table);
        assert(ret_secret);

        /* Try to read the boot secret EFI variable, but if it doesn't exist create a new one */

        err = read_efivar_secret(ret_secret);
        if (err != EFI_NOT_FOUND)
                return err;

        return setup_efivar_secret(seed_table, ret_secret);
}

static EFI_STATUS setup_secret_mixin(
                EFI_FILE *handle,
                struct linux_efi_random_seed *seed_table,
                uint8_t ret_mixin[static BOOT_SECRET_SIZE]) {

        EFI_STATUS err;

        assert(handle);
        assert(seed_table);
        assert(ret_mixin);

        /* This writes a new 'mixin' to the ESP, in case the ESP so far had none */

        uint8_t mixin[BOOT_SECRET_SIZE];
        random_seed_make_secret(seed_table, mixin);

        size_t wsize = sizeof(mixin);
        err = handle->Write(handle, &wsize, mixin);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to write secret mixin file: %m");
        if (wsize != sizeof(mixin))
                return log_debug_status(EFI_LOAD_ERROR, "Short write while writing secret mixin file: %m");

        err = handle->Flush(handle);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to flush secret mixin file: %m");

        memcpy(ret_mixin, mixin, sizeof(mixin));
        return EFI_SUCCESS;
}

static EFI_STATUS acquire_secret_mixin(
                EFI_FILE *root_dir,
                struct linux_efi_random_seed *seed_table,
                uint8_t ret_mixin[static BOOT_SECRET_SIZE]) {

        EFI_STATUS err;

        assert(seed_table);
        assert(ret_mixin);

        if (!root_dir)
                return EFI_NOT_FOUND;

        /* Acquires the mixin for the boot secret stored in the ESP. If it already exists we'll read it. If
         * it doesn't we'll initialize it */

        bool writable;
        _cleanup_file_close_ EFI_FILE *handle = NULL;
        err = root_dir->Open(
                        root_dir,
                        &handle,
                        (char16_t *) BOOT_SECRET_MIXIN_PATH,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        /* Attributes= */ 0);
        if (err == EFI_WRITE_PROTECTED) {
                err = root_dir->Open(
                                root_dir,
                                &handle,
                                (char16_t *) BOOT_SECRET_MIXIN_PATH,
                                EFI_FILE_MODE_READ,
                                /* Attributes= */ 0);
                if (err != EFI_SUCCESS)
                        return log_debug_status(err, "Failed to read the boot secret mixin file '%ls': %m", BOOT_SECRET_MIXIN_PATH);

                writable = false;
        } else if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to access the boot secret mixin file '%ls': %m", BOOT_SECRET_MIXIN_PATH);
        else
                writable = true;

        _cleanup_free_ EFI_FILE_INFO *info = NULL;
        err = get_file_info(handle, &info, /* ret_size= */ NULL);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to get boot secret mixin file '%ls' info: %m", BOOT_SECRET_MIXIN_PATH);
        if (info->FileSize == 0 && writable) /* New file? Fill it. */
                return setup_secret_mixin(handle, seed_table, ret_mixin);

        /* If the mixin file is too small we won't overwrite it (in order to not destroy some potentially
         * load bearing key), but we won't use it either. */
        if (info->FileSize < BOOT_SECRET_SIZE)
                return log_debug_status(EFI_PROTOCOL_ERROR, "Boot secret mixin file '%ls' is too short %" PRIu64 " < %u", BOOT_SECRET_MIXIN_PATH, info->FileSize, BOOT_SECRET_SIZE);

        uint8_t mixin[BOOT_SECRET_SIZE];
        size_t rsize = sizeof(mixin);
        err = handle->Read(handle, &rsize, mixin);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to read boot secret mixin file '%ls': %m", BOOT_SECRET_MIXIN_PATH);
        if (rsize != BOOT_SECRET_SIZE)
                return log_debug_status(EFI_PROTOCOL_ERROR, "Unexpected size from Read(): %zu != %zu", rsize, sizeof(mixin));

        memcpy(ret_mixin, mixin, BOOT_SECRET_SIZE);
        return EFI_SUCCESS;
}

static char* pick_id(const char *_osrel, size_t osrel_size) {
        assert(_osrel || osrel_size == 0);

        /* Make a NUL terminated copy we can chop into pieces */
        _cleanup_free_ char *osrel = NULL;
        osrel = xmalloc(osrel_size + 1);
        if (osrel_size > 0)
                memcpy(osrel, _osrel, osrel_size);
        osrel[osrel_size] = 0;

        /* Find an OS ID. Preferably the IMAGE_ID. */
        _cleanup_free_ char *os_id = NULL;
        char *line, *key, *value;
        size_t pos = 0;
        while ((line = line_get_key_value(osrel, "=", &pos, &key, &value))) {
                if (streq8(key, "IMAGE_ID"))
                        return xstrdup8(value);

                if (streq8(key, "ID")) {
                        free(os_id);
                        os_id = xstrdup8(value);
                }
        }

        /* If the IMAGE_ID= wasn't set, use the OS ID=. If that one isn't set either fall back to "linux". */
        return TAKE_PTR(os_id) ?: xstrdup8("linux");
}

static void derive_secret(
                uint8_t efivar_secret[static BOOT_SECRET_SIZE],
                uint8_t secret_mixin[static BOOT_SECRET_SIZE],
                const char *id,
                uint8_t ret[static BOOT_SECRET_SIZE]) {

        static const char hash_label[] = "systemd-stub derive secret label v1";

        assert(efivar_secret);
        assert(secret_mixin);
        assert(id);
        assert(ret);

        /* Now combine the EFI variable secret, the mixin from the ESP and the OS id to generate the secret
         * to pass to the OS */

        struct sha256_ctx hash;
        CLEANUP_ERASE(hash);
        sha256_init_ctx(&hash);
        sha256_process_bytes(hash_label, sizeof(hash_label) - 1, &hash);
        sha256_process_bytes(efivar_secret, BOOT_SECRET_SIZE, &hash);
        sha256_process_bytes(secret_mixin, BOOT_SECRET_SIZE, &hash);

        /* Include an OS id in the hash, so that every OS gets a different derived secret */
        size_t size = strlen8(id);
        sha256_process_bytes(&size, sizeof(size), &hash);
        sha256_process_bytes(id, size, &hash);

        assert_cc(SHA256_DIGEST_SIZE == BOOT_SECRET_SIZE);
        sha256_finish_ctx(&hash, ret);
}

EFI_STATUS prepare_boot_secret(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *osrel_section,
                uint8_t ret[static BOOT_SECRET_SIZE]) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(ret);

        /* Prepares the boot secret to pass to the OS */

        if (!loaded_image->DeviceHandle)
                return EFI_SUCCESS;

        _cleanup_file_close_ EFI_FILE *root = NULL;
        err = open_volume(loaded_image->DeviceHandle, &root);
        if (err != EFI_SUCCESS)
                return err;

        /* We need the Linux random seed EFI table, so that we can initialize the EFI variable secret and
         * generate the secret mixin. */
        struct linux_efi_random_seed *seed_table = NULL;
        err = random_seed_find_table(&seed_table);
        if (err != EFI_SUCCESS)
                return err;

        uint8_t efivar_secret[BOOT_SECRET_SIZE];
        CLEANUP_ERASE(efivar_secret);
        err = acquire_efivar_secret(seed_table, efivar_secret);
        if (err != EFI_SUCCESS)
                return err;

        uint8_t secret_mixin[BOOT_SECRET_SIZE];
        err = acquire_secret_mixin(root, seed_table, secret_mixin);
        if (err != EFI_SUCCESS)
                return err;

        const char *osrel = NULL;
        size_t osrel_size = 0;
        if (PE_SECTION_VECTOR_IS_SET(osrel_section)) {
                osrel = (const char*) loaded_image->ImageBase + osrel_section->memory_offset;
                osrel_size = osrel_section->memory_size;
        }
        _cleanup_free_ char *id = pick_id(osrel, osrel_size);

        derive_secret(efivar_secret, secret_mixin, id, ret);
        return EFI_SUCCESS;
}

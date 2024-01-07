/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util-fundamental.h"
#include "proto/rng.h"
#include "random-seed.h"
#include "secure-boot.h"
#include "sha256.h"
#include "util.h"

#define RANDOM_MAX_SIZE_MIN (32U)
#define RANDOM_MAX_SIZE_MAX (32U*1024U)

struct linux_efi_random_seed {
        uint32_t size;
        uint8_t seed[];
};

#define LINUX_EFI_RANDOM_SEED_TABLE_GUID \
        { 0x1ce1e5bc, 0x7ceb, 0x42f2, { 0x81, 0xe5, 0x8a, 0xad, 0xf1, 0x80, 0xf5, 0x7b } }

/* SHA256 gives us 256/8=32 bytes */
#define HASH_VALUE_SIZE 32

/* Linux's RNG is 256 bits, so let's provide this much */
#define DESIRED_SEED_SIZE 32

/* Some basic domain separation in case somebody uses this data elsewhere */
#define HASH_LABEL "systemd-boot random seed label v1"

static EFI_STATUS acquire_rng(void *ret, size_t size) {
        EFI_RNG_PROTOCOL *rng;
        EFI_STATUS err;

        assert(ret);

        /* Try to acquire the specified number of bytes from the UEFI RNG */

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_RNG_PROTOCOL), NULL, (void **) &rng);
        if (err != EFI_SUCCESS)
                return err;
        if (!rng)
                return EFI_UNSUPPORTED;

        err = rng->GetRNG(rng, NULL, size, ret);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to acquire RNG data: %m");
        return EFI_SUCCESS;
}

static EFI_STATUS acquire_system_token(void **ret, size_t *ret_size) {
        _cleanup_free_ void *data = NULL;
        EFI_STATUS err;
        size_t size;

        assert(ret);
        assert(ret_size);

        err = efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderSystemToken", &data, &size);
        if (err != EFI_SUCCESS) {
                if (err != EFI_NOT_FOUND)
                        log_error_status(err, "Failed to read LoaderSystemToken EFI variable: %m");
                return err;
        }

        if (size <= 0)
                return log_error_status(EFI_NOT_FOUND, "System token too short, ignoring.");

        *ret = TAKE_PTR(data);
        *ret_size = size;

        return EFI_SUCCESS;
}

static void validate_sha256(void) {

#ifdef EFI_DEBUG
        /* Let's validate our SHA256 implementation. We stole it from glibc, and converted it to UEFI
         * style. We better check whether it does the right stuff. We use the simpler test vectors from the
         * SHA spec. Note that we strip this out in optimization builds. */

        static const struct {
                const char *string;
                uint8_t hash[HASH_VALUE_SIZE];
        } array[] = {
                { "abc",
                  { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }},

                { "",
                  { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 }},

                { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                  { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }},

                { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                  { 0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
                    0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
                    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
                    0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1 }},
        };

        for (size_t i = 0; i < ELEMENTSOF(array); i++)
                assert(memcmp(SHA256_DIRECT(array[i].string, strlen8(array[i].string)), array[i].hash, HASH_VALUE_SIZE) == 0);
#endif
}

EFI_STATUS process_random_seed(EFI_FILE *root_dir) {
        uint8_t random_bytes[DESIRED_SEED_SIZE], hash_key[HASH_VALUE_SIZE];
        _cleanup_free_ struct linux_efi_random_seed *new_seed_table = NULL;
        struct linux_efi_random_seed *previous_seed_table = NULL;
        _cleanup_free_ void *seed = NULL, *system_token = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ EFI_FILE_INFO *info = NULL;
        struct sha256_ctx hash;
        uint64_t uefi_monotonic_counter = 0;
        size_t size, rsize, wsize;
        bool seeded_by_efi = false;
        EFI_STATUS err;
        EFI_TIME now;

        CLEANUP_ERASE(random_bytes);
        CLEANUP_ERASE(hash_key);
        CLEANUP_ERASE(hash);

        assert(root_dir);
        assert_cc(DESIRED_SEED_SIZE == HASH_VALUE_SIZE);

        validate_sha256();

        /* hash = LABEL || sizeof(input1) || input1 || ... || sizeof(inputN) || inputN */
        sha256_init_ctx(&hash);

        /* Some basic domain separation in case somebody uses this data elsewhere */
        sha256_process_bytes(HASH_LABEL, sizeof(HASH_LABEL) - 1, &hash);

        previous_seed_table = find_configuration_table(MAKE_GUID_PTR(LINUX_EFI_RANDOM_SEED_TABLE));
        if (!previous_seed_table) {
                size = 0;
                sha256_process_bytes(&size, sizeof(size), &hash);
        } else {
                size = previous_seed_table->size;
                seeded_by_efi = size >= DESIRED_SEED_SIZE;
                sha256_process_bytes(&size, sizeof(size), &hash);
                sha256_process_bytes(previous_seed_table->seed, size, &hash);

                /* Zero and free the previous seed table only at the end after we've managed to install a new
                 * one, so that in case this function fails or aborts, Linux still receives whatever the
                 * previous bootloader chain set. So, the next line of this block is not an explicit_bzero()
                 * call. */
        }

        /* Request some random data from the UEFI RNG. We don't need this to work safely, but it's a good
         * idea to use it because it helps us for cases where users mistakenly include a random seed in
         * golden master images that are replicated many times. */
        err = acquire_rng(random_bytes, sizeof(random_bytes));
        if (err != EFI_SUCCESS) {
                size = 0;
                /* If we can't get any randomness from EFI itself, then we'll only be relying on what's in
                 * ESP. But ESP is mutable, so if secure boot is enabled, we probably shouldn't trust that
                 * alone, in which case we bail out early. */
                if (!seeded_by_efi && secure_boot_enabled())
                        return EFI_NOT_FOUND;
        } else {
                seeded_by_efi = true;
                size = sizeof(random_bytes);
        }
        sha256_process_bytes(&size, sizeof(size), &hash);
        sha256_process_bytes(random_bytes, size, &hash);

        /* Get some system specific seed that the installer might have placed in an EFI variable. We include
         * it in our hash. This is protection against golden master image sloppiness, and it remains on the
         * system, even when disk images are duplicated or swapped out. */
        size = 0;
        err = acquire_system_token(&system_token, &size);
        if ((err != EFI_SUCCESS || size < DESIRED_SEED_SIZE) && !seeded_by_efi)
                return err;
        sha256_process_bytes(&size, sizeof(size), &hash);
        if (system_token) {
                sha256_process_bytes(system_token, size, &hash);
                explicit_bzero_safe(system_token, size);
        }

        err = root_dir->Open(
                        root_dir,
                        &handle,
                        (char16_t *) u"\\loader\\random-seed",
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0);
        if (err != EFI_SUCCESS) {
                if (err != EFI_NOT_FOUND && err != EFI_WRITE_PROTECTED)
                        log_error_status(err, "Failed to open random seed file: %m");
                return err;
        }

        err = get_file_info(handle, &info, NULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to get file info for random seed: %m");

        size = info->FileSize;
        if (size < RANDOM_MAX_SIZE_MIN)
                return log_error("Random seed file is too short.");

        if (size > RANDOM_MAX_SIZE_MAX)
                return log_error("Random seed file is too large.");

        seed = xmalloc(size);
        rsize = size;
        err = handle->Read(handle, &rsize, seed);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to read random seed file: %m");
        if (rsize != size) {
                explicit_bzero_safe(seed, rsize);
                return log_error_status(EFI_PROTOCOL_ERROR, "Short read on random seed file.");
        }

        sha256_process_bytes(&size, sizeof(size), &hash);
        sha256_process_bytes(seed, size, &hash);
        explicit_bzero_safe(seed, size);

        err = handle->SetPosition(handle, 0);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to seek to beginning of random seed file: %m");

        /* Let's also include the UEFI monotonic counter (which is supposedly increasing on every single
         * boot) in the hash, so that even if the changes to the ESP for some reason should not be
         * persistent, the random seed we generate will still be different on every single boot. */
        err = BS->GetNextMonotonicCount(&uefi_monotonic_counter);
        if (err != EFI_SUCCESS && !seeded_by_efi)
                return log_error_status(err, "Failed to acquire UEFI monotonic counter: %m");
        size = sizeof(uefi_monotonic_counter);
        sha256_process_bytes(&size, sizeof(size), &hash);
        sha256_process_bytes(&uefi_monotonic_counter, size, &hash);

        err = RT->GetTime(&now, NULL);
        size = err == EFI_SUCCESS ? sizeof(now) : 0; /* Known to be flaky, so don't bark on error. */
        sha256_process_bytes(&size, sizeof(size), &hash);
        sha256_process_bytes(&now, size, &hash);

        /* hash_key = HASH(hash) */
        sha256_finish_ctx(&hash, hash_key);

        /* hash = hash_key || 0 */
        sha256_init_ctx(&hash);
        sha256_process_bytes(hash_key, sizeof(hash_key), &hash);
        sha256_process_bytes(&(const uint8_t){ 0 }, sizeof(uint8_t), &hash);
        /* random_bytes = HASH(hash) */
        sha256_finish_ctx(&hash, random_bytes);

        size = sizeof(random_bytes);
        /* If the file size is too large, zero out the remaining bytes on disk. */
        if (size < info->FileSize) {
                err = handle->SetPosition(handle, size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to seek to offset of random seed file: %m");
                wsize = info->FileSize - size;
                err = handle->Write(handle, &wsize, seed /* All zeros now */);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to write random seed file: %m");
                if (wsize != info->FileSize - size)
                        return log_error_status(EFI_PROTOCOL_ERROR, "Short write on random seed file.");
                err = handle->Flush(handle);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to flush random seed file: %m");
                err = handle->SetPosition(handle, 0);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to seek to beginning of random seed file: %m");

                /* We could truncate the file here with something like:
                 *
                 *     info->FileSize = size;
                 *     err = handle->SetInfo(handle, &GenericFileInfo, info->Size, info);
                 *     if (err != EFI_SUCCESS)
                 *             return log_error_status(err, "Failed to truncate random seed file: %u");
                 *
                 * But this is considered slightly risky, because EFI filesystem drivers are a little bit
                 * flimsy. So instead we rely on userspace eventually truncating this when it writes a new
                 * seed. For now the best we do is zero it. */
        }
        /* Update the random seed on disk before we use it */
        wsize = size;
        err = handle->Write(handle, &wsize, random_bytes);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to write random seed file: %m");
        if (wsize != size)
                return log_error_status(EFI_PROTOCOL_ERROR, "Short write on random seed file.");
        err = handle->Flush(handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to flush random seed file: %m");

        err = BS->AllocatePool(EfiACPIReclaimMemory,
                               offsetof(struct linux_efi_random_seed, seed) + DESIRED_SEED_SIZE,
                               (void **) &new_seed_table);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to allocate EFI table for random seed: %m");
        new_seed_table->size = DESIRED_SEED_SIZE;

        /* hash = hash_key || 1 */
        sha256_init_ctx(&hash);
        sha256_process_bytes(hash_key, sizeof(hash_key), &hash);
        sha256_process_bytes(&(const uint8_t){ 1 }, sizeof(uint8_t), &hash);
        /* new_seed_table->seed = HASH(hash) */
        sha256_finish_ctx(&hash, new_seed_table->seed);

        err = BS->InstallConfigurationTable(MAKE_GUID_PTR(LINUX_EFI_RANDOM_SEED_TABLE), new_seed_table);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to install EFI table for random seed: %m");
        TAKE_PTR(new_seed_table);

        if (previous_seed_table) {
                /* Now that we've succeeded in installing the new table, we can safely nuke the old one. */
                explicit_bzero_safe(previous_seed_table->seed, previous_seed_table->size);
                explicit_bzero_safe(previous_seed_table, sizeof(*previous_seed_table));
                free(previous_seed_table);
        }

        return EFI_SUCCESS;
}

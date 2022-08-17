/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "missing_efi.h"
#include "random-seed.h"
#include "secure-boot.h"
#include "sha256.h"
#include "util.h"

#define RANDOM_MAX_SIZE_MIN (32U)
#define RANDOM_MAX_SIZE_MAX (32U*1024U)

#define EFI_RNG_GUID &(const EFI_GUID) EFI_RNG_PROTOCOL_GUID

/* SHA256 gives us 256/8=32 bytes */
#define HASH_VALUE_SIZE 32

static EFI_STATUS acquire_rng(UINTN size, void **ret) {
        _cleanup_free_ void *data = NULL;
        EFI_RNG_PROTOCOL *rng;
        EFI_STATUS err;

        assert(ret);

        /* Try to acquire the specified number of bytes from the UEFI RNG */

        err = BS->LocateProtocol((EFI_GUID *) EFI_RNG_GUID, NULL, (void **) &rng);
        if (err != EFI_SUCCESS)
                return err;
        if (!rng)
                return EFI_UNSUPPORTED;

        data = xmalloc(size);

        err = rng->GetRNG(rng, NULL, size, data);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to acquire RNG data: %r", err);

        *ret = TAKE_PTR(data);
        return EFI_SUCCESS;
}

static void hash_once(
                const void *old_seed,
                const void *rng,
                UINTN size,
                const void *system_token,
                UINTN system_token_size,
                uint64_t uefi_monotonic_counter,
                UINTN counter,
                uint8_t ret[static HASH_VALUE_SIZE]) {

        /* This hashes together:
         *
         *      1. The contents of the old seed file
         *      2. Some random data acquired from the UEFI RNG (optional)
         *      3. Some 'system token' the installer installed as EFI variable (optional)
         *      4. The UEFI "monotonic counter" that increases with each boot
         *      5. A supplied counter value
         *
         * And writes the result to the specified buffer.
         */

        struct sha256_ctx hash;

        assert(old_seed);
        assert(system_token_size == 0 || system_token);

        sha256_init_ctx(&hash);
        sha256_process_bytes(old_seed, size, &hash);
        if (rng)
                sha256_process_bytes(rng, size, &hash);
        if (system_token_size > 0)
                sha256_process_bytes(system_token, system_token_size, &hash);
        sha256_process_bytes(&uefi_monotonic_counter, sizeof(uefi_monotonic_counter), &hash);
        sha256_process_bytes(&counter, sizeof(counter), &hash);
        sha256_finish_ctx(&hash, ret);
}

static EFI_STATUS hash_many(
                const void *old_seed,
                const void *rng,
                UINTN size,
                const void *system_token,
                UINTN system_token_size,
                uint64_t uefi_monotonic_counter,
                UINTN counter_start,
                UINTN n,
                void **ret) {

        _cleanup_free_ void *output = NULL;

        assert(old_seed);
        assert(system_token_size == 0 || system_token);
        assert(ret);

        /* Hashes the specified parameters in counter mode, generating n hash values, with the counter in the
         * range counter_start…counter_start+n-1. */

        output = xmalloc_multiply(HASH_VALUE_SIZE, n);

        for (UINTN i = 0; i < n; i++)
                hash_once(old_seed, rng, size,
                          system_token, system_token_size,
                          uefi_monotonic_counter,
                          counter_start + i,
                          (uint8_t*) output + (i * HASH_VALUE_SIZE));

        *ret = TAKE_PTR(output);
        return EFI_SUCCESS;
}

static EFI_STATUS mangle_random_seed(
                const void *old_seed,
                const void *rng,
                UINTN size,
                const void *system_token,
                UINTN system_token_size,
                uint64_t uefi_monotonic_counter,
                void **ret_new_seed,
                void **ret_for_kernel) {

        _cleanup_free_ void *new_seed = NULL, *for_kernel = NULL;
        EFI_STATUS err;
        UINTN n;

        assert(old_seed);
        assert(system_token_size == 0 || system_token);
        assert(ret_new_seed);
        assert(ret_for_kernel);

        /* This takes the old seed file contents, an (optional) random number acquired from the UEFI RNG, an
         * (optional) system 'token' installed once by the OS installer in an EFI variable, and hashes them
         * together in counter mode, generating a new seed (to replace the file on disk) and the seed for the
         * kernel. To keep things simple, the new seed and kernel data have the same size as the old seed and
         * RNG data. */

        n = (size + HASH_VALUE_SIZE - 1) / HASH_VALUE_SIZE;

        /* Begin hashing in counter mode at counter 0 for the new seed for the disk */
        err = hash_many(old_seed, rng, size, system_token, system_token_size, uefi_monotonic_counter, 0, n, &new_seed);
        if (err != EFI_SUCCESS)
                return err;

        /* Continue counting at 'n' for the seed for the kernel */
        err = hash_many(old_seed, rng, size, system_token, system_token_size, uefi_monotonic_counter, n, n, &for_kernel);
        if (err != EFI_SUCCESS)
                return err;

        *ret_new_seed = TAKE_PTR(new_seed);
        *ret_for_kernel = TAKE_PTR(for_kernel);

        return EFI_SUCCESS;
}

static EFI_STATUS acquire_system_token(void **ret, UINTN *ret_size) {
        _cleanup_free_ char *data = NULL;
        EFI_STATUS err;
        UINTN size;

        assert(ret);
        assert(ret_size);

        err = efivar_get_raw(LOADER_GUID, L"LoaderSystemToken", &data, &size);
        if (err != EFI_SUCCESS) {
                if (err != EFI_NOT_FOUND)
                        log_error_stall(L"Failed to read LoaderSystemToken EFI variable: %r", err);
                return err;
        }

        if (size <= 0)
                return log_error_status_stall(EFI_NOT_FOUND, L"System token too short, ignoring.");

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

        for (UINTN i = 0; i < ELEMENTSOF(array); i++)
                assert(memcmp(SHA256_DIRECT(array[i].string, strlen8(array[i].string)), array[i].hash, HASH_VALUE_SIZE) == 0);
#endif
}

EFI_STATUS process_random_seed(EFI_FILE *root_dir, RandomSeedMode mode) {
        _cleanup_free_ void *seed = NULL, *new_seed = NULL, *rng = NULL, *for_kernel = NULL, *system_token = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        UINTN size, rsize, wsize, system_token_size = 0;
        _cleanup_free_ EFI_FILE_INFO *info = NULL;
        uint64_t uefi_monotonic_counter = 0;
        EFI_STATUS err;

        assert(root_dir);

        validate_sha256();

        if (mode == RANDOM_SEED_OFF)
                return EFI_NOT_FOUND;

        /* Let's better be safe than sorry, and for now disable this logic in SecureBoot mode, so that we
         * don't credit a random seed that is not authenticated. */
        if (secure_boot_enabled())
                return EFI_NOT_FOUND;

        /* Get some system specific seed that the installer might have placed in an EFI variable. We include
         * it in our hash. This is protection against golden master image sloppiness, and it remains on the
         * system, even when disk images are duplicated or swapped out. */
        err = acquire_system_token(&system_token, &system_token_size);
        if (mode != RANDOM_SEED_ALWAYS && err != EFI_SUCCESS)
                return err;

        err = root_dir->Open(
                        root_dir,
                        &handle,
                        (char16_t *) L"\\loader\\random-seed",
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0);
        if (err != EFI_SUCCESS) {
                if (err != EFI_NOT_FOUND && err != EFI_WRITE_PROTECTED)
                        log_error_stall(L"Failed to open random seed file: %r", err);
                return err;
        }

        err = get_file_info_harder(handle, &info, NULL);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to get file info for random seed: %r");

        size = info->FileSize;
        if (size < RANDOM_MAX_SIZE_MIN)
                return log_error_status_stall(EFI_INVALID_PARAMETER, L"Random seed file is too short.");

        if (size > RANDOM_MAX_SIZE_MAX)
                return log_error_status_stall(EFI_INVALID_PARAMETER, L"Random seed file is too large.");

        seed = xmalloc(size);

        rsize = size;
        err = handle->Read(handle, &rsize, seed);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to read random seed file: %r", err);
        if (rsize != size)
                return log_error_status_stall(EFI_PROTOCOL_ERROR, L"Short read on random seed file.");

        err = handle->SetPosition(handle, 0);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to seek to beginning of random seed file: %r", err);

        /* Request some random data from the UEFI RNG. We don't need this to work safely, but it's a good
         * idea to use it because it helps us for cases where users mistakenly include a random seed in
         * golden master images that are replicated many times. */
        (void) acquire_rng(size, &rng); /* It's fine if this fails */

        /* Let's also include the UEFI monotonic counter (which is supposedly increasing on every single
         * boot) in the hash, so that even if the changes to the ESP for some reason should not be
         * persistent, the random seed we generate will still be different on every single boot. */
        err = BS->GetNextMonotonicCount(&uefi_monotonic_counter);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to acquire UEFI monotonic counter: %r", err);

        /* Calculate new random seed for the disk and what to pass to the kernel */
        err = mangle_random_seed(seed, rng, size, system_token, system_token_size, uefi_monotonic_counter, &new_seed, &for_kernel);
        if (err != EFI_SUCCESS)
                return err;

        /* Update the random seed on disk before we use it */
        wsize = size;
        err = handle->Write(handle, &wsize, new_seed);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to write random seed file: %r", err);
        if (wsize != size)
                return log_error_status_stall(EFI_PROTOCOL_ERROR, L"Short write on random seed file.");

        err = handle->Flush(handle);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to flush random seed file: %r", err);

        /* We are good to go */
        err = efivar_set_raw(LOADER_GUID, L"LoaderRandomSeed", for_kernel, size, 0);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Failed to write random seed to EFI variable: %r", err);

        return EFI_SUCCESS;
}

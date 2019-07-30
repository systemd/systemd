#include <efi.h>
#include <efilib.h>

#include "missing_efi.h"
#include "random-seed.h"
#include "sha256.h"
#include "util.h"
#include "shim.h"

#define RANDOM_MAX_SIZE_MIN (32U)
#define RANDOM_MAX_SIZE_MAX (32U*1024U)

static const EFI_GUID rng_protocol_guid = EFI_RNG_PROTOCOL_GUID;

/* SHA256 gives us 256/8=32 bytes */
#define HASH_VALUE_SIZE 32

static EFI_STATUS acquire_rng(UINTN size, VOID **ret) {
        _cleanup_freepool_ VOID *data = NULL;
        EFI_RNG_PROTOCOL *rng;
        EFI_STATUS err;

        /* Try to acquire the specified number of bytes from the UEFI RNG */

        err = LibLocateProtocol((EFI_GUID*) &rng_protocol_guid, (VOID**) &rng);
        if (EFI_ERROR(err)) {
                Print(L"Failed to acquire RNG protocol: %r\n", err);
                return err;
        }
        if (!rng) {
                /* Print(L"RNG protocol not available.\n"); */
                return EFI_UNSUPPORTED;
        }

        data = AllocatePool(size);
        if (!data)
                return log_oom();

        err = uefi_call_wrapper(rng->GetRNG, 3, rng, NULL, size, data);
        if (EFI_ERROR(err)) {
                Print(L"Failed to acquire RNG data: %r\n", err);
                return err;
        }

        *ret = TAKE_PTR(data);
        return EFI_SUCCESS;
}

static VOID hash_once(
                const VOID *old_seed,
                const VOID *rng,
                UINTN size,
                const VOID *system_token,
                UINTN system_token_size,
                UINTN counter,
                UINT8 ret[static HASH_VALUE_SIZE]) {

        /* This hashes together:
         *
         *      1. The contents of the old seed file
         *      2. Some random data acquired from the UEFI RNG (optional)
         *      3. Some 'system token' the installer installed as EFI variable (optional)
         *      4. A counter value
         *
         * And writes the result to the specified buffer.
         */

        struct sha256_ctx hash;

        sha256_init_ctx(&hash);
        sha256_process_bytes(old_seed, size, &hash);
        if (rng)
                sha256_process_bytes(rng, size, &hash);
        if (system_token_size > 0)
                sha256_process_bytes(system_token, system_token_size, &hash);
        sha256_process_bytes(&counter, sizeof(counter), &hash);
        sha256_finish_ctx(&hash, ret);
}

static EFI_STATUS hash_many(
                const VOID *old_seed,
                const VOID *rng,
                UINTN size,
                const VOID *system_token,
                UINTN system_token_size,
                UINTN counter_start,
                UINTN n,
                VOID **ret) {

        _cleanup_freepool_ VOID *output = NULL;
        UINTN i;

        /* Hashes the specified parameters in counter mode, generating n hash values, with the counter in the
         * range counter_start…counter_start+n-1. */

        output = AllocatePool(n * HASH_VALUE_SIZE);
        if (!output)
                return log_oom();

        for (i = 0; i < n; i++)
                hash_once(old_seed, rng, size,
                          system_token, system_token_size,
                          counter_start + i,
                          (UINT8*) output + (i * HASH_VALUE_SIZE));

        *ret = TAKE_PTR(output);
        return EFI_SUCCESS;
}

static EFI_STATUS mangle_random_seed(
                const VOID *old_seed,
                const VOID *rng,
                UINTN size,
                const VOID *system_token,
                UINTN system_token_size,
                VOID **ret_new_seed,
                VOID **ret_for_kernel) {

        _cleanup_freepool_ VOID *new_seed = NULL, *for_kernel = NULL;
        EFI_STATUS err;
        UINTN n;

        /* This takes the old seed file contents, an (optional) random number acquired from the UEFI RNG, an
         * (optional) system 'token' installed once by the OS installer in an EFI variable, and hashes them
         * together in counter mode, generating a new seed (to replace the file on disk) and the seed for the
         * kernel. To keep things simple, the new seed and kernel data have the same size as the old seed and
         * RNG data. */

        n = (size + HASH_VALUE_SIZE - 1) / HASH_VALUE_SIZE;

        /* Begin hashing in counter mode at counter 0 for the new seed for the disk */
        err = hash_many(old_seed, rng, size, system_token, system_token_size, 0, n, &new_seed);
        if (EFI_ERROR(err))
                return err;

        /* Continue counting at 'n' for the seed for the kernel */
        err = hash_many(old_seed, rng, size, system_token, system_token_size, n, n, &for_kernel);
        if (EFI_ERROR(err))
                return err;

        *ret_new_seed = TAKE_PTR(new_seed);
        *ret_for_kernel = TAKE_PTR(for_kernel);

        return EFI_SUCCESS;
}

EFI_STATUS acquire_system_token(VOID **ret, UINTN *ret_size) {
        _cleanup_freepool_ CHAR8 *data = NULL;
        EFI_STATUS err;
        UINTN size;

        err = efivar_get_raw(&loader_guid, L"LoaderSystemToken", &data, &size);
        if (EFI_ERROR(err)) {
                if (err != EFI_NOT_FOUND)
                        Print(L"Failed to read LoaderSystemToken EFI variable: %r", err);
                return err;
        }

        if (size <= 0) {
                Print(L"System token too short, ignoring.");
                return EFI_NOT_FOUND;
        }

        *ret = TAKE_PTR(data);
        *ret_size = size;

        return EFI_SUCCESS;
}

static VOID validate_sha256(void) {

#ifndef __OPTIMIZE__
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

        UINTN i;

        for (i = 0; i < ELEMENTSOF(array); i++) {
                struct sha256_ctx hash;
                uint8_t result[HASH_VALUE_SIZE];

                sha256_init_ctx(&hash);
                sha256_process_bytes(array[i].string, strlena((const CHAR8*) array[i].string), &hash);
                sha256_finish_ctx(&hash, result);

                if (CompareMem(result, array[i].hash, HASH_VALUE_SIZE) != 0) {
                        Print(L"SHA256 failed validation.\n");
                        uefi_call_wrapper(BS->Stall, 1, 120 * 1000 * 1000);
                        return;
                }
        }

        Print(L"SHA256 validated\n");
#endif
}

EFI_STATUS process_random_seed(EFI_FILE *root_dir, RandomSeedMode mode) {
        _cleanup_freepool_ VOID *seed = NULL, *new_seed = NULL, *rng = NULL, *for_kernel = NULL, *system_token = NULL;
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        UINTN size, rsize, wsize, system_token_size = 0;
        _cleanup_freepool_ EFI_FILE_INFO *info = NULL;
        EFI_STATUS err;

        validate_sha256();

        if (mode == RANDOM_SEED_OFF) {
                /* Print(L"Random seed handling turned off.\n"); */
                return EFI_NOT_FOUND;
        }

        /* Let's better be safe than sorry, and for now disable this logic in SecureBoot mode, so that we
         * don't credit a random seed that is not authenticated. */
        if (secure_boot_enabled()) {
                /* Print(L"Not loading random seed, because we are in SecureBoot mode.\n"); */
                return EFI_NOT_FOUND;
        }

        /* Get some system specific seed that the installer might have placed in an EFI variable. We include
         * it in our hash. This is protection against golden master image sloppiness, and it remains on the
         * system, even when disk images are duplicated or swapped out. */
        err = acquire_system_token(&system_token, &system_token_size);
        if (mode != RANDOM_SEED_ALWAYS) {
                /* if (err == EFI_NOT_FOUND) */
                /*         Print(L"Not loading random seed, because no system token is set.\n"); */
                if (EFI_ERROR(err))
                        return err; /* in all other error cases we already logged */
        }

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, L"\\loader\\random-seed", EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (EFI_ERROR(err)) {
                if (err != EFI_NOT_FOUND)
                        Print(L"Failed to open random seed file: %r\n", err);
                /* else */
                /*         Print(L"Not loading random seed, because there is none.\n"); */

                return err;
        }

        info = LibFileInfo(handle);
        if (!info)
                return log_oom();

        size = info->FileSize;
        if (size < RANDOM_MAX_SIZE_MIN) {
                Print(L"Random seed file is too short?\n");
                return EFI_INVALID_PARAMETER;
        }

        if (size > RANDOM_MAX_SIZE_MAX) {
                Print(L"Random seed file is too large?\n");
                return EFI_INVALID_PARAMETER;
        }

        seed = AllocatePool(size);
        if (!seed)
                return log_oom();

        rsize = size;
        err = uefi_call_wrapper(handle->Read, 3, handle, &rsize, seed);
        if (EFI_ERROR(err)) {
                Print(L"Failed to read random seed file: %r\n", err);
                return err;
        }
        if (rsize != size) {
                Print(L"Short read on random seed file\n");
                return EFI_PROTOCOL_ERROR;
        }

        err = uefi_call_wrapper(handle->SetPosition, 2, handle, 0);
        if (EFI_ERROR(err)) {
                Print(L"Failed to seek to beginning of random seed file: %r\n", err);
                return err;
        }

        /* Request some random data from the UEFI RNG. We don't need this to work safely, but it's a good
         * idea to use it because it helps us for cases where users mistakenly include a random seed in
         * golden master images that are replicated many times. */
        (VOID) acquire_rng(size, &rng); /* It's fine if this fails */

        /* Calculate new random seed for the disk and what to pass to the kernel */
        err = mangle_random_seed(seed, rng, size, system_token, system_token_size, &new_seed, &for_kernel);
        if (EFI_ERROR(err))
                return err;

        /* Update the random seed on disk before we use it */
        wsize = size;
        err = uefi_call_wrapper(handle->Write, 3, handle, &wsize, new_seed);
        if (EFI_ERROR(err)) {
                Print(L"Failed to write random seed file: %r\n", err);
                return err;
        }
        if (wsize != size) {
                Print(L"Short write on random seed file\n");
                return EFI_PROTOCOL_ERROR;
        }

        err = uefi_call_wrapper(handle->Flush, 1, handle);
        if (EFI_ERROR(err)) {
                Print(L"Failed to flush random seed file: %r\n");
                return err;
        }

        /* We are good to go */
        err = efivar_set_raw(&loader_guid, L"LoaderRandomSeed", for_kernel, size, FALSE);
        if (EFI_ERROR(err)) {
                Print(L"Failed to write random seed to EFI variable: %r\n", err);
                return err;
        }

        return EFI_SUCCESS;
}

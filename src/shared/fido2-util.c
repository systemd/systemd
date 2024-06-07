/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fido2-util.h"
#include "fileio.h"
#include "libfido2-util.h"
#include "memory-util.h"
#include "random-util.h"

int fido2_generate_salt(void **ret_salt, size_t *ret_size) {
        _cleanup_(erase_and_freep) void *salt = NULL;
        int r;

        salt = malloc(FIDO2_SALT_SIZE);
        if (!salt)
                return log_oom();

        r = crypto_random_bytes(salt, FIDO2_SALT_SIZE);
        if (r < 0)
                return log_error_errno(r, "Failed to generate FIDO2 salt: %m");

        *ret_salt = TAKE_PTR(salt);
        *ret_size = FIDO2_SALT_SIZE;

        return 0;
}

int fido2_read_salt_file(const char *filename, uint64_t offset, size_t size, const char *client, const char *node, void **ret_salt, size_t *ret_size) {
        _cleanup_(erase_and_freep) void *salt = NULL;
        _cleanup_free_ char *bind_name = NULL;
        size_t salt_size;
        int r;

        /* If we read the salt via AF_UNIX, make the client recognizable */
        if (asprintf(&bind_name, "@%" PRIx64"/%s-fido2/%s", random_u64(), client, node) < 0)
                return log_oom();

        r = read_full_file_full(
                        AT_FDCWD, filename,
                        offset == 0 ? UINT64_MAX : offset,
                        size == 0 ? SIZE_MAX : size,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|
                        READ_FULL_FILE_CONNECT_SOCKET,
                        bind_name, (char**) &salt, &salt_size);
        if (r < 0)
                return log_error_errno(r, "Reading FIDO2 salt file '%s' failed: %m", filename);

        /* The FIDO CTAP v2.1 standard specifies that salt should be exactly 32 bytes long.
         * Instead of failing right away, let's just warn the user here. If the token is
         * spec-compliant, it will fail later when setting the salt on the assertion. */
        if (salt_size != FIDO2_SALT_SIZE)
                log_warning("Warning: using a non-standard FIDO2 salt size of %zu bytes.", salt_size);

        *ret_salt = TAKE_PTR(salt);
        *ret_size = salt_size;

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fido2-util.h"
#include "fileio.h"
#include "libfido2-util.h"
#include "random-util.h"

int fido2_generate_salt(struct iovec *ret_salt) {
        _cleanup_(iovec_done) struct iovec salt = {};
        int r;

        r = crypto_random_bytes_allocate_iovec(FIDO2_SALT_SIZE, &salt);
        if (r < 0)
                return log_error_errno(r, "Failed to generate FIDO2 salt: %m");

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}

int fido2_read_salt_file(const char *filename, uint64_t offset, const char *client, const char *node, struct iovec *ret_salt) {
        _cleanup_(iovec_done_erase) struct iovec salt = {};
        _cleanup_free_ char *bind_name = NULL;
        int r;

        /* If we read the salt via AF_UNIX, make the client recognizable */
        if (asprintf(&bind_name, "@%" PRIx64"/%s-fido2-salt/%s", random_u64(), client, node) < 0)
                return log_oom();

        r = read_full_file_full(
                        AT_FDCWD, filename,
                        offset == 0 ? UINT64_MAX : offset,
                        /* size= */ FIDO2_SALT_SIZE,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|
                        READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        bind_name, (char**) &salt.iov_base, &salt.iov_len);
        if (r == -E2BIG || (r >= 0 && salt.iov_len != FIDO2_SALT_SIZE))
                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                       "FIDO2 salt file must contain exactly %u bytes.", FIDO2_SALT_SIZE);
        if (r < 0)
                return log_error_errno(r, "Reading FIDO2 salt file '%s' failed: %m", filename);

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}

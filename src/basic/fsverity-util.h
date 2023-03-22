/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LINUX_FSVERITY_H

/* The signature is optional, and will be skipped if NULL, and the file will be immutable and measured
 * but without cryptographic validation of the digest. */
int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size);

#else

static inline int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "fsverity support is not compiled in.");
}

#endif

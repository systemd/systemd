/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LINUX_FSVERITY_H

int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size);

#else

static inline int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "fsverity support is not compiled in.");
}

#endif

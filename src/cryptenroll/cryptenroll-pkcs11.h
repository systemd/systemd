/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"

#if HAVE_P11KIT && HAVE_OPENSSL
int enroll_pkcs11(struct crypt_device *cd, const struct iovec *volume_key, const char *uri);
#else
static inline int enroll_pkcs11(struct crypt_device *cd, const struct iovec *volume_key, const char *uri) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 key enrollment not supported.");
}
#endif

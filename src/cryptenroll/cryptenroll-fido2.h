/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "libsss-util.h"
#include "cryptsetup-util.h"
#include "libfido2-util.h"
#include "log.h"

#if HAVE_LIBFIDO2
int enroll_fido2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, Factor *factor, int keyslot);
#else
static inline int enroll_fido2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, Factor *factor, int keyslot) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 key enrollment not supported.");
}
#endif

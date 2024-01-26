/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"
#include "varlink.h"

#if HAVE_P11KIT && HAVE_OPENSSL

int enroll_pkcs11(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *uri);
int vl_method_enroll_pkcs11(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata);

#else

static inline int enroll_pkcs11(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *uri) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 key enrollment not supported.");
}

static inline int vl_method_enroll_pkcs11(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata) {
        return varlink_errorb(
                        link,
                        VARLINK_ERROR_METHOD_NOT_IMPLEMENTED,
                        JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", "io.systemd.CryptEnroll.EnrollPKCS11")));
}

#endif

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "libfido2-util.h"
#include "log.h"
#include "varlink.h"

#if HAVE_LIBFIDO2
int load_volume_key_fido2(struct crypt_device *cd, const char *cd_node, const char *device, void *ret_vk, size_t *ret_vks);
int enroll_fido2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, Fido2EnrollFlags lock_with, int cred_alg);
int vl_method_enroll_fido2(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata);

#else
static inline int load_volume_key_fido2(struct crypt_device *cd, const char *cd_node, const char *device, void *ret_vk, size_t *ret_vks) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 unlocking not supported.");
}

static inline int enroll_fido2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, Fido2EnrollFlags lock_with, int cred_alg) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 key enrollment not supported.");
}

static inline int vl_method_enroll_fido2(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata) {
        return varlink_errorb(
                        link,
                        VARLINK_ERROR_METHOD_NOT_IMPLEMENTED,
                        JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", "io.systemd.CryptEnroll.EnrollFIDO2")));
}
#endif

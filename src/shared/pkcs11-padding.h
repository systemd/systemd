/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum Pkcs11RsaPadding {
        PKCS11_RSA_PADDING_PKCS1V15,    /* CKM_RSA_PKCS, RFC 8017 PKCS#1 v1.5 (legacy) */
        PKCS11_RSA_PADDING_OAEP_SHA1,   /* CKM_RSA_PKCS_OAEP with SHA-1/MGF1-SHA-1 (more supported) */
        PKCS11_RSA_PADDING_OAEP_SHA256, /* CKM_RSA_PKCS_OAEP with SHA-256/MGF1-SHA-256 (preferred if supported) */
        _PKCS11_RSA_PADDING_MAX,
        _PKCS11_RSA_PADDING_INVALID = -EINVAL,
} Pkcs11RsaPadding;

const char* pkcs11_rsa_padding_to_string(Pkcs11RsaPadding i);
Pkcs11RsaPadding pkcs11_rsa_padding_from_string(const char *s);

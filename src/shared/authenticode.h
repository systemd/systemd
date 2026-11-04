/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef SYSTEMD_CFLAGS_MARKER_LIBOPENSSL
#  error "missing libopenssl_cflags in meson dependency."
#endif

#include "crypto-util.h"
#include "forward.h"

int authenticode_spc_indirect_data_content_new(const void *digest, size_t digest_size, uint8_t **ret, size_t *ret_size);
int authenticode_pkcs7_new(
                X509 *certificate,
                EVP_PKEY *private_key,
                STACK_OF(X509_ATTRIBUTE) *signed_attributes,
                PKCS7 **ret_p7,
                PKCS7_SIGNER_INFO **ret_si);
int authenticode_pkcs7_data_bio(PKCS7 *p7, const void *idc, size_t idc_size, BIO **ret);
int authenticode_pkcs7_add_digest_attribute(BIO *data, PKCS7_SIGNER_INFO *si);
int authenticode_pkcs7_finalize(PKCS7 *p7, const void *idc, size_t idc_size, uint8_t **ret, size_t *ret_size);

/* Signs the PE file in fd and appends the signature. If signed_attributes is set, the signature uses
 * *signed_attributes instead of the default attributes, and *signed_attributes is reset to NULL. If
 * signed_attributes_signature is set, it is used as the signature of the signed attributes, and the private
 * key isn't needed. The function takes over the memory of signed_attributes_signature then. */
int authenticode_sign_pe_full(
                int fd,
                X509 *certificate,
                EVP_PKEY *private_key,
                STACK_OF(X509_ATTRIBUTE) **signed_attributes,
                struct iovec *signed_attributes_signature);
static inline int authenticode_sign_pe(int fd, X509 *certificate, EVP_PKEY *private_key) {
        return authenticode_sign_pe_full(fd, certificate, private_key, /* signed_attributes= */ NULL,
                                         /* signed_attributes_signature= */ NULL);
}

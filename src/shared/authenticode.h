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

int authenticode_sign_pe(int fd, X509 *certificate, EVP_PKEY *private_key);

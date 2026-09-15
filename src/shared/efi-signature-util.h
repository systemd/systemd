/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "sd-id128.h"

#include "efi.h"
#include "forward.h"

#define EFI_CERT_X509       SD_ID128_MAKE(a5,c0,59,a1,94,e4,4a,a7,87,b5,ab,15,5c,2b,f0,72)
#define EFI_CERT_SHA256     SD_ID128_MAKE(c1,c4,16,26,50,4c,40,92,ac,a9,41,f9,36,93,43,28)
#define EFI_CERT_TYPE_PKCS7 SD_ID128_MAKE(4a,af,d2,9d,68,df,49,ee,8a,a9,34,7d,37,56,65,a7)

typedef struct EfiSignatureListHeader {
        sd_id128_t type;
        uint32_t list_size;
        uint32_t header_size;
        uint32_t signature_size;
} EfiSignatureListHeader;

typedef struct EfiSignatureListView {
        EfiSignatureListHeader header;
        struct iovec entries;
} EfiSignatureListView;

typedef struct EfiSignatureEntry {
        sd_id128_t type;
        struct iovec data;
} EfiSignatureEntry;

int efi_signature_list_new(
                sd_id128_t type,
                sd_id128_t owner,
                const struct iovec *data,
                struct iovec *ret);
int efi_signature_list_next(const struct iovec *data, size_t *offset, EfiSignatureListView *ret);
int efi_signature_list_validate(const struct iovec *data);

int efi_signature_database_index_new(
                const struct iovec *database,
                EfiSignatureEntry **ret_entries,
                size_t *ret_n_entries);
bool efi_signature_database_index_contains(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                sd_id128_t type,
                const struct iovec *data);
const EfiSignatureEntry* efi_signature_database_index_find_by_data(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                const struct iovec *data);
int efi_signature_database_is_superset(
                const struct iovec *database,
                const struct iovec *subset);
int efi_signature_database_collect_applied(
                const struct iovec *database,
                const struct iovec *update,
                EfiSignatureEntry **ret_entries,
                size_t *ret_n_entries,
                bool *ret_all_present);

int efi_authenticated_variable_payload(const struct iovec *input, struct iovec *ret_payload);
int efi_authenticated_variable_sign(
                sd_id128_t vendor,
                const char *name,
                uint32_t attributes,
                const EFI_TIME *timestamp,
                const struct iovec *payload,
                X509 *certificate,
                EVP_PKEY *private_key,
                struct iovec *ret);
int efi_authenticated_variable_verify(
                sd_id128_t vendor,
                const char *name,
                const struct iovec *input,
                uint32_t attributes);

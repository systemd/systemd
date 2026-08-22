/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "efi.h"
#include "forward.h"

typedef struct EfiSignatureListHeader {
        EFI_GUID type;
        uint32_t list_size;
        uint32_t header_size;
        uint32_t signature_size;
} EfiSignatureListHeader;

typedef struct EfiSignatureListView {
        EfiSignatureListHeader header;
        const uint8_t *entries;
        size_t entries_size;
} EfiSignatureListView;

typedef struct EfiSignatureEntry {
        EFI_GUID type;
        const void *data;
        uint32_t size;
} EfiSignatureEntry;

int efi_signature_list_new(
                const EFI_GUID *type,
                const EFI_GUID *owner,
                const void *data,
                size_t size,
                struct iovec *ret);
int efi_signature_list_next(const void *data, size_t size, size_t *offset, EfiSignatureListView *ret);
int efi_signature_list_validate(const void *data, size_t size);

int efi_signature_database_index_new(
                const void *database,
                size_t database_size,
                EfiSignatureEntry **ret_entries,
                size_t *ret_n_entries);
bool efi_signature_database_index_contains(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                const EFI_GUID *type,
                uint32_t size,
                const void *data);
const EfiSignatureEntry* efi_signature_database_index_find_by_data(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                uint32_t size,
                const void *data);
int efi_signature_database_is_superset(
                const void *database,
                size_t database_size,
                const void *subset,
                size_t subset_size);
int efi_signature_database_collect_applied(
                const void *database,
                size_t database_size,
                const void *update,
                size_t update_size,
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

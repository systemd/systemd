/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <syslog.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "efi-api.h"
#include "efi-signature-util.h"
#include "efivars.h"
#include "iovec-util.h"
#include "memory-util.h"
#include "sort-util.h"
#include "unaligned.h"
#include "utf8.h"

static void signature_list_header_read(const void *data, EfiSignatureListHeader *ret) {
        const uint8_t *p = ASSERT_PTR(data);

        assert(ret);

        memcpy(&ret->type, p + offsetof(EFI_SIGNATURE_LIST, SignatureType), sizeof(ret->type));
        ret->list_size = unaligned_read_le32(p + offsetof(EFI_SIGNATURE_LIST, SignatureListSize));
        ret->header_size = unaligned_read_le32(p + offsetof(EFI_SIGNATURE_LIST, SignatureHeaderSize));
        ret->signature_size = unaligned_read_le32(p + offsetof(EFI_SIGNATURE_LIST, SignatureSize));
}

int efi_signature_list_new(
                const EFI_GUID *type,
                const EFI_GUID *owner,
                const void *data,
                size_t size,
                struct iovec *ret) {

        static const EFI_GUID zero_owner = {};
        _cleanup_free_ uint8_t *list = NULL;
        size_t list_size, signature_size;

        assert(type);
        assert(data || size == 0);
        assert(ret);

        if (size > UINT32_MAX - offsetof(EFI_SIGNATURE_DATA, SignatureData))
                return -E2BIG;
        signature_size = offsetof(EFI_SIGNATURE_DATA, SignatureData) + size;
        if (signature_size > UINT32_MAX - offsetof(EFI_SIGNATURE_LIST, Signatures))
                return -E2BIG;
        list_size = offsetof(EFI_SIGNATURE_LIST, Signatures) + signature_size;

        list = new0(uint8_t, list_size);
        if (!list)
                return -ENOMEM;

        memcpy(list + offsetof(EFI_SIGNATURE_LIST, SignatureType), type, sizeof(*type));
        unaligned_write_le32(list + offsetof(EFI_SIGNATURE_LIST, SignatureListSize), list_size);
        unaligned_write_le32(list + offsetof(EFI_SIGNATURE_LIST, SignatureHeaderSize), 0);
        unaligned_write_le32(list + offsetof(EFI_SIGNATURE_LIST, SignatureSize), signature_size);
        memcpy(list + offsetof(EFI_SIGNATURE_LIST, Signatures[0].SignatureOwner),
               owner ?: &zero_owner,
               sizeof(EFI_GUID));
        memcpy_safe(list + offsetof(EFI_SIGNATURE_LIST, Signatures[0].SignatureData), data, size);

        *ret = IOVEC_MAKE(TAKE_PTR(list), list_size);
        return 0;
}

int efi_signature_list_next(
                const void *data,
                size_t size,
                size_t *offset,
                EfiSignatureListView *ret) {

        static const EFI_GUID sha256 = EFI_CERT_SHA256_GUID;
        EfiSignatureListHeader header;
        const uint8_t *list;
        size_t entries_size;

        assert(data || size == 0);
        assert(offset);
        assert(*offset <= size);
        assert(ret);

        if (*offset == size)
                return 0;

        if (size - *offset < offsetof(EFI_SIGNATURE_LIST, Signatures))
                return -EBADMSG;

        list = (const uint8_t*) data + *offset;
        signature_list_header_read(list, &header);

        if (header.list_size < offsetof(EFI_SIGNATURE_LIST, Signatures) ||
            header.list_size > size - *offset)
                return -EBADMSG;
        if (header.header_size > header.list_size - offsetof(EFI_SIGNATURE_LIST, Signatures))
                return -EBADMSG;
        if (header.signature_size < offsetof(EFI_SIGNATURE_DATA, SignatureData))
                return -EBADMSG;
        if (efi_guid_equal(&header.type, &sha256) &&
            header.signature_size != offsetof(EFI_SIGNATURE_DATA, SignatureData) + SHA256_DIGEST_SIZE)
                return -EBADMSG;

        entries_size = header.list_size - offsetof(EFI_SIGNATURE_LIST, Signatures) - header.header_size;
        if (entries_size % header.signature_size != 0)
                return -EBADMSG;

        *ret = (EfiSignatureListView) {
                .header = header,
                .entries = list + offsetof(EFI_SIGNATURE_LIST, Signatures) + header.header_size,
                .entries_size = entries_size,
        };
        *offset += header.list_size;
        return 1;
}

int efi_signature_list_validate(const void *data, size_t size) {
        size_t offset = 0;
        int r;

        for (;;) {
                EfiSignatureListView list;

                r = efi_signature_list_next(data, size, &offset, &list);
                if (r <= 0)
                        return r;
        }
}

static int signature_entry_compare(const EfiSignatureEntry *a, const EfiSignatureEntry *b) {
        int r;

        assert(a);
        assert(b);

        r = memcmp(&a->type, &b->type, sizeof(a->type));
        if (r != 0)
                return r;

        r = CMP(a->size, b->size);
        if (r != 0)
                return r;

        return memcmp(a->data, b->data, a->size);
}

int efi_signature_database_index_new(
                const void *database,
                size_t database_size,
                EfiSignatureEntry **ret_entries,
                size_t *ret_n_entries) {

        _cleanup_free_ EfiSignatureEntry *entries = NULL;
        size_t n_entries = 0, offset = 0;
        int r;

        assert(ret_entries);
        assert(ret_n_entries);

        for (;;) {
                EfiSignatureListView list;

                r = efi_signature_list_next(database, database_size, &offset, &list);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                const uint8_t *entry = list.entries;
                for (size_t left = list.entries_size;
                     left > 0;
                     left -= list.header.signature_size, entry += list.header.signature_size) {
                        if (!GREEDY_REALLOC(entries, n_entries + 1))
                                return -ENOMEM;

                        entries[n_entries++] = (EfiSignatureEntry) {
                                .type = list.header.type,
                                .data = entry,
                                .size = list.header.signature_size,
                        };
                }
        }

        typesafe_qsort(entries, n_entries, signature_entry_compare);

        *ret_entries = TAKE_PTR(entries);
        *ret_n_entries = n_entries;
        return 0;
}

bool efi_signature_database_index_contains(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                const EFI_GUID *type,
                uint32_t size,
                const void *data) {

        assert(type);

        EfiSignatureEntry key = {
                .type = *type,
                .data = data,
                .size = size,
        };

        return typesafe_bsearch(&key, entries, n_entries, signature_entry_compare);
}

const EfiSignatureEntry* efi_signature_database_index_find_by_data(
                const EfiSignatureEntry *entries,
                size_t n_entries,
                uint32_t size,
                const void *data) {

        const EfiSignatureEntry *found = NULL;

        FOREACH_ARRAY(entry, entries, n_entries) {
                if (entry->size != size || memcmp(entry->data, data, size) != 0)
                        continue;

                if (found && !efi_guid_equal(&found->type, &entry->type))
                        return NULL;

                found = entry;
        }

        return found;
}

int efi_signature_database_is_superset(
                const void *database,
                size_t database_size,
                const void *subset,
                size_t subset_size) {

        _cleanup_free_ EfiSignatureEntry *database_entries = NULL;
        size_t n_database_entries = 0, offset = 0;
        int r;

        r = efi_signature_database_index_new(
                        database,
                        database_size,
                        &database_entries,
                        &n_database_entries);
        if (r < 0)
                return r;

        for (;;) {
                EfiSignatureListView list;

                r = efi_signature_list_next(subset, subset_size, &offset, &list);
                if (r < 0)
                        return r;
                if (r == 0)
                        return true;

                const uint8_t *entry = list.entries;
                for (size_t left = list.entries_size;
                     left > 0;
                     left -= list.header.signature_size, entry += list.header.signature_size)
                        if (!efi_signature_database_index_contains(
                                            database_entries,
                                            n_database_entries,
                                            &list.header.type,
                                            list.header.signature_size,
                                            entry))
                                return false;
        }
}

int efi_signature_database_collect_applied(
                const void *database,
                size_t database_size,
                const void *update,
                size_t update_size,
                EfiSignatureEntry **ret_entries,
                size_t *ret_n_entries,
                bool *ret_all_present) {

        _cleanup_free_ EfiSignatureEntry *applied = NULL, *database_entries = NULL;
        size_t n_applied = 0, n_database_entries = 0, offset = 0;
        bool all_present = true;
        int r;

        assert(ret_entries);
        assert(ret_n_entries);
        assert(ret_all_present);

        r = efi_signature_database_index_new(
                        database,
                        database_size,
                        &database_entries,
                        &n_database_entries);
        if (r < 0)
                return r;

        for (;;) {
                EfiSignatureListView list;

                r = efi_signature_list_next(update, update_size, &offset, &list);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                const uint8_t *entry = list.entries;
                for (size_t left = list.entries_size;
                     left > 0;
                     left -= list.header.signature_size, entry += list.header.signature_size) {
                        if (!efi_signature_database_index_contains(
                                            database_entries,
                                            n_database_entries,
                                            &list.header.type,
                                            list.header.signature_size,
                                            entry)) {
                                all_present = false;
                                continue;
                        }

                        if (!GREEDY_REALLOC(applied, n_applied + 1))
                                return -ENOMEM;

                        applied[n_applied++] = (EfiSignatureEntry) {
                                .type = list.header.type,
                                .data = entry,
                                .size = list.header.signature_size,
                        };
                }
        }

        *ret_entries = TAKE_PTR(applied);
        *ret_n_entries = n_applied;
        *ret_all_present = all_present;
        return 0;
}

static int authenticated_variable_layout(
                const struct iovec *input,
                const EFI_VARIABLE_AUTHENTICATION_2 **ret_auth,
                size_t *ret_payload_offset) {

        static const EFI_GUID pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
        const EFI_VARIABLE_AUTHENTICATION_2 *auth;
        size_t certificate_size;

        assert(input);
        assert(ret_auth);
        assert(ret_payload_offset);

        if (input->iov_len < offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData))
                return -EBADMSG;

        auth = input->iov_base;
        if (unaligned_read_le16(&auth->AuthInfo.Hdr.wRevision) != 0x0200 ||
            unaligned_read_le16(&auth->AuthInfo.Hdr.wCertificateType) != 0x0ef1)
                return -EBADMSG;
        if (!efi_guid_equal(&auth->AuthInfo.CertType, &pkcs7))
                return -EBADMSG;

        certificate_size = unaligned_read_le32(&auth->AuthInfo.Hdr.dwLength);
        if (certificate_size < sizeof(WIN_CERTIFICATE_UEFI_GUID) ||
            certificate_size > input->iov_len - offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo))
                return -EBADMSG;

        *ret_auth = auth;
        *ret_payload_offset = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + certificate_size;
        return 0;
}

int efi_authenticated_variable_payload(const struct iovec *input, struct iovec *ret_payload) {
        const EFI_VARIABLE_AUTHENTICATION_2 *auth;
        size_t offset;
        int r;

        assert(ret_payload);

        r = authenticated_variable_layout(input, &auth, &offset);
        if (r < 0)
                return r;

        r = efi_signature_list_validate((const uint8_t*) input->iov_base + offset, input->iov_len - offset);
        if (r < 0)
                return r;

        if (!iovec_memdup(&IOVEC_MAKE((const uint8_t*) input->iov_base + offset, input->iov_len - offset), ret_payload))
                return -ENOMEM;

        return 0;
}

#if HAVE_OPENSSL
static int make_authenticated_variable_data(
                sd_id128_t vendor_id,
                const char *name,
                uint32_t attributes,
                const EFI_TIME *timestamp,
                const struct iovec *payload,
                struct iovec *ret) {

        _cleanup_free_ char16_t *name16 = NULL;
        _cleanup_free_ uint8_t *data = NULL;
        EFI_GUID vendor;
        size_t name_size, total_size;
        uint8_t *p;

        assert(name);
        assert(timestamp);
        assert(payload);
        assert(ret);

        name16 = utf8_to_utf16(name, SIZE_MAX);
        if (!name16)
                return -ENOMEM;
        name_size = char16_strsize(name16) - sizeof(char16_t);

        total_size = name_size;
        if (!ADD_SAFE(&total_size, total_size, sizeof(vendor)) ||
            !ADD_SAFE(&total_size, total_size, sizeof(attributes)) ||
            !ADD_SAFE(&total_size, total_size, sizeof(*timestamp)) ||
            !ADD_SAFE(&total_size, total_size, payload->iov_len))
                return -EOVERFLOW;

        data = malloc(total_size);
        if (!data)
                return -ENOMEM;

        efi_id128_to_guid(vendor_id, &vendor);

        p = data;
        p = mempcpy(p, name16, name_size);
        p = mempcpy(p, &vendor, sizeof(vendor));
        unaligned_write_le32(p, attributes);
        p += sizeof(attributes);
        p = mempcpy(p, timestamp, sizeof(*timestamp));
        p = mempcpy_safe(p, payload->iov_base, payload->iov_len);
        assert(p == data + total_size);

        *ret = IOVEC_MAKE(TAKE_PTR(data), total_size);
        return 0;
}
#endif

int efi_authenticated_variable_sign(
                sd_id128_t vendor,
                const char *name,
                uint32_t attributes,
                const EFI_TIME *timestamp,
                const struct iovec *payload,
                X509 *certificate,
                EVP_PKEY *private_key,
                struct iovec *ret) {

#if HAVE_OPENSSL
        _cleanup_(iovec_done) struct iovec signed_data = {};
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        _cleanup_free_ uint8_t *blob = NULL, *signature = NULL;
        _cleanup_(BIO_freep) BIO *bio = NULL;
        size_t auth_size, signature_size;
        int r;

        assert(name);
        assert(timestamp);
        assert(payload);
        assert(certificate);
        assert(private_key);
        assert(ret);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        r = make_authenticated_variable_data(vendor, name, attributes, timestamp, payload, &signed_data);
        if (r < 0)
                return r;
        if (signed_data.iov_len > INT_MAX)
                return -E2BIG;

        bio = sym_BIO_new_mem_buf(signed_data.iov_base, (int) signed_data.iov_len);
        if (!bio)
                return log_openssl_errors(LOG_DEBUG, "Failed to allocate authenticated EFI variable BIO");

        p7 = sym_PKCS7_sign(
                        certificate,
                        private_key,
                        /* certs= */ NULL,
                        bio,
                        PKCS7_DETACHED|PKCS7_NOATTR|PKCS7_BINARY|PKCS7_NOSMIMECAP);
        if (!p7)
                return log_openssl_errors(LOG_DEBUG, "Failed to sign authenticated EFI variable");

        r = sym_i2d_PKCS7(p7, &signature);
        if (r < 0)
                return log_openssl_errors(LOG_DEBUG, "Failed to serialize authenticated EFI variable signature");
        signature_size = r;

                if (signature_size > UINT32_MAX - offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData) ||
                        payload->iov_len > SIZE_MAX - offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) ||
                        signature_size > SIZE_MAX - offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) - payload->iov_len)
                return -E2BIG;
        auth_size = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) + signature_size;

        blob = new(uint8_t, auth_size + payload->iov_len);
        if (!blob)
                return -ENOMEM;

        memcpy(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, TimeStamp), timestamp, sizeof(*timestamp));
        unaligned_write_le32(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.dwLength),
                             offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData) + signature_size);
        unaligned_write_le16(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wRevision), 0x0200);
        unaligned_write_le16(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wCertificateType), 0x0ef1);
        memcpy(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertType),
               &(EFI_GUID) EFI_CERT_TYPE_PKCS7_GUID,
               sizeof(EFI_GUID));
        memcpy(blob + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData), signature, signature_size);
        memcpy_safe(blob + auth_size, payload->iov_base, payload->iov_len);

        *ret = IOVEC_MAKE(TAKE_PTR(blob), auth_size + payload->iov_len);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

#if HAVE_OPENSSL
static size_t der_length_size(size_t length) {
        size_t n = 1;

        if (length < 128)
                return n;

        for (; length > 0; length >>= 8)
                n++;

        return n;
}

static uint8_t* der_write_length(uint8_t *p, size_t length) {
        if (length < 128) {
                *p++ = length;
                return p;
        }

        size_t n = der_length_size(length) - 1;
        *p++ = UINT8_C(0x80) | n;
        for (size_t i = n; i > 0; i--)
                *p++ = length >> ((i - 1) * 8);

        return p;
}

static int parse_efi_pkcs7(const void *data, size_t size, PKCS7 **ret) {
        static const uint8_t signed_data_oid[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        _cleanup_free_ uint8_t *wrapped = NULL;
        const unsigned char *p = data;
        size_t explicit_size, sequence_size, wrapped_size;
        uint8_t *q;

        assert(data || size == 0);
        assert(ret);

        if (size > LONG_MAX)
                return -E2BIG;

        p7 = sym_d2i_PKCS7(NULL, &p, (long) size);
        if (p7 && p == (const uint8_t*) data + size) {
                *ret = TAKE_PTR(p7);
                return 0;
        }

        if (p7) {
                sym_PKCS7_free(p7);
                p7 = NULL;
        }
        sym_ERR_clear_error();

        if (size > SIZE_MAX - 1 - der_length_size(size))
                return -EOVERFLOW;
        explicit_size = 1 + der_length_size(size) + size;
        if (explicit_size > SIZE_MAX - sizeof(signed_data_oid))
                return -EOVERFLOW;
        sequence_size = sizeof(signed_data_oid) + explicit_size;
        if (sequence_size > SIZE_MAX - 1 - der_length_size(sequence_size))
                return -EOVERFLOW;
        wrapped_size = 1 + der_length_size(sequence_size) + sequence_size;
        if (wrapped_size > LONG_MAX)
                return -E2BIG;

        wrapped = new(uint8_t, wrapped_size);
        if (!wrapped)
                return -ENOMEM;

        q = wrapped;
        *q++ = UINT8_C(0x30);
        q = der_write_length(q, sequence_size);
        q = mempcpy(q, signed_data_oid, sizeof(signed_data_oid));
        *q++ = UINT8_C(0xa0);
        q = der_write_length(q, size);
        q = mempcpy(q, data, size);
        assert(q == wrapped + wrapped_size);

        p = wrapped;
        p7 = sym_d2i_PKCS7(NULL, &p, (long) wrapped_size);
        if (!p7 || p != wrapped + wrapped_size) {
                sym_ERR_clear_error();
                return -EBADMSG;
        }

        *ret = TAKE_PTR(p7);
        return 0;
}
#endif

int efi_authenticated_variable_verify(
                sd_id128_t vendor_id,
                const char *name,
                const struct iovec *input,
                uint32_t attributes) {

#if HAVE_OPENSSL
        const EFI_VARIABLE_AUTHENTICATION_2 *auth;
        _cleanup_(iovec_done) struct iovec signed_data = {};
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        struct iovec payload;
        size_t offset, signature_size;
        int r;

        assert(name);

        r = authenticated_variable_layout(input, &auth, &offset);
        if (r < 0)
                return r;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        signature_size = unaligned_read_le32(&auth->AuthInfo.Hdr.dwLength) -
                offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData);
        if (signature_size > LONG_MAX)
                return -E2BIG;

        r = parse_efi_pkcs7(auth->AuthInfo.CertData, signature_size, &p7);
        if (r < 0)
                return r;

        payload = IOVEC_MAKE((const uint8_t*) input->iov_base + offset, input->iov_len - offset);

        for (unsigned append = 0; append < 2; append++) {
                _cleanup_(BIO_freep) BIO *bio = NULL;

                r = make_authenticated_variable_data(
                                vendor_id,
                                name,
                                attributes | (append ? EFI_VARIABLE_APPEND_WRITE : 0),
                                &auth->TimeStamp,
                                &payload,
                                &signed_data);
                if (r < 0)
                        return r;
                if (signed_data.iov_len > INT_MAX)
                        return -E2BIG;

                bio = sym_BIO_new_mem_buf(signed_data.iov_base, (int) signed_data.iov_len);
                if (!bio)
                        return log_openssl_errors(LOG_DEBUG, "Failed to allocate authenticated EFI variable BIO");

                if (sym_PKCS7_verify(p7, NULL, NULL, bio, NULL, PKCS7_NOVERIFY|PKCS7_BINARY) > 0)
                        return true;

                sym_ERR_clear_error();
                iovec_done(&signed_data);
        }

        return false;
#else
        return -EOPNOTSUPP;
#endif
}

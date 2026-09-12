/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "efi-signature-util.h"
#include "efivars.h"
#include "iovec-util.h"
#include "sha256.h"
#include "tests.h"
#include "unaligned.h"

static void* make_esl(
                EFI_GUID type,
                uint32_t header_size,
                uint32_t signature_size,
                size_t n_entries,
                size_t *ret_size) {

        static const EFI_GUID owner = EFI_GLOBAL_VARIABLE;
        size_t size = offsetof(EFI_SIGNATURE_LIST, Signatures) + header_size + n_entries * signature_size;
        uint8_t *data = ASSERT_NOT_NULL(new0(uint8_t, size));

        memcpy(data + offsetof(EFI_SIGNATURE_LIST, SignatureType), &type, sizeof(type));
        unaligned_write_le32(data + offsetof(EFI_SIGNATURE_LIST, SignatureListSize), size);
        unaligned_write_le32(data + offsetof(EFI_SIGNATURE_LIST, SignatureHeaderSize), header_size);
        unaligned_write_le32(data + offsetof(EFI_SIGNATURE_LIST, SignatureSize), signature_size);

        for (size_t i = 0; i < n_entries; i++) {
                uint8_t *entry = data + offsetof(EFI_SIGNATURE_LIST, Signatures) + header_size + i * signature_size;

                memcpy(entry, &owner, sizeof(owner));
                memset(entry + offsetof(EFI_SIGNATURE_DATA, SignatureData), (uint8_t) (i + 1),
                       signature_size - offsetof(EFI_SIGNATURE_DATA, SignatureData));
        }

        *ret_size = size;
        return data;
}

static void* make_authenticated_update(const void *payload, size_t payload_size, size_t *ret_size) {
        static const EFI_GUID pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
        size_t certificate_size = sizeof(WIN_CERTIFICATE_UEFI_GUID) + 1;
        size_t payload_offset = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + certificate_size;
        uint8_t *data = ASSERT_NOT_NULL(new0(uint8_t, payload_offset + payload_size));

        unaligned_write_le32(data + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.dwLength), certificate_size);
        unaligned_write_le16(data + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wRevision), WIN_CERT_REVISION_2_0);
        unaligned_write_le16(data + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wCertificateType), WIN_CERT_TYPE_EFI_GUID);
        memcpy(data + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertType), &pkcs7, sizeof(pkcs7));
        memcpy(data + payload_offset, payload, payload_size);

        *ret_size = payload_offset + payload_size;
        return data;
}

TEST(signature_list_validation) {
        const uint32_t sha256_entry_size = offsetof(EFI_SIGNATURE_DATA, SignatureData) + SHA256_DIGEST_SIZE;
        _cleanup_free_ uint8_t *bad = NULL, *esl = NULL, *x509_esl = NULL;
        _cleanup_(iovec_done) struct iovec generated = {};
        uint8_t digest[SHA256_DIGEST_SIZE];
        size_t esl_size, offset = 0, x509_esl_size;
        EfiSignatureListView view;

        memset(digest, 0xa5, sizeof(digest));
        ASSERT_OK(efi_signature_list_new(
                          EFI_CERT_SHA256, EFI_VENDOR_GLOBAL, &IOVEC_MAKE(digest, sizeof(digest)), &generated));
        ASSERT_OK(efi_signature_list_validate(&generated));
        ASSERT_OK_EQ(efi_signature_list_next(&generated, &offset, &view), 1);
        ASSERT_EQ(view.entries.iov_len, sha256_entry_size);
        ASSERT_EQ(memcmp(view.entries.iov_base, &(EFI_GUID) EFI_GLOBAL_VARIABLE, sizeof(EFI_GUID)), 0);
        ASSERT_EQ(memcmp((uint8_t*) view.entries.iov_base + offsetof(EFI_SIGNATURE_DATA, SignatureData),
                         digest, sizeof(digest)), 0);

        esl = make_esl((EFI_GUID) EFI_CERT_SHA256_GUID, /* header_size= */ 0, sha256_entry_size, /* n_entries= */ 2, &esl_size);
        offset = 0;
        ASSERT_OK(efi_signature_list_validate(&IOVEC_MAKE(esl, esl_size)));
        ASSERT_OK_EQ(efi_signature_list_next(&IOVEC_MAKE(esl, esl_size), &offset, &view), 1);
        ASSERT_EQ(view.header.signature_size, sha256_entry_size);
        ASSERT_EQ(view.entries.iov_len, 2U * sha256_entry_size);
        ASSERT_OK_EQ(efi_signature_list_next(&IOVEC_MAKE(esl, esl_size), &offset, &view), 0);
        ASSERT_OK(efi_signature_list_validate(&IOVEC_MAKE(NULL, 0)));

        ASSERT_ERROR(efi_signature_list_validate(
                             &IOVEC_MAKE(esl, offsetof(EFI_SIGNATURE_LIST, Signatures) - 1)), EBADMSG);

        bad = ASSERT_NOT_NULL(memdup(esl, esl_size));
        unaligned_write_le32(bad + offsetof(EFI_SIGNATURE_LIST, SignatureListSize),
                             offsetof(EFI_SIGNATURE_LIST, Signatures) - 1);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(bad, esl_size)), EBADMSG);

        memcpy(bad, esl, esl_size);
        unaligned_write_le32(bad + offsetof(EFI_SIGNATURE_LIST, SignatureListSize), esl_size + 1);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(bad, esl_size)), EBADMSG);

        memcpy(bad, esl, esl_size);
        unaligned_write_le32(bad + offsetof(EFI_SIGNATURE_LIST, SignatureHeaderSize), esl_size);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(bad, esl_size)), EBADMSG);

        memcpy(bad, esl, esl_size);
        unaligned_write_le32(bad + offsetof(EFI_SIGNATURE_LIST, SignatureSize),
                             offsetof(EFI_SIGNATURE_DATA, SignatureData) - 1);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(bad, esl_size)), EBADMSG);

        _cleanup_free_ void *short_sha256 = make_esl(
                        (EFI_GUID) EFI_CERT_SHA256_GUID,
                        /* header_size= */ 0,
                        offsetof(EFI_SIGNATURE_DATA, SignatureData) + 4,
                        /* n_entries= */ 1,
                        &offset);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(short_sha256, offset)), EBADMSG);

        x509_esl = make_esl(
                        (EFI_GUID) EFI_CERT_X509_GUID,
                        /* header_size= */ 0,
                        offsetof(EFI_SIGNATURE_DATA, SignatureData) + 1,
                        /* n_entries= */ 2,
                        &x509_esl_size);
        unaligned_write_le32(x509_esl + offsetof(EFI_SIGNATURE_LIST, SignatureSize),
                             offsetof(EFI_SIGNATURE_DATA, SignatureData) + 2);
        ASSERT_ERROR(efi_signature_list_validate(&IOVEC_MAKE(x509_esl, x509_esl_size)), EBADMSG);
}

TEST(signature_database) {
        const uint32_t signature_size = offsetof(EFI_SIGNATURE_DATA, SignatureData) + SHA256_DIGEST_SIZE;
        _cleanup_free_ EfiSignatureEntry *applied = NULL, *index = NULL;
        _cleanup_free_ uint8_t *database = NULL, *subset = NULL, *update = NULL;
        bool all_present;
        size_t database_size, n_applied, n_index, offset = 0, subset_size, update_size;
        EfiSignatureListView view;

        database = make_esl((EFI_GUID) EFI_CERT_SHA256_GUID, /* header_size= */ 0, signature_size, /* n_entries= */ 2, &database_size);
        subset = make_esl((EFI_GUID) EFI_CERT_SHA256_GUID, /* header_size= */ 0, signature_size, /* n_entries= */ 1, &subset_size);

        ASSERT_OK(efi_signature_database_index_new(&IOVEC_MAKE(database, database_size), &index, &n_index));
        ASSERT_EQ(n_index, 2U);
        ASSERT_OK_EQ(efi_signature_list_next(&IOVEC_MAKE(subset, subset_size), &offset, &view), 1);
        ASSERT_TRUE(efi_signature_database_index_contains(
                            index, n_index, view.header.type, &view.entries));
        ASSERT_NOT_NULL(efi_signature_database_index_find_by_data(
                                index, n_index, &view.entries));

        ASSERT_OK_EQ(efi_signature_database_is_superset(
                             &IOVEC_MAKE(database, database_size), &IOVEC_MAKE(subset, subset_size)), 1);
        ASSERT_OK_EQ(efi_signature_database_is_superset(
                             &IOVEC_MAKE(subset, subset_size), &IOVEC_MAKE(database, database_size)), 0);
        ASSERT_OK_EQ(efi_signature_database_is_superset(
                             &IOVEC_MAKE(database, database_size), &IOVEC_MAKE(NULL, 0)), 1);

        update = ASSERT_NOT_NULL(memdup(database, database_size));
        update_size = database_size;
        update[update_size - 1] ^= UINT8_C(0xff);
        ASSERT_OK(efi_signature_database_collect_applied(
                          &IOVEC_MAKE(database, database_size),
                          &IOVEC_MAKE(update, update_size),
                          &applied, &n_applied,
                          &all_present));
        ASSERT_EQ(n_applied, 1U);
        ASSERT_FALSE(all_present);

        applied = mfree(applied);
        ASSERT_OK(efi_signature_database_collect_applied(
                          &IOVEC_MAKE(database, database_size),
                          &IOVEC_MAKE(database, database_size),
                          &applied, &n_applied,
                          &all_present));
        ASSERT_EQ(n_applied, 2U);
        ASSERT_TRUE(all_present);
}

TEST(authenticated_variable) {
        static const EFI_GUID zero = {};
        const uint32_t signature_size = offsetof(EFI_SIGNATURE_DATA, SignatureData) + SHA256_DIGEST_SIZE;
        _cleanup_free_ uint8_t *auth = NULL, *bad = NULL, *esl = NULL;
        _cleanup_(iovec_done) struct iovec payload = {};
        size_t auth_size, esl_size;

        esl = make_esl((EFI_GUID) EFI_CERT_SHA256_GUID, /* header_size= */ 0, signature_size, /* n_entries= */ 1, &esl_size);
        auth = make_authenticated_update(esl, esl_size, &auth_size);

        ASSERT_OK(efi_authenticated_variable_payload(&IOVEC_MAKE(auth, auth_size), &payload));
        ASSERT_EQ(payload.iov_len, esl_size);
        ASSERT_EQ(memcmp(payload.iov_base, esl, esl_size), 0);

#if HAVE_OPENSSL
        ASSERT_ERROR(efi_authenticated_variable_verify(
                             EFI_VENDOR_DATABASE,
                             "db",
                             &IOVEC_MAKE(auth, auth_size),
                             EFI_VARIABLE_NON_VOLATILE|
                             EFI_VARIABLE_BOOTSERVICE_ACCESS|
                             EFI_VARIABLE_RUNTIME_ACCESS|
                             EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
                     EBADMSG);
#endif

        ASSERT_ERROR(efi_authenticated_variable_payload(
                             &IOVEC_MAKE(auth, offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) - 1),
                             &payload),
                     EBADMSG);

        bad = ASSERT_NOT_NULL(memdup(auth, auth_size));
        unaligned_write_le16(bad + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wRevision), 0);
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);

        memcpy(bad, auth, auth_size);
        unaligned_write_le16(bad + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.wCertificateType), 0);
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);

        memcpy(bad, auth, auth_size);
        memcpy(bad + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertType), &zero, sizeof(zero));
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);

        memcpy(bad, auth, auth_size);
        unaligned_write_le32(bad + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.dwLength),
                             sizeof(WIN_CERTIFICATE_UEFI_GUID) - 1);
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);

        memcpy(bad, auth, auth_size);
        unaligned_write_le32(bad + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.dwLength), UINT32_MAX);
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);

        memcpy(bad, auth, auth_size);
        size_t payload_offset = auth_size - esl_size;
        unaligned_write_le32(bad + payload_offset + offsetof(EFI_SIGNATURE_LIST, SignatureListSize), esl_size + 1);
        ASSERT_ERROR(efi_authenticated_variable_payload(&IOVEC_MAKE(bad, auth_size), &payload), EBADMSG);
}

DEFINE_TEST_MAIN(LOG_INFO);

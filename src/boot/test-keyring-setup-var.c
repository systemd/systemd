/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "keyring-setup-var.h"
#include "tests.h"

TEST(keyring_setup_credential_name_is_valid) {
        assert_se(keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.foo"));
        assert_se(keyring_setup_credential_name_is_valid("keyring-setup.dm-verity.foo-1_2.3"));

        assert_se(!keyring_setup_credential_name_is_valid(""));
        assert_se(!keyring_setup_credential_name_is_valid("keyring-setup."));            /* nothing after the prefix */
        assert_se(!keyring_setup_credential_name_is_valid("foo"));                       /* no prefix */
        assert_se(!keyring_setup_credential_name_is_valid(".keyring-setup.fs-verity.foo"));
        assert_se(!keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.Foo"));   /* upper case */
        assert_se(!keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.f/oo")); /* path separator */
        assert_se(!keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.f oo")); /* space */

        /* Length limit: 250 is fine (255 = NAME_MAX with the ".cred" suffix appended), 251 is not */
        char name[257 + 1];
        memset(name, 'a', sizeof(name) - 1);
        memcpy(name, "keyring-setup.", strlen("keyring-setup."));
        name[250] = 0;
        assert_se(keyring_setup_credential_name_is_valid(name));
        name[250] = 'a';
        name[251] = 0;
        assert_se(!keyring_setup_credential_name_is_valid(name));
}

static size_t append_record(uint8_t *buf, size_t offset, const char *name, const char *payload) {
        size_t name_size = strlen(name) + 1, payload_size = strlen(payload);

        memcpy(buf + offset, name, name_size);
        offset += name_size;

        buf[offset++] = (uint8_t) payload_size;
        buf[offset++] = (uint8_t) (payload_size >> 8);
        buf[offset++] = (uint8_t) (payload_size >> 16);
        buf[offset++] = (uint8_t) (payload_size >> 24);

        memcpy(buf + offset, payload, payload_size);
        return offset + payload_size;
}

TEST(keyring_setup_next_record) {
        uint8_t buf[1024];
        size_t boundary1, size, offset = 0;
        const char *name;
        const void *payload;
        size_t payload_size;

        boundary1 = append_record(buf, 0, "keyring-setup.fs-verity.foo", "hello");
        size = append_record(buf, boundary1, "keyring-setup.dm-verity.bar", "world!");

        /* The happy path: two records, then a clean end */
        assert_se(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size) == EFI_SUCCESS);
        assert_se(streq8(name, "keyring-setup.fs-verity.foo"));
        assert_se(payload_size == 5);
        assert_se(memcmp(payload, "hello", 5) == 0);

        assert_se(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size) == EFI_SUCCESS);
        assert_se(streq8(name, "keyring-setup.dm-verity.bar"));
        assert_se(payload_size == 6);
        assert_se(memcmp(payload, "world!", 6) == 0);

        assert_se(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size) == EFI_NOT_FOUND);
        assert_se(offset == size);

        /* Empty payloads end cleanly right away */
        offset = 0;
        assert_se(keyring_setup_next_record(buf, 0, &offset, &name, &payload, &payload_size) == EFI_NOT_FOUND);

        /* Truncation at every point: walking must end in EFI_INVALID_PARAMETER, unless the cut happens to
         * fall on a record boundary, where it is a clean end. */
        for (size_t cut = 1; cut < size; cut++) {
                EFI_STATUS err;

                offset = 0;
                do
                        err = keyring_setup_next_record(buf, cut, &offset, &name, &payload, &payload_size);
                while (err == EFI_SUCCESS);

                if (cut == boundary1)
                        assert_se(err == EFI_NOT_FOUND);
                else
                        assert_se(err == EFI_INVALID_PARAMETER);
        }

        /* A record with a zero size payload is malformed */
        uint8_t zero[64];
        size = append_record(zero, 0, "keyring-setup.fs-verity.foo", "");
        offset = 0;
        assert_se(keyring_setup_next_record(zero, size, &offset, &name, &payload, &payload_size) == EFI_INVALID_PARAMETER);

        /* A record with an invalid name is malformed */
        uint8_t bad[64];
        size = append_record(bad, 0, "not-a-keyring-cred", "hello");
        offset = 0;
        assert_se(keyring_setup_next_record(bad, size, &offset, &name, &payload, &payload_size) == EFI_INVALID_PARAMETER);

        /* A length field pointing past the end is malformed */
        uint8_t overrun[64];
        size = append_record(overrun, 0, "keyring-setup.fs-verity.foo", "hello");
        overrun[strlen("keyring-setup.fs-verity.foo") + 1] = 0xFF;
        offset = 0;
        assert_se(keyring_setup_next_record(overrun, size, &offset, &name, &payload, &payload_size) == EFI_INVALID_PARAMETER);
}

DEFINE_TEST_MAIN(LOG_INFO);

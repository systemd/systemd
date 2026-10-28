/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "keyring-setup-var.h"
#include "tests.h"

TEST(keyring_setup_credential_name_is_valid) {
        ASSERT_TRUE(keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.foo"));
        ASSERT_TRUE(keyring_setup_credential_name_is_valid("keyring-setup.dm-verity.foo-1_2.3"));

        ASSERT_FALSE(keyring_setup_credential_name_is_valid(""));
        ASSERT_FALSE(keyring_setup_credential_name_is_valid("keyring-setup."));            /* nothing after the prefix */
        ASSERT_FALSE(keyring_setup_credential_name_is_valid("foo"));                       /* no prefix */
        ASSERT_FALSE(keyring_setup_credential_name_is_valid(".keyring-setup.fs-verity.foo"));
        ASSERT_FALSE(keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.Foo"));   /* upper case */
        ASSERT_FALSE(keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.f/oo")); /* path separator */
        ASSERT_FALSE(keyring_setup_credential_name_is_valid("keyring-setup.fs-verity.f oo")); /* space */

        /* Length limit: 250 is fine (255 = NAME_MAX with the ".cred" suffix appended), 251 is not */
        char name[257 + 1];
        memset(name, 'a', sizeof(name) - 1);
        memcpy(name, "keyring-setup.", strlen("keyring-setup."));
        name[250] = 0;
        ASSERT_TRUE(keyring_setup_credential_name_is_valid(name));
        name[250] = 'a';
        name[251] = 0;
        ASSERT_FALSE(keyring_setup_credential_name_is_valid(name));
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

/* Walks all records, returns the status that ended the walk */
static EFI_STATUS walk(const void *data, size_t size) {
        EFI_STATUS err;

        for (size_t offset = 0;;) {
                const char *name;
                const void *payload;
                size_t payload_size;

                err = keyring_setup_next_record(data, size, &offset, &name, &payload, &payload_size);
                if (err != EFI_SUCCESS)
                        return err;
        }
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
        ASSERT_EQ(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size), EFI_SUCCESS);
        ASSERT_STREQ(name, "keyring-setup.fs-verity.foo");
        ASSERT_EQ(payload_size, 5U);
        ASSERT_EQ(memcmp(payload, "hello", 5), 0);

        ASSERT_EQ(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size), EFI_SUCCESS);
        ASSERT_STREQ(name, "keyring-setup.dm-verity.bar");
        ASSERT_EQ(payload_size, 6U);
        ASSERT_EQ(memcmp(payload, "world!", 6), 0);

        ASSERT_EQ(keyring_setup_next_record(buf, size, &offset, &name, &payload, &payload_size), EFI_NOT_FOUND);
        ASSERT_EQ(offset, size);

        /* Empty payloads end cleanly right away */
        ASSERT_EQ(walk(buf, 0), EFI_NOT_FOUND);

        /* Truncation at every point: walking must end in EFI_INVALID_PARAMETER, unless the cut happens to
         * fall on a record boundary, where it is a clean end. */
        for (size_t cut = 1; cut < size; cut++)
                ASSERT_EQ(walk(buf, cut), cut == boundary1 ? EFI_NOT_FOUND : EFI_INVALID_PARAMETER);

        /* A record with a zero size payload is malformed */
        uint8_t zero[64];
        size = append_record(zero, 0, "keyring-setup.fs-verity.foo", "");
        ASSERT_EQ(walk(zero, size), EFI_INVALID_PARAMETER);

        /* A record with an invalid name is malformed */
        uint8_t bad[64];
        size = append_record(bad, 0, "not-a-keyring-cred", "hello");
        ASSERT_EQ(walk(bad, size), EFI_INVALID_PARAMETER);

        /* A length field pointing past the end is malformed, whichever of its bytes does it */
        uint8_t overrun[64];
        size = append_record(overrun, 0, "keyring-setup.fs-verity.foo", "hello");
        size_t length_field = strlen("keyring-setup.fs-verity.foo") + 1;
        overrun[length_field] = 0xFF;
        ASSERT_EQ(walk(overrun, size), EFI_INVALID_PARAMETER);
        overrun[length_field] = 5;
        overrun[length_field + 3] = 0x01;
        ASSERT_EQ(walk(overrun, size), EFI_INVALID_PARAMETER);
        overrun[length_field + 3] = 0;
        ASSERT_EQ(walk(overrun, size), EFI_NOT_FOUND);
}

TEST(keyring_setup_validate) {
        uint8_t buf[1024];
        size_t size, n;

        size = append_record(buf, 0, "keyring-setup.fs-verity.foo", "hello");
        size = append_record(buf, size, "keyring-setup.dm-verity.bar", "world!");
        ASSERT_EQ(keyring_setup_validate(buf, size, &n), EFI_SUCCESS);
        ASSERT_EQ(n, 2U);
        ASSERT_EQ(keyring_setup_validate(buf, size, NULL), EFI_SUCCESS);

        /* Repeated names are refused */
        size = append_record(buf, size, "keyring-setup.fs-verity.foo", "again");
        ASSERT_EQ(keyring_setup_validate(buf, size, &n), EFI_ALREADY_STARTED);

        /* Malformed records are refused */
        size = append_record(buf, 0, "keyring-setup.fs-verity.foo", "hello");
        ASSERT_EQ(keyring_setup_validate(buf, size - 1, &n), EFI_INVALID_PARAMETER);

        /* Size limits */
        ASSERT_EQ(keyring_setup_validate(buf, 0, &n), EFI_BAD_BUFFER_SIZE);

        _cleanup_free_ uint8_t *large = ASSERT_PTR(malloc(KEYRING_SETUP_SIZE_MAX + 1));
        size = append_record(large, 0, "keyring-setup.fs-verity.foo", "hello");
        memset(large + size, 0, KEYRING_SETUP_SIZE_MAX + 1 - size);
        ASSERT_EQ(keyring_setup_validate(large, KEYRING_SETUP_SIZE_MAX + 1, &n), EFI_BAD_BUFFER_SIZE);
}

DEFINE_TEST_MAIN(LOG_INFO);

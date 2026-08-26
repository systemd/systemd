/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "keyring-util.h"
#include "tests.h"

TEST(proc_keys_entry_parse) {
        _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .dm-verity: empty", &e));
        ASSERT_EQ(e.serial, 0x3bd7ab0b);
        ASSERT_STREQ(e.flags, "I------");
        ASSERT_EQ(e.perm, 0x082f0000u);
        ASSERT_EQ(e.uid, 0u);
        ASSERT_EQ(e.gid, 0u);
        ASSERT_STREQ(e.type, "keyring");
        ASSERT_STREQ(e.description, ".dm-verity: empty");
        proc_keys_entry_done(&e);

        /* The kernel truncates the type to nine characters, descriptions may contain spaces */
        ASSERT_OK(proc_keys_entry_parse("2f0a2f9c I--Q--- 123456  59s 39010000  1000  1000 asymmetri Example CA: 8f3c0a: X509.rsa 8f3c0a []", &e));
        ASSERT_EQ(e.serial, 0x2f0a2f9c);
        ASSERT_STREQ(e.flags, "I--Q---");
        ASSERT_EQ(e.perm, 0x39010000u);
        ASSERT_EQ(e.uid, 1000u);
        ASSERT_EQ(e.gid, 1000u);
        ASSERT_STREQ(e.type, "asymmetri");
        ASSERT_STREQ(e.description, "Example CA: 8f3c0a: X509.rsa 8f3c0a []");
        proc_keys_entry_done(&e);

        /* A key without describe callback has no description at all */
        ASSERT_OK(proc_keys_entry_parse("00000003 I------     1 perm 1f3f0000     0     0 keyring  ", &e));
        ASSERT_STREQ(e.type, "keyring");
        ASSERT_STREQ(e.description, "");
        proc_keys_entry_done(&e);

        ASSERT_ERROR(proc_keys_entry_parse("", &e), EBADMSG);
        ASSERT_ERROR(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0", &e), EBADMSG);
        ASSERT_ERROR(proc_keys_entry_parse("3bd7ab0b I-----     1 perm 082f0000     0     0 keyring   x", &e), EBADMSG);
        ASSERT_FAIL(proc_keys_entry_parse("zzzzzzzz I------     1 perm 082f0000     0     0 keyring   x", &e));
        ASSERT_FAIL(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000    -1     0 keyring   x", &e));
        ASSERT_ERROR(proc_keys_entry_parse("ffffffff I------     1 perm 082f0000     0     0 keyring   x", &e), ERANGE);
}

TEST(proc_keys_entry_is_keyring) {
        _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .dm-verity: empty", &e));
        ASSERT_TRUE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verit"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity:"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".fs-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .dm-verity: 3", &e));
        ASSERT_TRUE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Not instantiated: no count suffix */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b -----N-     1 perm 082f0000     0     0 keyring   .dm-verity", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Revoked keyrings linger until garbage collected */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b IR-----     1 perm 082f0000     0     0 keyring   .dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I-----i     1 perm 082f0000     0     0 keyring   .dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Only the "keyring" type may carry a dot-prefixed name; the kernel does not reserve it for others */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 39010000     0     0 asymmetri .dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .dm-verity: lots", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
}

TEST(keyring_find_by_name) {
        key_serial_t serial;
        int r;

        r = keyring_find_by_name(".this-keyring-does-not-exist", &serial);
        if (r == -EACCES || r == -ENOENT) {
                log_tests_skipped_errno(r, "/proc/keys not readable or keyring not found");
                return;
        }
        ASSERT_FAIL(r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

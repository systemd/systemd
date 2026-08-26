/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "keyring-util.h"
#include "stdio-util.h"
#include "tests.h"
#include "user-util.h"

TEST(proc_keys_entry_parse) {
        _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: empty", &e));
        ASSERT_EQ(e.serial, 0x3bd7ab0b);
        ASSERT_STREQ(e.flags, "I------");
        ASSERT_EQ(e.perm, 0x082f0000u);
        ASSERT_EQ(e.uid, 0u);
        ASSERT_EQ(e.gid, 0u);
        ASSERT_STREQ(e.type, "keyring");
        ASSERT_STREQ(e.description, ".dm-verity: empty");
        proc_keys_entry_done(&e);

        /* The kernel truncates the type to nine characters, descriptions may contain spaces */
        ASSERT_OK(proc_keys_entry_parse("2f0a2f9c I--Q--- 123456  59s 39010000  1000  1000 asymmetri "
                                        "Example CA: 8f3c0a: X509.rsa 8f3c0a []", &e));
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

        /* Flags the kernel might add later are ignored */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------X     1 perm 082f0000     0     0 keyring   "
                                        "x", &e));
        ASSERT_STREQ(e.flags, "I------");
        proc_keys_entry_done(&e);

        ASSERT_ERROR(proc_keys_entry_parse("", &e), EBADMSG);
        ASSERT_ERROR(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0", &e), EBADMSG);
        ASSERT_ERROR(proc_keys_entry_parse("3bd7ab0b I-----     1 perm 082f0000     0     0 keyring   "
                                           "x", &e), EBADMSG);
        ASSERT_FAIL(proc_keys_entry_parse("zzzzzzzz I------     1 perm 082f0000     0     0 keyring   "
                                          "x", &e));
        ASSERT_FAIL(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000    -1     0 keyring   "
                                          "x", &e));
        ASSERT_ERROR(proc_keys_entry_parse("ffffffff I------     1 perm 082f0000     0     0 keyring   "
                                           "x", &e), ERANGE);
}

TEST(proc_keys_entry_is_keyring) {
        _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: empty", &e));
        ASSERT_TRUE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verit"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity:"));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".fs-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: 3", &e));
        ASSERT_TRUE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Not instantiated: no count suffix */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b -----N-     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Revoked keyrings linger until garbage collected */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b IR-----     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I-D----     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I-----i     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        /* Only keyrings may carry a dot-prefixed name, the kernel does not reserve it for other types */
        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 39010000     0     0 asymmetri "
                                        ".dm-verity: 3", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
        proc_keys_entry_done(&e);

        ASSERT_OK(proc_keys_entry_parse("3bd7ab0b I------     1 perm 082f0000     0     0 keyring   "
                                        ".dm-verity: lots", &e));
        ASSERT_FALSE(proc_keys_entry_is_keyring(&e, ".dm-verity"));
}

TEST(keyring_find_by_name) {
        char name[STRLEN("test-keyring-util-find-") + DECIMAL_STR_MAX(pid_t)];
        _cleanup_free_ char *forged = NULL, *forged_ring = NULL;
        key_serial_t serial, ring, other, victim, forgery, forgery_ring;
        int r;

        r = keyring_find_by_name(".this-keyring-does-not-exist", getuid(), &serial);
        if (ERRNO_IS_NEG_PRIVILEGE(r) || r == -ERFKILL) {
                log_tests_skipped_errno(r, "/proc/keys not readable");
                return;
        }
        ASSERT_ERROR(r, ENOKEY);

        /* Keyrings the process possesses show up in /proc/keys. A leftover of a crashed run may linger. */
        xsprintf(name, "test-keyring-util-find-" PID_FMT, getpid());
        ring = add_key("keyring", name, NULL, 0, KEY_SPEC_THREAD_KEYRING);
        if (ring < 0) {
                log_tests_skipped_errno(errno, "Cannot create keyring");
                return;
        }
        ASSERT_OK(keyring_find_by_name(name, getuid(), &serial));
        ASSERT_EQ(serial, ring);
        ASSERT_OK(keyring_find_by_name(name, UID_INVALID, &serial));
        ASSERT_EQ(serial, ring);

        /* Owned by somebody else */
        ASSERT_ERROR(keyring_find_by_name(name, getuid() == 0 ? 1 : 0, &serial), ENOKEY);

        /* A description with a newline forges a /proc/keys row: the serial must describe the keyring, and
         * the real one listed twice is still one keyring */
        victim = add_key("user", "test-keyring-util-victim", "x", 1, KEY_SPEC_THREAD_KEYRING);
        ASSERT_OK_ERRNO(victim);
        ASSERT_OK(asprintf(&forged, "x\n%08x I------     1 perm 3f010000 %5u %5u keyring   %s",
                           (unsigned) victim, getuid(), getgid(), name));
        ASSERT_OK(asprintf(&forged_ring, "x\n%08x I------     1 perm 3f010000 %5u %5u keyring   %s",
                           (unsigned) ring, getuid(), getgid(), name));
        forgery = add_key("user", forged, "x", 1, KEY_SPEC_THREAD_KEYRING);
        ASSERT_OK_ERRNO(forgery);
        forgery_ring = add_key("user", forged_ring, "x", 1, KEY_SPEC_THREAD_KEYRING);
        ASSERT_OK_ERRNO(forgery_ring);
        ASSERT_OK(keyring_find_by_name(name, getuid(), &serial));
        ASSERT_EQ(serial, ring);

        /* Two keyrings of the same name are ambiguous */
        other = add_key("keyring", name, NULL, 0, KEY_SPEC_PROCESS_KEYRING);
        ASSERT_OK_ERRNO(other);
        ASSERT_ERROR(keyring_find_by_name(name, getuid(), &serial), ENOTUNIQ);

        (void) keyctl(KEYCTL_UNLINK, forgery_ring, KEY_SPEC_THREAD_KEYRING, 0, 0);
        (void) keyctl(KEYCTL_UNLINK, forgery, KEY_SPEC_THREAD_KEYRING, 0, 0);
        (void) keyctl(KEYCTL_UNLINK, victim, KEY_SPEC_THREAD_KEYRING, 0, 0);
        (void) keyctl(KEYCTL_UNLINK, other, KEY_SPEC_PROCESS_KEYRING, 0, 0);
        (void) keyctl(KEYCTL_UNLINK, ring, KEY_SPEC_THREAD_KEYRING, 0, 0);
}

TEST(keyring_find_by_name_from) {
        _cleanup_fclose_ FILE *f = NULL;
        key_serial_t serial;
        const char *s;

        /* Rows that do not parse at all can only mean the kernel changed the format */
        s = "what\nis\nthis\n";
        ASSERT_NOT_NULL(f = fmemopen((void*) s, strlen(s), "r"));
        ASSERT_ERROR(keyring_find_by_name_from(f, ".dm-verity", 0, &serial), EBADMSG);
        f = safe_fclose(f);

        /* An empty file means no keys, not a format change */
        ASSERT_NOT_NULL(f = fmemopen(NULL, 1, "w+"));
        ASSERT_ERROR(keyring_find_by_name_from(f, ".dm-verity", 0, &serial), ENOKEY);
        f = safe_fclose(f);

        /* And so do rows that parse but do not match, garbage among them or not */
        s = "3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .other: 3\n";
        ASSERT_NOT_NULL(f = fmemopen((void*) s, strlen(s), "r"));
        ASSERT_ERROR(keyring_find_by_name_from(f, ".dm-verity", 0, &serial), ENOKEY);
        f = safe_fclose(f);

        s = "garbage\n3bd7ab0b I------     1 perm 082f0000     0     0 keyring   .other: 3\n";
        ASSERT_NOT_NULL(f = fmemopen((void*) s, strlen(s), "r"));
        ASSERT_ERROR(keyring_find_by_name_from(f, ".dm-verity", 0, &serial), ENOKEY);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

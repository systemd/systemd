/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "iovec-util.h"
#include "keyring-util.h"
#include "stdio-util.h"
#include "string-util.h"
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

TEST(keyring_ops) {
        _cleanup_free_ key_serial_t *l = NULL;
        _cleanup_free_ char *desc = NULL, *ring_desc = NULL, *long_desc = NULL;
        char long_name[128];
        key_serial_t ring, key, other;
        uint32_t perm;
        size_t n;
        int r;

        /* A private keyring in the thread keyring suffices, no privileges needed */
        ring = add_key("keyring", "test-keyring-util", NULL, 0, KEY_SPEC_THREAD_KEYRING);
        if (ring < 0) {
                log_tests_skipped_errno(errno, "Cannot create keyring");
                return;
        }

        ASSERT_OK(keyring_list(ring, /* ret= */ NULL, &n));
        ASSERT_EQ(n, 0u);

        key = add_key("user", "test-key", "x", 1, ring);
        ASSERT_OK_ERRNO(key);

        ASSERT_OK(keyring_list(ring, &l, &n));
        ASSERT_EQ(n, 1u);
        ASSERT_EQ(l[0], key);

        /* The thread keyring exists now that something was added to it */
        ASSERT_OK(keyring_resolve(KEY_SPEC_THREAD_KEYRING));
        /* A special ID the kernel does not know */
        ASSERT_ERROR(keyring_resolve(-12345), EINVAL);

        /* Write also grants removing a key again */
        ASSERT_OK(keyring_unlink_key(ring, key));
        ASSERT_OK(keyring_list(ring, /* ret= */ NULL, &n));
        ASSERT_EQ(n, 0u);
        key = add_key("user", "test-key", "x", 1, ring);
        ASSERT_OK_ERRNO(key);

        /* A keyring created via add_key() grants the possessor everything and the owner View */
        ASSERT_OK(keyring_perm(ring, &perm));
        ASSERT_EQ(perm, (uint32_t) (KEY_POS_ALL|KEY_USR_VIEW));
        ASSERT_OK(keyring_description(ring, &ring_desc));
        ASSERT_STREQ(ring_desc, "test-keyring-util");

        /* The restriction of systemd-keyring-setup admits asymmetric keys signed by a member only, and
         * cannot be replaced */
        r = keyring_restrict(ring, "asymmetric", "key_or_keyring:0:chain");
        if (IN_SET(r, -ENOKEY, -ENOENT)) {
                log_tests_skipped_errno(r, "Kernel lacks asymmetric keys");
                return;
        }
        ASSERT_OK(r);
        ASSERT_ERROR(keyring_restrict(ring, "asymmetric", "key_or_keyring:0:chain"), EEXIST);
        ASSERT_ERROR_ERRNO(add_key("user", "test-key-2", "y", 1, ring), EOPNOTSUPP);
        ASSERT_OK(keyring_list(ring, /* ret= */ NULL, &n));
        ASSERT_EQ(n, 1u);

        /* The mask systemd-keyring-setup leaves behind: the possessor may search, the owner may look, list,
         * add and remove, but neither change the mask nor the restriction. A search descending from a possessed
         * keyring still succeeds, which is how the kernel verifies signatures against a sealed keyring. */
        ASSERT_OK(keyring_set_perm(ring, KEY_POS_SEARCH|KEY_USR_VIEW|KEY_USR_READ|KEY_USR_WRITE));
        ASSERT_OK(keyring_perm(ring, &perm));
        ASSERT_EQ(perm, (uint32_t) (KEY_POS_SEARCH|KEY_USR_VIEW|KEY_USR_READ|KEY_USR_WRITE));
        ASSERT_ERROR(keyring_set_perm(ring, KEY_POS_ALL), EACCES);
        ASSERT_ERROR(keyring_restrict(ring, "asymmetric", "key_or_keyring:0:chain"), EACCES);
        ASSERT_ERROR_ERRNO(add_key("user", "test-key-3", "z", 1, ring), EOPNOTSUPP);
        ASSERT_OK(keyring_list(ring, /* ret= */ NULL, &n));
        ASSERT_EQ(n, 1u);
        ASSERT_EQ(keyctl(KEYCTL_SEARCH, KEY_SPEC_THREAD_KEYRING, (unsigned long) "user",
                         (unsigned long) "test-key", 0), (long) key);
        ASSERT_OK(RET_NERRNO(keyctl(KEYCTL_UNLINK, key, ring, 0, 0)));
        ASSERT_OK(keyring_list(ring, /* ret= */ NULL, &n));
        ASSERT_EQ(n, 0u);

        /* Descriptions of asymmetric keys are long, the describe buffer must grow */
        memset(long_name, 'x', sizeof(long_name) - 1);
        long_name[sizeof(long_name) - 1] = 0;
        other = add_key("user", long_name, "x", 1, KEY_SPEC_THREAD_KEYRING);
        ASSERT_OK_ERRNO(other);
        ASSERT_OK(keyring_describe(other, &desc));
        ASSERT_TRUE(startswith(desc, "user;"));
        ASSERT_TRUE(endswith(desc, long_name));
        ASSERT_OK(keyring_description(other, &long_desc));
        ASSERT_STREQ(long_desc, long_name);

        (void) keyctl(KEYCTL_UNLINK, other, KEY_SPEC_THREAD_KEYRING, 0, 0);
        (void) keyctl(KEYCTL_UNLINK, ring, KEY_SPEC_THREAD_KEYRING, 0, 0);
}

/* Self-signed, CN=test-keyring-util-cert, subject key identifier
 * 142fb06314c9a0ae97ac6fc60510533009799f1e */
static const uint8_t test_cert_der[] = {
        0x30, 0x82, 0x01, 0x99, 0x30, 0x82, 0x01, 0x3f, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x67, 0x8b, 0x8e, 0x64, 0x9b, 0x1a, 0xbb, 0x20, 0x99,
        0x4f, 0xe6, 0x35, 0x9f, 0x8f, 0xe0, 0xcc, 0x23, 0x99, 0x4e, 0xd1, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16,
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x72, 0x69, 0x6e, 0x67,
        0x2d, 0x75, 0x74, 0x69, 0x6c, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x30, 0x20,
        0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x33, 0x31, 0x30, 0x37, 0x35, 0x31,
        0x31, 0x34, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x38, 0x30,
        0x37, 0x30, 0x37, 0x35, 0x31, 0x31, 0x34, 0x5a, 0x30, 0x21, 0x31, 0x1f,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x74, 0x65, 0x73,
        0x74, 0x2d, 0x6b, 0x65, 0x79, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x75, 0x74,
        0x69, 0x6c, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06,
        0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xd7, 0x37,
        0x02, 0xe6, 0x58, 0x76, 0x77, 0xdf, 0xd9, 0x3d, 0x92, 0xb1, 0x02, 0xe4,
        0x2a, 0x79, 0x5c, 0x84, 0xf3, 0x97, 0xcf, 0x48, 0xdd, 0x71, 0xd6, 0x62,
        0xeb, 0xde, 0x79, 0xdc, 0x49, 0x85, 0x86, 0x56, 0xa7, 0x08, 0x4f, 0xf8,
        0x4c, 0x08, 0x02, 0xa1, 0xbc, 0xfd, 0x37, 0x1d, 0x9c, 0x5f, 0x39, 0x0c,
        0x78, 0x02, 0xa0, 0xbd, 0x0a, 0xd5, 0x52, 0x23, 0x15, 0x3e, 0x16, 0x3e,
        0xf5, 0x04, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x14, 0x2f, 0xb0, 0x63, 0x14, 0xc9, 0xa0,
        0xae, 0x97, 0xac, 0x6f, 0xc6, 0x05, 0x10, 0x53, 0x30, 0x09, 0x79, 0x9f,
        0x1e, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0x14, 0x2f, 0xb0, 0x63, 0x14, 0xc9, 0xa0, 0xae, 0x97, 0xac,
        0x6f, 0xc6, 0x05, 0x10, 0x53, 0x30, 0x09, 0x79, 0x9f, 0x1e, 0x30, 0x0f,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x0f, 0x10,
        0xa6, 0xbd, 0xbd, 0x3d, 0x5a, 0x8c, 0x2c, 0xec, 0xb2, 0x32, 0xac, 0x75,
        0x47, 0x5f, 0x8d, 0x73, 0x08, 0xdb, 0x0d, 0x65, 0x90, 0x26, 0xcc, 0xa6,
        0xc9, 0x01, 0xa1, 0x85, 0x45, 0xb4, 0x02, 0x21, 0x00, 0xdb, 0x09, 0x6f,
        0xc5, 0xfd, 0x97, 0xd8, 0x21, 0xdd, 0x28, 0x31, 0x4e, 0x82, 0xe2, 0x46,
        0x86, 0xb8, 0xfe, 0xac, 0x6e, 0x14, 0x27, 0xe2, 0x04, 0x3e, 0x64, 0xd1,
        0x6d, 0x14, 0x40, 0xbc, 0xbd,
};

/* Self-signed, CN=test-keyring-util-stranger */
static const uint8_t test_stranger_der[] = {
        0x30, 0x82, 0x01, 0xa0, 0x30, 0x82, 0x01, 0x47, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x21, 0xac, 0x6d, 0x07, 0x9c, 0xae, 0x5e, 0xca, 0x5b,
        0x8f, 0xbd, 0x1d, 0x1d, 0x35, 0xcb, 0x62, 0x98, 0x80, 0x5c, 0x84, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x25, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1a,
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x72, 0x69, 0x6e, 0x67,
        0x2d, 0x75, 0x74, 0x69, 0x6c, 0x2d, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67,
        0x65, 0x72, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x33, 0x31,
        0x30, 0x37, 0x35, 0x31, 0x31, 0x34, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32,
        0x36, 0x30, 0x38, 0x30, 0x37, 0x30, 0x37, 0x35, 0x31, 0x31, 0x34, 0x5a,
        0x30, 0x25, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x1a, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x72, 0x69, 0x6e,
        0x67, 0x2d, 0x75, 0x74, 0x69, 0x6c, 0x2d, 0x73, 0x74, 0x72, 0x61, 0x6e,
        0x67, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x80, 0x00, 0x64, 0x74, 0x92, 0x3c,
        0x8e, 0x8f, 0xea, 0x97, 0xbb, 0x73, 0xa6, 0xe7, 0x02, 0x5f, 0x64, 0x5d,
        0xee, 0xaa, 0x63, 0xe7, 0xcb, 0x11, 0x06, 0x22, 0xed, 0xef, 0x15, 0x36,
        0x9a, 0xb2, 0x02, 0x20, 0xe8, 0x39, 0x3d, 0xdd, 0xc1, 0x6f, 0xf9, 0x8c,
        0x4d, 0x01, 0x3a, 0x0e, 0xa6, 0x23, 0xd2, 0x0d, 0xae, 0x37, 0x60, 0xd4,
        0x81, 0xde, 0x96, 0x67, 0x3c, 0x64, 0x33, 0x00, 0x11, 0x69, 0xa3, 0x53,
        0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0xe5, 0x32, 0xa4, 0xaa, 0x40, 0x47, 0xed, 0x04, 0x85, 0x14, 0x3d,
        0x56, 0x54, 0x7d, 0x7d, 0xf5, 0x11, 0x56, 0xb7, 0x09, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xe5, 0x32,
        0xa4, 0xaa, 0x40, 0x47, 0xed, 0x04, 0x85, 0x14, 0x3d, 0x56, 0x54, 0x7d,
        0x7d, 0xf5, 0x11, 0x56, 0xb7, 0x09, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x60, 0x4d, 0x16, 0x1e, 0x4b, 0xa6,
        0x3e, 0x81, 0x26, 0xff, 0x49, 0x35, 0x5d, 0xa0, 0x5b, 0xcb, 0x80, 0xec,
        0x69, 0x53, 0xfd, 0x20, 0x8a, 0xba, 0xef, 0x4c, 0x8b, 0x4f, 0x02, 0x0c,
        0x3d, 0xe3, 0x02, 0x20, 0x2b, 0xc6, 0x20, 0x08, 0xd5, 0xe6, 0xc6, 0x4d,
        0x00, 0x6c, 0x84, 0xd5, 0xb4, 0x4d, 0x20, 0xed, 0xb1, 0xf3, 0xfb, 0x54,
        0xf1, 0xe8, 0xa6, 0x84, 0xf1, 0xcc, 0xce, 0x37, 0xcd, 0xd6, 0xef, 0xa1,
};

TEST(keyring_chain) {
        _cleanup_free_ char *description = NULL;
        key_serial_t ring, serial, serial2;
        int r;

        ring = add_key("keyring", "test-keyring-util-chain", NULL, 0, KEY_SPEC_THREAD_KEYRING);
        if (ring < 0)
                return (void) log_tests_skipped_errno(errno, "Cannot create keyring");

        struct iovec der = IOVEC_MAKE((void*) test_cert_der, sizeof(test_cert_der)),
                stranger_der = IOVEC_MAKE((void*) test_stranger_der, sizeof(test_stranger_der));

        /* Added without a description the kernel derives "<subject>: <key id>", which the presence check of
         * systemd-keyring-setup relies on */
        r = keyring_add_asymmetric(ring, /* description= */ NULL, &der, &serial);
        if (IN_SET(r, -ENOPKG, -EBADMSG, -ENOENT, -ENOKEY))
                return (void) log_tests_skipped_errno(r, "Kernel cannot parse the certificate");
        ASSERT_OK(r);
        ASSERT_OK(keyring_description(serial, &description));
        ASSERT_STREQ(description, "test-keyring-util-cert: 142fb06314c9a0ae97ac6fc60510533009799f1e");

        /* An explicit description wins over the derived one */
        _cleanup_free_ char *named = NULL;
        key_serial_t serial_named;
        ASSERT_OK(keyring_add_asymmetric(ring, "named", &der, &serial_named));
        ASSERT_OK(keyring_description(serial_named, &named));
        ASSERT_STREQ(named, "named");
        ASSERT_OK(keyring_unlink_key(ring, serial_named));

        /* Under the chain restriction only certificates signed by a member may be added, and the self-signed
         * member chains to itself */
        r = keyring_restrict(ring, "asymmetric", "key_or_keyring:0:chain");
        if (IN_SET(r, -ENOKEY, -ENOENT))
                return (void) log_tests_skipped_errno(r, "Kernel lacks asymmetric key restrictions");
        ASSERT_OK(r);
        r = keyring_add_asymmetric(ring, /* description= */ NULL, &der, &serial2);
        if (r == -ENOPKG)
                return (void) log_tests_skipped_errno(r, "Kernel cannot verify the signature algorithm");
        ASSERT_OK(r);
        ASSERT_ERROR(keyring_add_asymmetric(ring, /* description= */ NULL, &stranger_der, &serial2), ENOKEY);

        (void) keyctl(KEYCTL_UNLINK, ring, KEY_SPEC_THREAD_KEYRING, 0, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "image-policy.h"
#include "tests.h"

static void test_policy(const ImagePolicy *p, const char *name) {
        _cleanup_free_ char *as_string = NULL, *as_string_simplified = NULL;
        _cleanup_free_ ImagePolicy *parsed = NULL;

        assert_se(image_policy_to_string(p, /* simplify= */ false, &as_string) >= 0);
        assert_se(image_policy_to_string(p, /* simplify= */ true, &as_string_simplified) >= 0);

        printf("%s%s", ansi_underline(), name);

        if (!streq(as_string_simplified, name)) {
                printf(" → %s", as_string_simplified);

                if (!streq(as_string, as_string_simplified))
                        printf(" (aka %s)", as_string);
        }

        printf("%s\n", ansi_normal());

        assert_se(image_policy_from_string(as_string, /* graceful= */ false, &parsed) >= 0);
        assert_se(image_policy_equal(p, parsed));
        parsed = image_policy_free(parsed);

        assert_se(image_policy_from_string(as_string_simplified, /* graceful= */ false, &parsed) >= 0);
        assert_se(image_policy_equivalent(p, parsed));
        parsed = image_policy_free(parsed);

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                _cleanup_free_ char *k = NULL;
                PartitionPolicyFlags f;

                f = image_policy_get(p, d);
                if (f < 0) {
                        f = image_policy_get_exhaustively(p, d);
                        assert_se(f >= 0);
                        assert_se(partition_policy_flags_to_string(f, /* simplify= */ true, &k) >= 0);

                        printf("%s\t%s → n/a (exhaustively: %s)%s\n", ansi_grey(), partition_designator_to_string(d), k, ansi_normal());
                } else {
                        assert_se(partition_policy_flags_to_string(f, /* simplify= */ true, &k) >= 0);
                        printf("\t%s → %s\n", partition_designator_to_string(d), k);
                }
        }

        _cleanup_free_ char *w = NULL;
        assert_se(partition_policy_flags_to_string(image_policy_default(p), /* simplify= */ true, &w) >= 0);
        printf("\tdefault → %s\n", w);
}

static void test_policy_string(const char *t) {
        _cleanup_free_ ImagePolicy *parsed = NULL;

        assert_se(image_policy_from_string(t, /* graceful= */ false, &parsed) >= 0);
        test_policy(parsed, t);
}

static void test_policy_equiv(const char *s, bool (*func)(const ImagePolicy *p)) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;

        assert_se(image_policy_from_string(s, /* graceful= */ false, &p) >= 0);

        assert_se(func(p));
        assert_se(func == image_policy_equiv_ignore || !image_policy_equiv_ignore(p));
        assert_se(func == image_policy_equiv_allow || !image_policy_equiv_allow(p));
        assert_se(func == image_policy_equiv_deny || !image_policy_equiv_deny(p));
}

TEST_RET(test_image_policy_to_string) {
        test_policy(&image_policy_allow, "*");
        test_policy(&image_policy_ignore, "-");
        test_policy(&image_policy_deny, "~");
        test_policy(&image_policy_sysext, "sysext");
        test_policy(&image_policy_sysext_strict, "sysext-strict");
        test_policy(&image_policy_confext, "confext");
        test_policy(&image_policy_confext_strict, "confext-strict");
        test_policy(&image_policy_container, "container");
        test_policy(&image_policy_host, "host");
        test_policy(&image_policy_service, "service");
        test_policy(NULL, "null");

        test_policy_string("");
        test_policy_string("-");
        test_policy_string("*");
        test_policy_string("~");
        test_policy_string("swap=open");
        test_policy_string("swap=open:root=signed");
        test_policy_string("swap=open:root=signed+read-only-on+growfs-off:=absent");
        test_policy_string("=-");
        test_policy_string("=");
        test_policy_string("root=ext4+squashfs+verity");
        test_policy_string("usr=encrypted+erofs+read-only-off");
        test_policy_string("home=unprotected+btrfs");
        test_policy_string("=vfat+erofs");

        test_policy_equiv("", image_policy_equiv_ignore);
        test_policy_equiv("-", image_policy_equiv_ignore);
        test_policy_equiv("*", image_policy_equiv_allow);
        test_policy_equiv("~", image_policy_equiv_deny);
        test_policy_equiv("=absent", image_policy_equiv_deny);
        test_policy_equiv("=open", image_policy_equiv_allow);
        test_policy_equiv("=verity+signed+encrypted+encryptedwithintegrity+unprotected+unused+absent", image_policy_equiv_allow);
        test_policy_equiv("=signed+verity+encrypted+encryptedwithintegrity+unused+unprotected+absent", image_policy_equiv_allow);
        test_policy_equiv("=ignore", image_policy_equiv_ignore);
        test_policy_equiv("=absent+unused", image_policy_equiv_ignore);
        test_policy_equiv("=unused+absent", image_policy_equiv_ignore);
        test_policy_equiv("root=ignore:=ignore", image_policy_equiv_ignore);

        assert_se(image_policy_from_string("pfft", /* graceful= */ false, NULL) == -EINVAL);
        assert_se(image_policy_from_string("öäüß", /* graceful= */ false, NULL) == -EINVAL);
        assert_se(image_policy_from_string(":", /* graceful= */ false, NULL) == -EINVAL);
        assert_se(image_policy_from_string("a=", /* graceful= */ false, NULL) == -EBADSLT);
        assert_se(image_policy_from_string("=a", /* graceful= */ false, NULL) == -EBADRQC);
        assert_se(image_policy_from_string("==", /* graceful= */ false, NULL) == -EBADRQC);
        assert_se(image_policy_from_string("root=verity:root=encrypted", /* graceful= */ false, NULL) == -ENOTUNIQ);
        assert_se(image_policy_from_string("root=grbl", /* graceful= */ false, NULL) == -EBADRQC);
        assert_se(image_policy_from_string("wowza=grbl", /* graceful= */ false, NULL) == -EBADSLT);

        assert_se(image_policy_from_string("pfft", /* graceful= */ true, NULL) == -EINVAL);
        assert_se(image_policy_from_string("öäüß", /* graceful= */ true, NULL) == -EINVAL);
        assert_se(image_policy_from_string(":", /* graceful= */ true, NULL) == -EINVAL);
        assert_se(image_policy_from_string("a=", /* graceful= */ true, NULL) == 0);
        assert_se(image_policy_from_string("=a", /* graceful= */ true, NULL) == 0);
        assert_se(image_policy_from_string("==", /* graceful= */ true, NULL) == 0);
        assert_se(image_policy_from_string("root=verity:root=encrypted", /* graceful= */ true, NULL) == -ENOTUNIQ);
        assert_se(image_policy_from_string("root=grbl", /* graceful= */ true, NULL) == 0);
        assert_se(image_policy_from_string("wowza=grbl", /* graceful= */ true, NULL) == 0);

        return 0;
}

TEST(extend) {
        assert_se(partition_policy_flags_extend(0) == _PARTITION_POLICY_MASK);
        assert_se(partition_policy_flags_extend(_PARTITION_POLICY_MASK) == _PARTITION_POLICY_MASK);
        assert_se(partition_policy_flags_extend(PARTITION_POLICY_UNPROTECTED) == (PARTITION_POLICY_UNPROTECTED|_PARTITION_POLICY_PFLAGS_MASK));
        assert_se(partition_policy_flags_extend(PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_READ_ONLY_ON) == (PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_READ_ONLY_ON|_PARTITION_POLICY_GROWFS_MASK));
        assert_se(partition_policy_flags_extend(PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_READ_ONLY_ON|PARTITION_POLICY_GROWFS_OFF) == (PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_READ_ONLY_ON|PARTITION_POLICY_GROWFS_OFF));
        assert_se(partition_policy_flags_extend(PARTITION_POLICY_GROWFS_ON) == (PARTITION_POLICY_GROWFS_ON|_PARTITION_POLICY_USE_MASK|_PARTITION_POLICY_READ_ONLY_MASK));
}

static void test_policy_intersect_one(const char *a, const char *b, const char *c, bool intersect) {
        _cleanup_(image_policy_freep) ImagePolicy *x = NULL, *y = NULL, *z = NULL, *t = NULL;

        assert_se(image_policy_from_string(a, /* graceful= */ false, &x) >= 0);
        assert_se(image_policy_from_string(b, /* graceful= */ false, &y) >= 0);
        assert_se(image_policy_from_string(c, /* graceful= */ false, &z) >= 0);

        if (intersect)
                assert_se(image_policy_intersect(x, y, &t) >= 0);
        else
                assert_se(image_policy_union(x, y, &t) >= 0);

        _cleanup_free_ char *s1 = NULL, *s2 = NULL, *s3 = NULL, *s4 = NULL;
        assert_se(image_policy_to_string(x, false, &s1) >= 0);
        assert_se(image_policy_to_string(y, false, &s2) >= 0);
        assert_se(image_policy_to_string(z, false, &s3) >= 0);
        assert_se(image_policy_to_string(t, false, &s4) >= 0);

        log_info("%s %s %s → %s vs. %s", s1, intersect ? "^" : "U", s2, s3, s4);

        assert_se(image_policy_equivalent(z, t) > 0);
}

TEST(image_policy_intersect) {
        test_policy_intersect_one("", "", "", /* intersect= */ true);
        test_policy_intersect_one("-", "-", "-", /* intersect= */ true);
        test_policy_intersect_one("*", "*", "*", /* intersect= */ true);
        test_policy_intersect_one("~", "~", "~", /* intersect= */ true);
        test_policy_intersect_one("root=verity+signed", "root=signed+verity", "root=verity+signed", /* intersect= */ true);
        test_policy_intersect_one("root=verity+signed", "root=signed", "root=signed", /* intersect= */ true);
        test_policy_intersect_one("root=verity+signed", "root=verity", "root=verity", /* intersect= */ true);
        test_policy_intersect_one("root=open", "root=verity", "root=verity", /* intersect= */ true);
        test_policy_intersect_one("root=open", "=verity+ignore", "root=verity+ignore:=ignore", /* intersect= */ true);
}

TEST(image_policy_union) {
        test_policy_intersect_one("root=verity+signed", "root=signed+verity", "root=verity+signed", /* intersect= */ false);
        test_policy_intersect_one("root=verity+signed", "root=signed", "root=verity+signed", /* intersect= */ false);
        test_policy_intersect_one("root=verity+signed", "root=verity", "root=verity+signed", /* intersect= */ false);
        test_policy_intersect_one("root=signed", "root=verity", "root=verity+signed", /* intersect= */ false);
        test_policy_intersect_one("root=signed:=absent", "root=verity:=unused", "root=verity+signed", /* intersect= */ false);
        test_policy_intersect_one("root=open", "root=verity", "root=open", /* intersect= */ false);
        test_policy_intersect_one("root=open", "=verity+ignore", "root=open:=verity+ignore", /* intersect= */ false);
        test_policy_intersect_one("root=open:usr=absent", "root=open:usr=absent", "root=open:usr=absent", /* intersect= */ false);

}

static void test_policy_ignore_designators_one(const char *a, const PartitionDesignator array[], size_t n, const char *b) {
        _cleanup_(image_policy_freep) ImagePolicy *x = NULL, *y = NULL, *t = NULL;

        ASSERT_OK(image_policy_from_string(a, /* graceful= */ false, &x));
        ASSERT_OK(image_policy_from_string(b, /* graceful= */ false, &y));

        _cleanup_free_ char *s1 = NULL, *s2 = NULL, *s3 = NULL;
        ASSERT_OK(image_policy_to_string(x, true, &s1));
        ASSERT_OK(image_policy_to_string(y, true, &s2));

        ASSERT_OK(image_policy_ignore_designators(x, array, n, &t));

        ASSERT_OK(image_policy_to_string(t, true, &s3));

        log_info("%s → %s vs. %s", s1, s2, s3);

        ASSERT_TRUE(image_policy_equivalent(t, y));
}

TEST(image_policy_ignore_designators) {
        test_policy_ignore_designators_one("-", NULL, 0, "-");
        test_policy_ignore_designators_one("-", ((const PartitionDesignator[]) { PARTITION_ROOT }), 1, "-");
        test_policy_ignore_designators_one("*", ((const PartitionDesignator[]) { PARTITION_ROOT }), 1, "root=ignore:=open");
        test_policy_ignore_designators_one("*", ((const PartitionDesignator[]) { PARTITION_ROOT, PARTITION_USR }), 2, "root=ignore:usr=ignore:=open");
        test_policy_ignore_designators_one("~", ((const PartitionDesignator[]) { PARTITION_VAR, PARTITION_ESP, PARTITION_VAR }), 2, "var=ignore:esp=ignore:=absent");
}

TEST(partition_policy_determine_fstype) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *fstype = NULL;
        bool encrypted;
        int r;

        ASSERT_OK(image_policy_from_string("root=ext4+encrypted", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_GT(r, 0);
        ASSERT_STREQ(fstype, "ext4");
        ASSERT_TRUE(encrypted);

        fstype = mfree(fstype);
        p = image_policy_free(p);
        ASSERT_OK(image_policy_from_string("usr=verity+erofs", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_USR, &encrypted, &fstype);
        ASSERT_GT(r, 0);
        ASSERT_STREQ(fstype, "erofs");
        ASSERT_FALSE(encrypted);
        fstype = mfree(fstype);
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_EQ(r, 0);
        ASSERT_FALSE(fstype);
        ASSERT_FALSE(encrypted);

        fstype = mfree(fstype);
        p = image_policy_free(p);
        ASSERT_OK(image_policy_from_string("root=ext4+erofs", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_EQ(r, 0);
        ASSERT_FALSE(fstype);
        ASSERT_FALSE(encrypted);

        fstype = mfree(fstype);
        p = image_policy_free(p);
        ASSERT_OK(image_policy_from_string("root=encrypted", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_EQ(r, 0);
        ASSERT_FALSE(fstype);
        ASSERT_FALSE(encrypted);

        fstype = mfree(fstype);
        p = image_policy_free(p);
        ASSERT_OK(image_policy_from_string("", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_EQ(r, 0);
        ASSERT_FALSE(fstype);
        ASSERT_FALSE(encrypted);

        fstype = mfree(fstype);
        r = partition_policy_determine_fstype(/* policy= */ NULL, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_EQ(r, 0);
        ASSERT_FALSE(fstype);
        ASSERT_FALSE(encrypted);

        fstype = mfree(fstype);
        p = image_policy_free(p);
        ASSERT_OK(image_policy_from_string("root=encrypted+signed+btrfs", /* graceful= */ false, &p));
        r = partition_policy_determine_fstype(p, PARTITION_ROOT, &encrypted, &fstype);
        ASSERT_GT(r, 0);
        ASSERT_STREQ(fstype, "btrfs");
        ASSERT_FALSE(encrypted);
}

TEST(image_policy_new_from_dissected) {
        _cleanup_(image_policy_freep) ImagePolicy *policy = NULL;
        DissectedImage image;
        VeritySettings verity;
        uint8_t dummy_data[4];

        /* Test 1: Empty image - all partitions should be absent */
        image = (DissectedImage) {};

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(image_policy_default(policy), PARTITION_POLICY_ABSENT);
        ASSERT_EQ(image_policy_n_entries(policy), (size_t) _PARTITION_DESIGNATOR_MAX);

        /* All partitions should have PARTITION_POLICY_ABSENT */
        for (PartitionDesignator pd = 0; pd < _PARTITION_DESIGNATOR_MAX; pd++)
                ASSERT_EQ(policy->policies[pd].flags, (PartitionPolicyFlags) PARTITION_POLICY_ABSENT);

        policy = image_policy_free(policy);

        /* Test 2: Image with a single ext4 root partition */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "ext4",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EXT4 | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_USR].flags, (PartitionPolicyFlags) PARTITION_POLICY_ABSENT);

        policy = image_policy_free(policy);

        /* Test 3: Image with encrypted root partition (LUKS) */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "crypto_LUKS",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_ENCRYPTED | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 4: Image with verity ready (without signature) */
        image = (DissectedImage) {
                .verity_ready = true,
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "squashfs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_SQUASHFS | PARTITION_POLICY_VERITY | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 5: Image with verity signature ready */
        image = (DissectedImage) {
                .verity_sig_ready = true,
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "erofs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EROFS | PARTITION_POLICY_SIGNED | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 6: Image with growfs enabled */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "btrfs",
                                .growfs = true,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_BTRFS | PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 7: Multiple partitions with different filesystems */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "ext4",
                        },
                        [PARTITION_USR] = {
                                .found = true,
                                .fstype = (char*) "xfs",
                        },
                        [PARTITION_HOME] = {
                                .found = true,
                                .fstype = (char*) "btrfs",
                                .growfs = true,
                        },
                        [PARTITION_ESP] = {
                                .found = true,
                                .fstype = (char*) "vfat",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EXT4 | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_USR].flags, (PartitionPolicyFlags) (PARTITION_POLICY_XFS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_HOME].flags, (PartitionPolicyFlags) (PARTITION_POLICY_BTRFS | PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_ESP].flags, (PartitionPolicyFlags) (PARTITION_POLICY_VFAT | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_SWAP].flags, (PartitionPolicyFlags) PARTITION_POLICY_ABSENT);

        policy = image_policy_free(policy);

        /* Test 8: VeritySettings with root_hash set (no signature) */
        dummy_data[0] = 0xde; dummy_data[1] = 0xad; dummy_data[2] = 0xbe; dummy_data[3] = 0xef;
        verity = (VeritySettings) {
                .designator = _PARTITION_DESIGNATOR_INVALID,
                .root_hash = IOVEC_MAKE(dummy_data, sizeof(dummy_data)),
        };
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "squashfs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, &verity);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_SQUASHFS | PARTITION_POLICY_VERITY | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 9: VeritySettings with root_hash_sig set */
        dummy_data[0] = 0x01; dummy_data[1] = 0x02; dummy_data[2] = 0x03; dummy_data[3] = 0x04;
        verity = (VeritySettings) {
                .designator = _PARTITION_DESIGNATOR_INVALID,
                .root_hash_sig = IOVEC_MAKE(dummy_data, sizeof(dummy_data)),
        };
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "erofs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, &verity);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EROFS | PARTITION_POLICY_SIGNED | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 10: VeritySettings with designator targeting specific partition */
        dummy_data[0] = 0xab; dummy_data[1] = 0xcd;
        verity = (VeritySettings) {
                .designator = PARTITION_USR,
                .root_hash = IOVEC_MAKE(dummy_data, 2),
        };
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "ext4",
                        },
                        [PARTITION_USR] = {
                                .found = true,
                                .fstype = (char*) "squashfs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, &verity);
        ASSERT_NOT_NULL(policy);
        /* Root should NOT have verity since verity targets USR */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EXT4 | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        /* USR should have verity */
        ASSERT_EQ(policy->policies[PARTITION_USR].flags, (PartitionPolicyFlags) (PARTITION_POLICY_SQUASHFS | PARTITION_POLICY_VERITY | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 11: Unknown filesystem type (should have no fstype flag) */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "unknown_fs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        /* Should only have GROWFS_OFF and READ_ONLY_ON for unknown filesystem */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 12: NULL filesystem type (should have no fstype flag) */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = NULL,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        /* Should only have GROWFS_OFF and READ_ONLY_ON for NULL fstype */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 13: Combination of verity_ready from image and verity settings - image takes precedence for sig */
        dummy_data[0] = 0x11; dummy_data[1] = 0x22;
        verity = (VeritySettings) {
                .designator = _PARTITION_DESIGNATOR_INVALID,
                .root_hash = IOVEC_MAKE(dummy_data, 2),
        };
        image = (DissectedImage) {
                .verity_sig_ready = true, /* This should take precedence */
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "squashfs",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, &verity);
        ASSERT_NOT_NULL(policy);
        /* verity_sig_ready should result in SIGNED, not just VERITY */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_SQUASHFS | PARTITION_POLICY_SIGNED | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 14: All known filesystem types */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = { .found = true, .fstype = (char*) "ext4" },
                        [PARTITION_USR] = { .found = true, .fstype = (char*) "btrfs" },
                        [PARTITION_HOME] = { .found = true, .fstype = (char*) "xfs" },
                        [PARTITION_SRV] = { .found = true, .fstype = (char*) "f2fs" },
                        [PARTITION_VAR] = { .found = true, .fstype = (char*) "erofs" },
                        [PARTITION_TMP] = { .found = true, .fstype = (char*) "squashfs" },
                        [PARTITION_ESP] = { .found = true, .fstype = (char*) "vfat" },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EXT4 | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_USR].flags, (PartitionPolicyFlags) (PARTITION_POLICY_BTRFS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_HOME].flags, (PartitionPolicyFlags) (PARTITION_POLICY_XFS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_SRV].flags, (PartitionPolicyFlags) (PARTITION_POLICY_F2FS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_VAR].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EROFS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_TMP].flags, (PartitionPolicyFlags) (PARTITION_POLICY_SQUASHFS | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));
        ASSERT_EQ(policy->policies[PARTITION_ESP].flags, (PartitionPolicyFlags) (PARTITION_POLICY_VFAT | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 15: Encrypted partition with verity (LUKS takes precedence, no verity flag) */
        image = (DissectedImage) {
                .verity_ready = true,
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "crypto_LUKS",
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        /* crypto_LUKS check happens first, then verity is added */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_ENCRYPTED | PARTITION_POLICY_VERITY | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 16: Multiple flags combined - encrypted + growfs */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_HOME] = {
                                .found = true,
                                .fstype = (char*) "crypto_LUKS",
                                .growfs = true,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_HOME].flags, (PartitionPolicyFlags) (PARTITION_POLICY_ENCRYPTED | PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_READ_ONLY_ON));

        policy = image_policy_free(policy);

        /* Test 17: single_file_system=true should NOT set growfs or read-only flags */
        image = (DissectedImage) {
                .single_file_system = true,
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "ext4",
                                .rw = true,
                                .growfs = true,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        /* single_file_system=true means no growfs/read-only flags */
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) PARTITION_POLICY_EXT4);

        policy = image_policy_free(policy);

        /* Test 18: rw=true should set READ_ONLY_OFF instead of READ_ONLY_ON */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "ext4",
                                .rw = true,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_EXT4 | PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_READ_ONLY_OFF));

        policy = image_policy_free(policy);

        /* Test 19: rw=true with growfs=true */
        image = (DissectedImage) {
                .partitions = {
                        [PARTITION_ROOT] = {
                                .found = true,
                                .fstype = (char*) "btrfs",
                                .rw = true,
                                .growfs = true,
                        },
                },
        };

        policy = image_policy_new_from_dissected(&image, /* verity= */ NULL);
        ASSERT_NOT_NULL(policy);
        ASSERT_EQ(policy->policies[PARTITION_ROOT].flags, (PartitionPolicyFlags) (PARTITION_POLICY_BTRFS | PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_READ_ONLY_OFF));
}

DEFINE_TEST_MAIN(LOG_INFO);

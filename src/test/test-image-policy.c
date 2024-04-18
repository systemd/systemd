/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "image-policy.h"
#include "pretty-print.h"
#include "string-util.h"
#include "tests.h"
#include "pager.h"

static void test_policy(const ImagePolicy *p, const char *name) {
        _cleanup_free_ char *as_string = NULL, *as_string_simplified = NULL;
        _cleanup_free_ ImagePolicy *parsed = NULL;

        assert_se(image_policy_to_string(p, /* simplified= */ false, &as_string) >= 0);
        assert_se(image_policy_to_string(p, /* simplified= */ true, &as_string_simplified) >= 0);

        printf("%s%s", ansi_underline(), name);

        if (!streq(as_string_simplified, name)) {
                printf(" → %s", as_string_simplified);

                if (!streq(as_string, as_string_simplified))
                        printf(" (aka %s)", as_string);
        }

        printf("%s\n", ansi_normal());

        assert_se(image_policy_from_string(as_string, &parsed) >= 0);
        assert_se(image_policy_equal(p, parsed));
        parsed = image_policy_free(parsed);

        assert_se(image_policy_from_string(as_string_simplified, &parsed) >= 0);
        assert_se(image_policy_equivalent(p, parsed));
        parsed = image_policy_free(parsed);

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                _cleanup_free_ char *k = NULL;
                PartitionPolicyFlags f;

                f = image_policy_get(p, d);
                if (f < 0) {
                        f = image_policy_get_exhaustively(p, d);
                        assert_se(f >= 0);
                        assert_se(partition_policy_flags_to_string(f, /* simplified= */ true, &k) >= 0);

                        printf("%s\t%s → n/a (exhaustively: %s)%s\n", ansi_grey(), partition_designator_to_string(d), k, ansi_normal());
                } else {
                        assert_se(partition_policy_flags_to_string(f, /* simplified= */ true, &k) >= 0);
                        printf("\t%s → %s\n", partition_designator_to_string(d), k);
                }
        }

        _cleanup_free_ char *w = NULL;
        assert_se(partition_policy_flags_to_string(image_policy_default(p), /* simplified= */ true, &w) >= 0);
        printf("\tdefault → %s\n", w);
}

static void test_policy_string(const char *t) {
        _cleanup_free_ ImagePolicy *parsed = NULL;

        assert_se(image_policy_from_string(t, &parsed) >= 0);
        test_policy(parsed, t);
}

static void test_policy_equiv(const char *s, bool (*func)(const ImagePolicy *p)) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;

        assert_se(image_policy_from_string(s, &p) >= 0);

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

        test_policy_equiv("", image_policy_equiv_ignore);
        test_policy_equiv("-", image_policy_equiv_ignore);
        test_policy_equiv("*", image_policy_equiv_allow);
        test_policy_equiv("~", image_policy_equiv_deny);
        test_policy_equiv("=absent", image_policy_equiv_deny);
        test_policy_equiv("=open", image_policy_equiv_allow);
        test_policy_equiv("=verity+signed+encrypted+unprotected+unused+absent", image_policy_equiv_allow);
        test_policy_equiv("=signed+verity+encrypted+unused+unprotected+absent", image_policy_equiv_allow);
        test_policy_equiv("=ignore", image_policy_equiv_ignore);
        test_policy_equiv("=absent+unused", image_policy_equiv_ignore);
        test_policy_equiv("=unused+absent", image_policy_equiv_ignore);
        test_policy_equiv("root=ignore:=ignore", image_policy_equiv_ignore);

        assert_se(image_policy_from_string("pfft", NULL) == -EINVAL);
        assert_se(image_policy_from_string("öäüß", NULL) == -EINVAL);
        assert_se(image_policy_from_string(":", NULL) == -EINVAL);
        assert_se(image_policy_from_string("a=", NULL) == -EBADSLT);
        assert_se(image_policy_from_string("=a", NULL) == -EBADRQC);
        assert_se(image_policy_from_string("==", NULL) == -EBADRQC);
        assert_se(image_policy_from_string("root=verity:root=encrypted", NULL) == -ENOTUNIQ);
        assert_se(image_policy_from_string("root=grbl", NULL) == -EBADRQC);
        assert_se(image_policy_from_string("wowza=grbl", NULL) == -EBADSLT);

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

static void test_policy_intersect_one(const char *a, const char *b, const char *c) {
        _cleanup_(image_policy_freep) ImagePolicy *x = NULL, *y = NULL, *z = NULL, *t = NULL;

        assert_se(image_policy_from_string(a, &x) >= 0);
        assert_se(image_policy_from_string(b, &y) >= 0);
        assert_se(image_policy_from_string(c, &z) >= 0);

        assert_se(image_policy_intersect(x, y, &t) >= 0);

        _cleanup_free_ char *s1 = NULL, *s2 = NULL, *s3 = NULL, *s4 = NULL;
        assert_se(image_policy_to_string(x, false, &s1) >= 0);
        assert_se(image_policy_to_string(y, false, &s2) >= 0);
        assert_se(image_policy_to_string(z, false, &s3) >= 0);
        assert_se(image_policy_to_string(t, false, &s4) >= 0);

        log_info("%s ^ %s → %s vs. %s", s1, s2, s3, s4);

        assert_se(image_policy_equivalent(z, t) > 0);
}

TEST(image_policy_intersect) {
        test_policy_intersect_one("", "", "");
        test_policy_intersect_one("-", "-", "-");
        test_policy_intersect_one("*", "*", "*");
        test_policy_intersect_one("~", "~", "~");
        test_policy_intersect_one("root=verity+signed", "root=signed+verity", "root=verity+signed");
        test_policy_intersect_one("root=verity+signed", "root=signed", "root=signed");
        test_policy_intersect_one("root=verity+signed", "root=verity", "root=verity");
        test_policy_intersect_one("root=open", "root=verity", "root=verity");
        test_policy_intersect_one("root=open", "=verity+ignore", "root=verity+ignore:=ignore");
}

DEFINE_TEST_MAIN(LOG_INFO);

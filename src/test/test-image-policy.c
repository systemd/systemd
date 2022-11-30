/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "image-policy.h"
#include "pretty-print.h"
#include "string-util.h"
#include "tests.h"
#include "pager.h"

static void test_policy(const ImagePolicy *p, const char *name) {
        _cleanup_free_ ImagePolicy *parsed = NULL;
        _cleanup_free_ char *s = NULL;

        assert_se(image_policy_to_string(p, &s) >= 0);

        if (streq(name, s))
                printf("%s%s%s\n", ansi_underline(), s, ansi_normal());
        else
                printf("%s%s → %s%s\n", ansi_underline(), name, s, ansi_normal());

        assert_se(image_policy_from_string(s, &parsed) >= 0);
        assert_se(image_policy_equal(p, parsed));

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                _cleanup_free_ char *k = NULL;
                PartitionPolicyFlags f;

                f = image_policy_get(p, d);
                if (f < 0) {
                        f = image_policy_get_exhaustively(p, d);
                        assert_se(f >= 0);
                        assert_se(partition_policy_flags_to_string(f, &k) >= 0);

                        printf("%s\t%s → n/a (exhaustively: %s)%s\n", ansi_grey(), partition_designator_to_string(d), k, ansi_normal());
                } else {
                        assert_se(partition_policy_flags_to_string(f, &k) >= 0);
                        printf("\t%s → %s\n", partition_designator_to_string(d), k);
                }
        }
}

static void test_policy_string(const char *t) {
        _cleanup_free_ ImagePolicy *parsed = NULL;

        assert_se(image_policy_from_string(t, &parsed) >= 0);
        test_policy(parsed, t);
}

TEST_RET(test_image_policy_to_string) {
        test_policy(&image_policy_sysext, "sysext");
        test_policy(&image_policy_container, "container");
        test_policy(&image_policy_host, "host");
        test_policy(&image_policy_service, "service");

        test_policy_string("");
        test_policy_string("*");
        test_policy_string("-");
        test_policy_string("~");

        test_policy_string("swap=open");
        test_policy_string("swap=open:root=signed");

        test_policy_string("swap=open:root=signed+read-only-on+growfs-off");

        _cleanup_free_ ImagePolicy *permissive_policy =
                malloc(offsetof(ImagePolicy, policies) + sizeof(PartitionPolicy) *  _PARTITION_DESIGNATOR_MAX);
        assert_se(permissive_policy);
        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++)
                permissive_policy->policies[d] = (PartitionPolicy) {
                        .designator = d,
                        .flags = PARTITION_POLICY_OPEN,
                };
        permissive_policy->n_policies = _PARTITION_DESIGNATOR_MAX;

        test_policy(permissive_policy, "permissive");

        return 0;
}

DEFINE_TEST_MAIN(LOG_INFO);

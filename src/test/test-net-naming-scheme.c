/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "tests.h"

#ifdef _DEFAULT_NET_NAMING_SCHEME
/* The primary purpose of this check is to verify that _DEFAULT_NET_NAMING_SCHEME_TEST
 * is a valid identifier. If an invalid name is given during configuration, this will
 * fail with a name error. */
assert_cc(_DEFAULT_NET_NAMING_SCHEME >= 0);
#endif

TEST(default_net_naming_scheme) {
        const NamingScheme *n;
        ASSERT_NOT_NULL(n = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME));
        log_info("default → %s", n->name);

        ASSERT_PTR_EQ(naming_scheme_from_name(n->name), n);
}

TEST(naming_scheme_conversions) {
        const NamingScheme *n;
        ASSERT_NOT_NULL(n = naming_scheme_from_name("latest"));
        log_info("latest → %s", n->name);

        ASSERT_NOT_NULL(n = naming_scheme_from_name("v238"));
        ASSERT_STREQ(n->name, "v238");
}

TEST(sriov_pf_port_name) {
        const NamingScheme *old, *new;

        ASSERT_NOT_NULL(old = naming_scheme_from_name("v261"));
        ASSERT_NOT_NULL(new = naming_scheme_from_name("v263"));
        ASSERT_FALSE(FLAGS_SET(old->flags, NAMING_SR_IOV_PF_PORT_NAME));
        ASSERT_EQ(new->flags, old->flags | NAMING_SR_IOV_PF_PORT_NAME);
}

DEFINE_TEST_MAIN(LOG_INFO);

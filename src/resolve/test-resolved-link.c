/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/if.h>

#include "netlink-internal.h"
#include "resolved-link.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * link_new()
 * ================================================================ */

TEST(link_new) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);
}

/* ================================================================
 * link_process_rtnl()
 * ================================================================ */

TEST(link_process_rtnl) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *msg = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        ASSERT_OK(netlink_open_family(&nl, AF_INET));
        nl->protocol = NETLINK_ROUTE;

        ASSERT_OK(sd_rtnl_message_new_link(nl, &msg, RTM_NEWLINK, 1));
        ASSERT_NOT_NULL(msg);
        message_seal(msg);

        ASSERT_OK(link_process_rtnl(link, msg));
}

/* ================================================================
 * link_relevant()
 * ================================================================ */

TEST(link_relevant) {
        Manager manager = {};
        LinkAddress *address = NULL;
        _cleanup_(link_freep) Link *link = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        link->flags = IFF_LOOPBACK;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link->operstate = IF_OPER_UP;

        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        union in_addr_union ip = { .in.s_addr = htobe32(0xc0a84301) };
        union in_addr_union bcast = { .in.s_addr = htobe32(0xc0a843ff) };

        ASSERT_OK(link_address_new(link, &address, AF_INET, &ip, &bcast));
        ASSERT_NOT_NULL(address);

        ASSERT_TRUE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->is_managed = true;
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->networkd_operstate = LINK_OPERSTATE_DEGRADED_CARRIER;
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link_address_free(address);
}

DEFINE_TEST_MAIN(LOG_DEBUG)

/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

        ASSERT_OK(netlink_open_family(&nl, AF_INET));
        nl->protocol = NETLINK_GENERIC;

        ASSERT_OK(sd_rtnl_message_new_link(nl, &msg, RTM_NEWLINK, 1));
        message_seal(msg);

        ASSERT_OK(link_process_rtnl(link, msg));
}

DEFINE_TEST_MAIN(LOG_DEBUG)

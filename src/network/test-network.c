/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <stdio.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "netdev.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "ordered-set.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "vrf.h"

TEST(deserialize_in_addr) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        _cleanup_free_ struct in6_addr *addresses6 = NULL;
        union in_addr_union a, b, c, d, e, f;
        static const char *addresses_string = "192.168.0.1 0:0:0:0:0:FFFF:204.152.189.116 192.168.0.2 ::1 192.168.0.3 1:0:0:0:0:0:0:8";

        ASSERT_ERROR(in_addr_from_string(AF_INET, "0:0:0:0:0:FFFF:204.152.189.116", &a), EINVAL);
        ASSERT_ERROR(in_addr_from_string(AF_INET6, "192.168.0.1", &d), EINVAL);

        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.1", &a));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.2", &b));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.3", &c));
        ASSERT_OK(in_addr_from_string(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116", &d));
        ASSERT_OK(in_addr_from_string(AF_INET6, "::1", &e));
        ASSERT_OK(in_addr_from_string(AF_INET6, "1:0:0:0:0:0:0:8", &f));

        ASSERT_OK_EQ(deserialize_in_addrs(&addresses, addresses_string), 3);
        ASSERT_NOT_NULL(addresses);
        ASSERT_TRUE(in4_addr_equal(&a.in, &addresses[0]));
        ASSERT_TRUE(in4_addr_equal(&b.in, &addresses[1]));
        ASSERT_TRUE(in4_addr_equal(&c.in, &addresses[2]));

        ASSERT_OK_EQ(deserialize_in6_addrs(&addresses6, addresses_string), 3);
        ASSERT_NOT_NULL(addresses6);
        ASSERT_TRUE(in6_addr_equal(&d.in6, &addresses6[0]));
        ASSERT_TRUE(in6_addr_equal(&e.in6, &addresses6[1]));
        ASSERT_TRUE(in6_addr_equal(&f.in6, &addresses6[2]));
}

static void test_route_tables_one(Manager *manager, const char *name, uint32_t number) {
        _cleanup_free_ char *str = NULL, *expected = NULL, *num_str = NULL;
        uint32_t t;

        if (!STR_IN_SET(name, "default", "main", "local")) {
                ASSERT_STREQ(hashmap_get(manager->route_table_names_by_number, UINT32_TO_PTR(number)), name);
                ASSERT_EQ(PTR_TO_UINT32(hashmap_get(manager->route_table_numbers_by_name, name)), number);
        }

        ASSERT_OK(asprintf(&expected, "%s(%" PRIu32 ")", name, number));
        ASSERT_OK(manager_get_route_table_to_string(manager, number, /* append_num= */ true, &str));
        ASSERT_STREQ(str, expected);

        str = mfree(str);

        ASSERT_OK(manager_get_route_table_to_string(manager, number, /* append_num= */ false, &str));
        ASSERT_STREQ(str, name);

        ASSERT_OK(manager_get_route_table_from_string(manager, name, &t));
        ASSERT_EQ(t, number);

        ASSERT_OK(asprintf(&num_str, "%" PRIu32, number));
        ASSERT_OK(manager_get_route_table_from_string(manager, num_str, &t));
        ASSERT_EQ(t, number);
}

TEST(route_tables) {
        _cleanup_(manager_freep) Manager *manager = NULL;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(manager_setup(manager));

        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "hoge:123 foo:456 aaa:111", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "bbb:11111 ccc:22222", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "ddd:22222", manager, manager));

        test_route_tables_one(manager, "hoge", 123);
        test_route_tables_one(manager, "foo", 456);
        test_route_tables_one(manager, "aaa", 111);
        test_route_tables_one(manager, "bbb", 11111);
        test_route_tables_one(manager, "ccc", 22222);

        ASSERT_FALSE(hashmap_contains(manager->route_table_numbers_by_name, "ddd"));

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);

        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "", manager, manager));
        ASSERT_NULL(manager->route_table_names_by_number);
        ASSERT_NULL(manager->route_table_numbers_by_name);

        /* Invalid pairs */
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "main:123 default:333 local:999", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "xxx:253 yyy:254 local:255", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "1234:321 :567 hoge:foo aaa:-888", manager, manager));
        ASSERT_NULL(manager->route_table_names_by_number);
        ASSERT_NULL(manager->route_table_numbers_by_name);

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);
}

TEST(vrf_table) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        Vrf vrf = {};

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(manager_setup(manager));

        vrf.meta.manager = manager;

        ASSERT_OK(config_parse_vrf_table("netdev", "filename", 1, "VRF", 1, "Table", 0, "default", &vrf.table, &vrf));
        ASSERT_EQ(vrf.table, 253U);

        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "vrf-test:1234", manager, manager));
        ASSERT_OK(config_parse_vrf_table("netdev", "filename", 1, "VRF", 1, "Table", 0, "vrf-test", &vrf.table, &vrf));
        ASSERT_EQ(vrf.table, 1234U);

        ASSERT_OK(config_parse_vrf_table("netdev", "filename", 1, "VRF", 1, "Table", 0, "5678", &vrf.table, &vrf));
        ASSERT_EQ(vrf.table, 5678U);

        ASSERT_OK(config_parse_vrf_table("netdev", "filename", 1, "VRF", 1, "Table", 0, "no-such-table", &vrf.table, &vrf));
        ASSERT_EQ(vrf.table, 5678U);
}

static int test_request_process(Request *req, Link *link, void *userdata) {
        assert_not_reached();
}

static int test_request_netlink_handler(
                sd_netlink *rtnl,
                sd_netlink_message *message,
                Request *req,
                Link *link,
                void *userdata) {

        assert(rtnl);
        assert(message);
        assert(req);
        assert(!link);
        assert(userdata);

        *(bool*) userdata = true;
        return 0;
}

static void test_request_netlink_handler_one(bool detach) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        bool handler_called = false;
        unsigned counter = 0;
        Request *req;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK_POSITIVE(manager_queue_request_full(
                        manager,
                        REQUEST_TYPE_ADDRESS_LABEL,
                        &handler_called,
                        /* free_func= */ NULL,
                        /* hash_func= */ NULL,
                        /* compare_func= */ NULL,
                        test_request_process,
                        &counter,
                        test_request_netlink_handler,
                        &req));
        ASSERT_EQ(counter, 1U);

        int ifindex = (int) if_nametoindex("lo");
        ASSERT_GT(ifindex, 0);
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, ifindex));
        ASSERT_OK(request_call_netlink_async(rtnl, message, req));
        ASSERT_EQ(netlink_get_reply_callback_count(rtnl), 1U);

        if (detach) {
                request_detach(req);
                ASSERT_EQ(counter, 0U);
                ASSERT_EQ(netlink_get_reply_callback_count(rtnl), 0U);
        }

        ASSERT_OK(sd_netlink_wait(rtnl, 0));
        ASSERT_OK_POSITIVE(sd_netlink_process(rtnl, /* ret= */ NULL));

        ASSERT_EQ(handler_called, !detach);
        ASSERT_EQ(counter, 0U);
        ASSERT_EQ(netlink_get_reply_callback_count(rtnl), 0U);
        ASSERT_TRUE(ordered_set_isempty(manager->request_queue));
}

TEST(request_netlink_handler_called) {
        test_request_netlink_handler_one(/* detach= */ false);
}

TEST(request_netlink_handler_detached) {
        test_request_netlink_handler_one(/* detach= */ true);
}

static void test_getlink_error_one(LinkState state, int error) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_(link_unrefp) Link *link = NULL;
        _cleanup_(netdev_unrefp) NetDev *loaded = NULL, *netdev = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *request = NULL, *added = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL, *removed = NULL;
        _cleanup_(unlink_tempfilep) char netdev_file[] = "/tmp/test-network-netdev-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        unsigned callbacks, retry;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(sd_event_new(&manager->event));
        ASSERT_OK(sd_netlink_open(&manager->rtnl));

        /* Only send read-only requests, and first verify that this ifindex does not exist. */
        ASSERT_OK(sd_rtnl_message_new_link(manager->rtnl, &request, RTM_GETLINK, INT_MAX));
        ASSERT_ERROR(sd_netlink_call(manager->rtnl, request, 0, /* ret= */ NULL), ENODEV);

        ASSERT_OK(fmkostemp_safe(netdev_file, "w", &f));
        ASSERT_OK_ERRNO(fputs("[NetDev]\nName=test-vanished\nKind=vlan\n[VLAN]\nId=1\n", f) < 0 ? -1 : 0);
        ASSERT_OK_ERRNO(fflush(f));
        ASSERT_OK(netdev_load_one(manager, netdev_file, &loaded));
        ASSERT_OK(netdev_attach_name(loaded, loaded->ifname));
        netdev = netdev_ref(loaded); /* Keep a test reference in addition to the manager's reference. */
        TAKE_PTR(loaded);

        ASSERT_OK(sd_rtnl_message_new_link(manager->rtnl, &added, RTM_NEWLINK, INT_MAX));
        ASSERT_OK(sd_rtnl_message_link_set_type(added, ARPHRD_ETHER));
        ASSERT_OK(sd_netlink_message_append_string(added, IFLA_IFNAME, "test-vanished"));
        ASSERT_OK(sd_netlink_message_open_container(added, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(added, IFLA_INFO_KIND, "vlan"));
        ASSERT_OK(sd_netlink_message_close_container(added));
        ASSERT_OK(sd_netlink_message_rewind(added, manager->rtnl));
        ASSERT_OK_ZERO(manager_rtnl_process_link(manager->rtnl, added, manager));

        ASSERT_EQ(netdev->ifindex, INT_MAX);
        ASSERT_OK(link_get_by_index(manager, INT_MAX, &link));
        link_ref(link); /* Keep a test reference in addition to the manager's reference. */

        ASSERT_OK(sd_rtnl_message_new_link(manager->rtnl, &removed, RTM_DELLINK, link->ifindex));
        ASSERT_OK(sd_netlink_message_append_string(removed, IFLA_IFNAME, link->ifname));
        ASSERT_OK(sd_netlink_message_rewind(removed, manager->rtnl));

        if (state == LINK_STATE_LINGER)
                ASSERT_OK_POSITIVE(manager_rtnl_process_link(manager->rtnl, removed, manager));
        else
                link_set_state(link, state);

        ASSERT_OK(message_new_synthetic_error(manager->rtnl, error, 1, &reply));
        ASSERT_OK_ZERO(link_getlink_handler_internal(
                        manager->rtnl, reply, link, "Synthetic GETLINK failure"));

        /* If the link vanished, it must be dropped immediately, so that it is not reconfigured and does not
         * stay tracked by the manager. Other errors retain the existing state-dependent recovery behavior. */
        callbacks = netlink_get_reply_callback_count(manager->rtnl);
        retry = link->automatic_reconfigure_ratelimit.num;
        if (error == -ENODEV) {
                ASSERT_EQ(link->state, LINK_STATE_LINGER);
                ASSERT_EQ(callbacks, 0U);
                ASSERT_EQ(retry, 0U);
                ASSERT_NULL(hashmap_get(manager->links_by_index, INT_TO_PTR(link->ifindex)));
                ASSERT_FALSE(hashmap_contains(manager->links_by_name, link->ifname));
                ASSERT_EQ(netdev->state, NETDEV_STATE_LOADING);
                ASSERT_EQ(netdev->ifindex, 0);
        } else if (state == LINK_STATE_FAILED) {
                /* Other late replies must continue to be ignored for failed links. */
                ASSERT_EQ(link->state, LINK_STATE_FAILED);
                ASSERT_EQ(callbacks, 0U);
                ASSERT_EQ(retry, 0U);
                ASSERT_PTR_EQ(hashmap_get(manager->links_by_index, INT_TO_PTR(link->ifindex)), link);
                ASSERT_TRUE(hashmap_contains(manager->links_by_name, link->ifname));
                ASSERT_EQ(netdev->ifindex, INT_MAX);
        } else {
                ASSERT_NE(link->state, LINK_STATE_LINGER);
                ASSERT_EQ(callbacks, 1U);
                ASSERT_EQ(retry, 1U);
                ASSERT_PTR_EQ(hashmap_get(manager->links_by_index, INT_TO_PTR(link->ifindex)), link);
                ASSERT_TRUE(hashmap_contains(manager->links_by_name, link->ifname));

                /* Drain the recovery request, so that the diagnostic below includes the complete retry
                 * burst. The link does not exist, so the drained request fails with ENODEV, and must be
                 * dropped instead of starting yet another reconfiguration. */
                for (unsigned i = 0; i < 16 && netlink_get_reply_callback_count(manager->rtnl) > 0; i++) {
                        ASSERT_OK(sd_netlink_wait(manager->rtnl, USEC_PER_SEC));
                        ASSERT_OK(sd_netlink_process(manager->rtnl, /* ret= */ NULL));
                }
                ASSERT_EQ(netlink_get_reply_callback_count(manager->rtnl), 0U);
                ASSERT_EQ(link->automatic_reconfigure_ratelimit.num, retry);
                ASSERT_EQ(link->state, LINK_STATE_LINGER);
                ASSERT_NULL(hashmap_get(manager->links_by_index, INT_TO_PTR(link->ifindex)));
                ASSERT_FALSE(hashmap_contains(manager->links_by_name, link->ifname));
                ASSERT_EQ(netdev->state, NETDEV_STATE_LOADING);
                ASSERT_EQ(netdev->ifindex, 0);
        }

        log_info("GETLINK error=%i, initial state=%s, queued callbacks=%u, retry count=%u, final state=%s",
                 error, link_state_to_string(state), callbacks, link->automatic_reconfigure_ratelimit.num,
                 link_state_to_string(link->state));

        /* A late or repeated RTM_DELLINK notification must be harmless. */
        ASSERT_OK(sd_netlink_message_rewind(removed, manager->rtnl));
        ASSERT_OK_POSITIVE(manager_rtnl_process_link(manager->rtnl, removed, manager));
        ASSERT_EQ(link->state, LINK_STATE_LINGER);
        ASSERT_FALSE(hashmap_contains(manager->links_by_index, INT_TO_PTR(link->ifindex)));
        ASSERT_FALSE(hashmap_contains(manager->links_by_name, link->ifname));
        ASSERT_EQ(netdev->state, NETDEV_STATE_LOADING);
        ASSERT_EQ(netdev->ifindex, 0);
        ASSERT_OK_POSITIVE(netdev_set_ifindex_internal(netdev, INT_MAX - 1));
}

TEST(getlink_enodev_pending) {
        test_getlink_error_one(LINK_STATE_PENDING, -ENODEV);
}

TEST(getlink_enodev_unmanaged) {
        test_getlink_error_one(LINK_STATE_UNMANAGED, -ENODEV);
}

TEST(getlink_enodev_configured) {
        test_getlink_error_one(LINK_STATE_CONFIGURED, -ENODEV);
}

TEST(getlink_enodev_failed) {
        test_getlink_error_one(LINK_STATE_FAILED, -ENODEV);
}

TEST(getlink_enodev_linger) {
        /* Here an RTM_DELLINK notification drops the link before the error handler is called. */
        test_getlink_error_one(LINK_STATE_LINGER, -ENODEV);
}

TEST(getlink_other_error_retries) {
        test_getlink_error_one(LINK_STATE_CONFIGURED, -EIO);
}

TEST(getlink_failed_other_error_ignored) {
        test_getlink_error_one(LINK_STATE_FAILED, -EIO);
}

TEST(manager_enumerate) {
        _cleanup_(manager_freep) Manager *manager = NULL;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(manager_setup(manager));

        /* TODO: should_reload, is false if the config dirs do not exist, so we can't do this test here, move
         * it to a test for paths_check_timestamps directly. */
        if (ASSERT_OK_OR(manager_load_config(manager), -EPERM) < 0)
                return (void) log_tests_skipped("Cannot load configuration files");

        ASSERT_OK(manager_enumerate(manager));
}

TEST(dhcp_hostname_shorten_overlong) {
        _cleanup_free_ char *s = NULL;

        /* simple hostname, no actions, no errors */
        ASSERT_OK_ZERO(shorten_overlong("name1", &s));
        ASSERT_STREQ(s, "name1");
        s = mfree(s);

        /* simple fqdn, no actions, no errors */
        ASSERT_OK_ZERO(shorten_overlong("name1.example.com", &s));
        ASSERT_STREQ(s, "name1.example.com");
        s = mfree(s);

        /* overlong fqdn, cut to first dot, no errors */
        ASSERT_OK_POSITIVE(shorten_overlong("name1.test-dhcp-this-one-here-is-a-very-very-long-domain.example.com", &s));
        ASSERT_STREQ(s, "name1");
        s = mfree(s);

        /* overlong hostname, cut to HOST_MAX_LEN, no errors */
        ASSERT_OK_POSITIVE(shorten_overlong("test-dhcp-this-one-here-is-a-very-very-long-hostname-without-domainname", &s));
        ASSERT_STREQ(s, "test-dhcp-this-one-here-is-a-very-very-long-hostname-without-dom");
        s = mfree(s);

        /* overlong fqdn, cut to first dot, empty result error */
        ASSERT_ERROR(shorten_overlong(".test-dhcp-this-one-here-is-a-very-very-long-hostname.example.com", &s), EDOM);
        ASSERT_NULL(s);
}

DEFINE_TEST_MAIN(LOG_INFO);

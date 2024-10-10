/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/fou.h>
#include <linux/genetlink.h>
#include <linux/if_macsec.h>
#include <linux/l2tp.h>
#include <linux/nl80211.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "macro.h"
#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(message_newlink_bridge) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        uint32_t cost;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 1) >= 0);
        assert_se(sd_rtnl_message_link_set_family(message, AF_BRIDGE) >= 0);
        assert_se(sd_netlink_message_open_container(message, IFLA_PROTINFO) >= 0);
        assert_se(sd_netlink_message_append_u32(message, IFLA_BRPORT_COST, 10) >= 0);
        assert_se(sd_netlink_message_close_container(message) >= 0);

        assert_se(sd_netlink_message_rewind(message, rtnl) >= 0);

        assert_se(sd_netlink_message_enter_container(message, IFLA_PROTINFO) >= 0);
        assert_se(sd_netlink_message_read_u32(message, IFLA_BRPORT_COST, &cost) >= 0);
        assert_se(cost == 10);
        assert_se(sd_netlink_message_exit_container(message) >= 0);
}

TEST(message_getlink) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        int ifindex;
        uint8_t u8_data;
        uint16_t u16_data;
        uint32_t u32_data;
        const char *str_data;
        struct ether_addr eth_data;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, &reply) == 1);

        /* u8 */
        assert_se(sd_netlink_message_read_u8(reply, IFLA_CARRIER, &u8_data) >= 0);
        assert_se(sd_netlink_message_read_u8(reply, IFLA_OPERSTATE, &u8_data) >= 0);
        assert_se(sd_netlink_message_read_u8(reply, IFLA_LINKMODE, &u8_data) >= 0);

        /* u16 */
        assert_se(sd_netlink_message_get_type(reply, &u16_data) >= 0);
        assert_se(u16_data == RTM_NEWLINK);

        /* u32 */
        assert_se(sd_netlink_message_read_u32(reply, IFLA_MTU, &u32_data) >= 0);
        assert_se(sd_netlink_message_read_u32(reply, IFLA_GROUP, &u32_data) >= 0);
        assert_se(sd_netlink_message_read_u32(reply, IFLA_TXQLEN, &u32_data) >= 0);
        assert_se(sd_netlink_message_read_u32(reply, IFLA_NUM_TX_QUEUES, &u32_data) >= 0);

        /* string */
        assert_se(sd_netlink_message_read_string(reply, IFLA_IFNAME, &str_data) >= 0);

        /* ether_addr */
        assert_se(sd_netlink_message_read_ether_addr(reply, IFLA_ADDRESS, &eth_data) >= 0);
}

TEST(message_address) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        int ifindex;
        struct in_addr in_data;
        struct ifa_cacheinfo cache;
        const char *label;
        int r;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        assert_se(sd_rtnl_message_new_addr(rtnl, &message, RTM_GETADDR, ifindex, AF_INET) >= 0);
        assert_se(sd_netlink_message_set_request_dump(message, true) >= 0);

        r = sd_netlink_call(rtnl, message, 0, &reply);
        assert_se(r >= 0);

        /* If the loopback device is down we won't get any results. */
        if (r > 0) {
                assert_se(sd_netlink_message_read_in_addr(reply, IFA_LOCAL, &in_data) >= 0);
                assert_se(sd_netlink_message_read_in_addr(reply, IFA_ADDRESS, &in_data) >= 0);
                assert_se(sd_netlink_message_read_string(reply, IFA_LABEL, &label) >= 0);
                assert_se(sd_netlink_message_read_cache_info(reply, IFA_CACHEINFO, &cache) >= 0);
        }
}

TEST(message_route) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        struct in_addr addr, addr_data;
        uint32_t index = 2, u32_data;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_route(rtnl, &req, RTM_NEWROUTE, AF_INET, RTPROT_STATIC) >= 0);

        addr.s_addr = htobe32(INADDR_LOOPBACK);

        assert_se(sd_netlink_message_append_in_addr(req, RTA_GATEWAY, &addr) >= 0);
        assert_se(sd_netlink_message_append_u32(req, RTA_OIF, index) >= 0);

        assert_se(sd_netlink_message_rewind(req, rtnl) >= 0);

        assert_se(sd_netlink_message_read_in_addr(req, RTA_GATEWAY, &addr_data) >= 0);
        assert_se(addr_data.s_addr == addr.s_addr);

        assert_se(sd_netlink_message_read_u32(req, RTA_OIF, &u32_data) >= 0);
        assert_se(u32_data == index);

        assert_se((req = sd_netlink_message_unref(req)) == NULL);
}

static int link_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        const char *data;

        assert_se(rtnl);
        assert_se(m);

        assert_se(streq_ptr(userdata, "foo"));

        assert_se(sd_netlink_message_read_string(m, IFLA_IFNAME, &data) >= 0);
        assert_se(streq(data, "lo"));

        log_info("%s: got link info about %s", __func__, data);
        return 1;
}

TEST(netlink_event_loop) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        _cleanup_free_ char *userdata = NULL;
        int ifindex;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        assert_se(userdata = strdup("foo"));

        assert_se(sd_event_default(&event) >= 0);
        assert_se(sd_netlink_attach_event(rtnl, event, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call_async(rtnl, NULL, m, link_handler, NULL, userdata, 0, NULL) >= 0);

        assert_se(sd_event_run(event, 0) >= 0);

        assert_se(sd_netlink_detach_event(rtnl) >= 0);
        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);
}

static void test_async_destroy(void *userdata) {
}

TEST(netlink_call_async) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *slot = NULL;
        _cleanup_free_ char *userdata = NULL;
        sd_netlink_destroy_t destroy_callback;
        const char *description;
        int ifindex;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        assert_se(userdata = strdup("foo"));

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call_async(rtnl, &slot, m, link_handler, test_async_destroy, userdata, 0, "hogehoge") >= 0);

        assert_se(sd_netlink_slot_get_netlink(slot) == rtnl);

        assert_se(sd_netlink_slot_get_userdata(slot) == userdata);
        assert_se(sd_netlink_slot_set_userdata(slot, NULL) == userdata);
        assert_se(sd_netlink_slot_get_userdata(slot) == NULL);
        assert_se(sd_netlink_slot_set_userdata(slot, userdata) == NULL);
        assert_se(sd_netlink_slot_get_userdata(slot) == userdata);

        assert_se(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback) == 1);
        assert_se(destroy_callback == test_async_destroy);
        assert_se(sd_netlink_slot_set_destroy_callback(slot, NULL) >= 0);
        assert_se(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback) == 0);
        assert_se(destroy_callback == NULL);
        assert_se(sd_netlink_slot_set_destroy_callback(slot, test_async_destroy) >= 0);
        assert_se(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback) == 1);
        assert_se(destroy_callback == test_async_destroy);

        assert_se(sd_netlink_slot_get_floating(slot) == 0);
        assert_se(sd_netlink_slot_set_floating(slot, 1) == 1);
        assert_se(sd_netlink_slot_get_floating(slot) == 1);

        assert_se(sd_netlink_slot_get_description(slot, &description) == 1);
        assert_se(streq(description, "hogehoge"));
        assert_se(sd_netlink_slot_set_description(slot, NULL) >= 0);
        assert_se(sd_netlink_slot_get_description(slot, &description) == 0);
        assert_se(description == NULL);

        assert_se(sd_netlink_wait(rtnl, 0) >= 0);
        assert_se(sd_netlink_process(rtnl, &reply) >= 0);

        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);
}

struct test_async_object {
        unsigned n_ref;
        char *ifname;
};

static struct test_async_object *test_async_object_free(struct test_async_object *t) {
        assert_se(t);

        free(t->ifname);
        return mfree(t);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(struct test_async_object, test_async_object, test_async_object_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct test_async_object *, test_async_object_unref);

static int link_handler2(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        struct test_async_object *t = userdata;
        const char *data;

        assert_se(rtnl);
        assert_se(m);
        assert_se(userdata);

        log_info("%s: got link info about %s", __func__, t->ifname);

        assert_se(sd_netlink_message_read_string(m, IFLA_IFNAME, &data) >= 0);
        assert_se(streq(data, "lo"));

        return 1;
}

static void test_async_object_destroy(void *userdata) {
        struct test_async_object *t = userdata;

        assert_se(userdata);

        log_info("%s: n_ref=%u", __func__, t->n_ref);
        test_async_object_unref(t);
}

TEST(async_destroy_callback) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_(test_async_object_unrefp) struct test_async_object *t = NULL;
        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *slot = NULL;
        int ifindex;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        assert_se(t = new(struct test_async_object, 1));
        *t = (struct test_async_object) {
                .n_ref = 1,
        };
        assert_se(t->ifname = strdup("lo"));

        /* destroy callback is called after processing message */
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call_async(rtnl, NULL, m, link_handler2, test_async_object_destroy, t, 0, NULL) >= 0);

        assert_se(t->n_ref == 1);
        assert_se(test_async_object_ref(t));
        assert_se(t->n_ref == 2);

        assert_se(sd_netlink_wait(rtnl, 0) >= 0);
        assert_se(sd_netlink_process(rtnl, &reply) == 1);
        assert_se(t->n_ref == 1);

        assert_se(!sd_netlink_message_unref(m));

        /* destroy callback is called when asynchronous call is cancelled, that is, slot is freed. */
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call_async(rtnl, &slot, m, link_handler2, test_async_object_destroy, t, 0, NULL) >= 0);

        assert_se(t->n_ref == 1);
        assert_se(test_async_object_ref(t));
        assert_se(t->n_ref == 2);

        assert_se(!(slot = sd_netlink_slot_unref(slot)));
        assert_se(t->n_ref == 1);

        assert_se(!sd_netlink_message_unref(m));

        /* destroy callback is also called by sd_netlink_unref() */
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_netlink_call_async(rtnl, NULL, m, link_handler2, test_async_object_destroy, t, 0, NULL) >= 0);

        assert_se(t->n_ref == 1);
        assert_se(test_async_object_ref(t));
        assert_se(t->n_ref == 2);

        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);
        assert_se(t->n_ref == 1);
}

static int pipe_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        int *counter = userdata;
        int r;

        (*counter)--;

        r = sd_netlink_message_get_errno(m);

        log_info_errno(r, "%d left in pipe. got reply: %m", *counter);

        assert_se(r >= 0);

        return 1;
}

TEST(pipe) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m1 = NULL, *m2 = NULL;
        int ifindex, counter = 0;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        ifindex = (int) if_nametoindex("lo");

        assert_se(sd_rtnl_message_new_link(rtnl, &m1, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_rtnl_message_new_link(rtnl, &m2, RTM_GETLINK, ifindex) >= 0);

        counter++;
        assert_se(sd_netlink_call_async(rtnl, NULL, m1, pipe_handler, NULL, &counter, 0, NULL) >= 0);

        counter++;
        assert_se(sd_netlink_call_async(rtnl, NULL, m2, pipe_handler, NULL, &counter, 0, NULL) >= 0);

        while (counter > 0) {
                assert_se(sd_netlink_wait(rtnl, 0) >= 0);
                assert_se(sd_netlink_process(rtnl, NULL) >= 0);
        }

        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);
}

TEST(message_container) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t u16_data;
        uint32_t u32_data;
        const char *string_data;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0) >= 0);

        assert_se(sd_netlink_message_open_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "vlan") >= 0);
        assert_se(sd_netlink_message_append_u16(m, IFLA_VLAN_ID, 100) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);

        assert_se(sd_netlink_message_rewind(m, rtnl) >= 0);

        assert_se(sd_netlink_message_enter_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_netlink_message_read_string(m, IFLA_INFO_KIND, &string_data) >= 0);
        assert_se(streq("vlan", string_data));

        assert_se(sd_netlink_message_enter_container(m, IFLA_INFO_DATA) >= 0);
        assert_se(sd_netlink_message_read_u16(m, IFLA_VLAN_ID, &u16_data) >= 0);
        assert_se(sd_netlink_message_exit_container(m) >= 0);

        assert_se(sd_netlink_message_read_string(m, IFLA_INFO_KIND, &string_data) >= 0);
        assert_se(streq("vlan", string_data));
        assert_se(sd_netlink_message_exit_container(m) >= 0);

        assert_se(sd_netlink_message_read_u32(m, IFLA_LINKINFO, &u32_data) < 0);
}

TEST(sd_netlink_add_match) {
        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *s1 = NULL, *s2 = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_netlink_add_match(rtnl, &s1, RTM_NEWLINK, link_handler, NULL, NULL, NULL) >= 0);
        assert_se(sd_netlink_add_match(rtnl, &s2, RTM_NEWLINK, link_handler, NULL, NULL, NULL) >= 0);
        assert_se(sd_netlink_add_match(rtnl, NULL, RTM_NEWLINK, link_handler, NULL, NULL, NULL) >= 0);

        assert_se(!(s1 = sd_netlink_slot_unref(s1)));
        assert_se(!(s2 = sd_netlink_slot_unref(s2)));

        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);
}

TEST(dump_addresses) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC) >= 0);
        assert_se(sd_netlink_message_set_request_dump(req, true) >= 0);
        assert_se(sd_netlink_call(rtnl, req, 0, &reply) >= 0);

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                uint16_t type;
                unsigned char scope, flags;
                int family, ifindex;

                assert_se(sd_netlink_message_get_type(m, &type) >= 0);
                assert_se(type == RTM_NEWADDR);

                assert_se(sd_rtnl_message_addr_get_ifindex(m, &ifindex) >= 0);
                assert_se(sd_rtnl_message_addr_get_family(m, &family) >= 0);
                assert_se(sd_rtnl_message_addr_get_scope(m, &scope) >= 0);
                assert_se(sd_rtnl_message_addr_get_flags(m, &flags) >= 0);

                assert_se(ifindex > 0);
                assert_se(IN_SET(family, AF_INET, AF_INET6));

                log_info("got IPv%i address on ifindex %i", family == AF_INET ? 4 : 6, ifindex);
        }
}

TEST(sd_netlink_message_get_errno) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(message_new_synthetic_error(rtnl, -ETIMEDOUT, 1, &m) >= 0);
        assert_se(sd_netlink_message_get_errno(m) == -ETIMEDOUT);
}

TEST(message_array) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *genl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        assert_se(sd_genl_socket_open(&genl) >= 0);
        assert_se(sd_genl_message_new(genl, CTRL_GENL_NAME, CTRL_CMD_GETFAMILY, &m) >= 0);

        assert_se(sd_netlink_message_open_container(m, CTRL_ATTR_MCAST_GROUPS) >= 0);
        for (unsigned i = 0; i < 10; i++) {
                char name[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];
                uint32_t id = i + 1000;

                xsprintf(name, "hoge%" PRIu32, id);
                assert_se(sd_netlink_message_open_array(m, i + 1) >= 0);
                assert_se(sd_netlink_message_append_u32(m, CTRL_ATTR_MCAST_GRP_ID, id) >= 0);
                assert_se(sd_netlink_message_append_string(m, CTRL_ATTR_MCAST_GRP_NAME, name) >= 0);
                assert_se(sd_netlink_message_close_container(m) >= 0);
        }
        assert_se(sd_netlink_message_close_container(m) >= 0);

        message_seal(m);
        assert_se(sd_netlink_message_rewind(m, genl) >= 0);

        assert_se(sd_netlink_message_enter_container(m, CTRL_ATTR_MCAST_GROUPS) >= 0);
        for (unsigned i = 0; i < 10; i++) {
                char expected[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];
                const char *name;
                uint32_t id;

                assert_se(sd_netlink_message_enter_array(m, i + 1) >= 0);
                assert_se(sd_netlink_message_read_u32(m, CTRL_ATTR_MCAST_GRP_ID, &id) >= 0);
                assert_se(sd_netlink_message_read_string(m, CTRL_ATTR_MCAST_GRP_NAME, &name) >= 0);
                assert_se(sd_netlink_message_exit_container(m) >= 0);

                assert_se(id == i + 1000);
                xsprintf(expected, "hoge%" PRIu32, id);
                assert_se(streq(name, expected));
        }
        assert_se(sd_netlink_message_exit_container(m) >= 0);
}

TEST(message_strv) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        _cleanup_strv_free_ char **names_in = NULL, **names_out;
        const char *p;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINKPROP, 1) >= 0);

        for (unsigned i = 0; i < 10; i++) {
                char name[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];

                xsprintf(name, "hoge%" PRIu32, i + 1000);
                assert_se(strv_extend(&names_in, name) >= 0);
        }

        assert_se(sd_netlink_message_open_container(m, IFLA_PROP_LIST) >= 0);
        assert_se(sd_netlink_message_append_strv(m, IFLA_ALT_IFNAME, (const char**) names_in) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);

        message_seal(m);
        assert_se(sd_netlink_message_rewind(m, rtnl) >= 0);

        assert_se(sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &names_out) >= 0);
        assert_se(strv_equal(names_in, names_out));

        assert_se(sd_netlink_message_enter_container(m, IFLA_PROP_LIST) >= 0);
        assert_se(sd_netlink_message_read_string(m, IFLA_ALT_IFNAME, &p) >= 0);
        assert_se(streq(p, "hoge1009"));
        assert_se(sd_netlink_message_exit_container(m) >= 0);
}

static int genl_ctrl_match_callback(sd_netlink *genl, sd_netlink_message *m, void *userdata) {
        const char *name;
        uint16_t id;
        uint8_t cmd;

        assert_se(genl);
        assert_se(m);

        assert_se(sd_genl_message_get_family_name(genl, m, &name) >= 0);
        assert_se(streq(name, CTRL_GENL_NAME));

        assert_se(sd_genl_message_get_command(genl, m, &cmd) >= 0);

        switch (cmd) {
        case CTRL_CMD_NEWFAMILY:
        case CTRL_CMD_DELFAMILY:
                assert_se(sd_netlink_message_read_string(m, CTRL_ATTR_FAMILY_NAME, &name) >= 0);
                assert_se(sd_netlink_message_read_u16(m, CTRL_ATTR_FAMILY_ID, &id) >= 0);
                log_debug("%s: %s (id=%"PRIu16") family is %s.",
                          __func__, name, id, cmd == CTRL_CMD_NEWFAMILY ? "added" : "removed");
                break;
        case CTRL_CMD_NEWMCAST_GRP:
        case CTRL_CMD_DELMCAST_GRP:
                assert_se(sd_netlink_message_read_string(m, CTRL_ATTR_FAMILY_NAME, &name) >= 0);
                assert_se(sd_netlink_message_read_u16(m, CTRL_ATTR_FAMILY_ID, &id) >= 0);
                log_debug("%s: multicast group for %s (id=%"PRIu16") family is %s.",
                          __func__, name, id, cmd == CTRL_CMD_NEWMCAST_GRP ? "added" : "removed");
                break;
        default:
                log_debug("%s: received nlctrl message with unknown command '%"PRIu8"'.", __func__, cmd);
        }

        return 0;
}

TEST(genl) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *genl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const char *name;
        uint8_t cmd;
        int r;

        assert_se(sd_genl_socket_open(&genl) >= 0);
        assert_se(sd_event_default(&event) >= 0);
        assert_se(sd_netlink_attach_event(genl, event, 0) >= 0);

        assert_se(sd_genl_message_new(genl, CTRL_GENL_NAME, CTRL_CMD_GETFAMILY, &m) >= 0);
        assert_se(sd_genl_message_get_family_name(genl, m, &name) >= 0);
        assert_se(streq(name, CTRL_GENL_NAME));
        assert_se(sd_genl_message_get_command(genl, m, &cmd) >= 0);
        assert_se(cmd == CTRL_CMD_GETFAMILY);

        assert_se(sd_genl_add_match(genl, NULL, CTRL_GENL_NAME, "notify", 0, genl_ctrl_match_callback, NULL, NULL, "genl-ctrl-notify") >= 0);

        m = sd_netlink_message_unref(m);
        assert_se(sd_genl_message_new(genl, "should-not-exist", CTRL_CMD_GETFAMILY, &m) < 0);
        assert_se(sd_genl_message_new(genl, "should-not-exist", CTRL_CMD_GETFAMILY, &m) == -EOPNOTSUPP);

        /* These families may not be supported by kernel. Hence, ignore results. */
        (void) sd_genl_message_new(genl, FOU_GENL_NAME, 0, &m);
        m = sd_netlink_message_unref(m);
        (void) sd_genl_message_new(genl, L2TP_GENL_NAME, 0, &m);
        m = sd_netlink_message_unref(m);
        (void) sd_genl_message_new(genl, MACSEC_GENL_NAME, 0, &m);
        m = sd_netlink_message_unref(m);
        (void) sd_genl_message_new(genl, NL80211_GENL_NAME, 0, &m);
        m = sd_netlink_message_unref(m);
        (void) sd_genl_message_new(genl, NETLBL_NLTYPE_UNLABELED_NAME, 0, &m);

        for (;;) {
                r = sd_event_run(event, 500 * USEC_PER_MSEC);
                assert_se(r >= 0);
                if (r == 0)
                        return;
        }
}

static void remove_dummy_interfacep(int *ifindex) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;

        if (!ifindex || *ifindex <= 0)
                return;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, *ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) == 1);
}

TEST(rtnl_set_link_name) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        _cleanup_(remove_dummy_interfacep) int ifindex = 0;
        _cleanup_strv_free_ char **alternative_names = NULL;
        int r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-netlink") >= 0);
        assert_se(sd_netlink_message_open_container(message, IFLA_LINKINFO) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy") >= 0);
        r = sd_netlink_call(rtnl, message, 0, &reply);
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("dummy network interface is not supported");
        assert_se(r >= 0);

        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-netlink") >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, &reply) == 1);

        assert_se(sd_rtnl_message_link_get_ifindex(reply, &ifindex) >= 0);
        assert_se(ifindex > 0);

        /* Test that the new name (which is currently an alternative name) is
         * restored as an alternative name on error. Create an error by using
         * an invalid device name, namely one that exceeds IFNAMSIZ
         * (alternative names can exceed IFNAMSIZ, but not regular names). */
        r = rtnl_set_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename", "test-shortname"));
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("alternative name is not supported");
        assert_se(r >= 0);

        assert_se(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names) >= 0);
        assert_se(strv_contains(alternative_names, "testlongalternativename"));
        assert_se(strv_contains(alternative_names, "test-shortname"));

        assert_se(rtnl_set_link_name(&rtnl, ifindex, "testlongalternativename", NULL) == -EINVAL);
        assert_se(rtnl_set_link_name(&rtnl, ifindex, "test-shortname", STRV_MAKE("testlongalternativename", "test-shortname", "test-additional-name")) >= 0);

        alternative_names = strv_free(alternative_names);
        assert_se(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names) >= 0);
        assert_se(strv_contains(alternative_names, "testlongalternativename"));
        assert_se(strv_contains(alternative_names, "test-additional-name"));
        assert_se(!strv_contains(alternative_names, "test-shortname"));

        assert_se(rtnl_delete_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename")) >= 0);

        alternative_names = strv_free(alternative_names);
        assert_se(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names) >= 0);
        assert_se(!strv_contains(alternative_names, "testlongalternativename"));
        assert_se(strv_contains(alternative_names, "test-additional-name"));
        assert_se(!strv_contains(alternative_names, "test-shortname"));

        _cleanup_free_ char *resolved = NULL;
        assert_se(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", &resolved) == ifindex);
        assert_se(streq_ptr(resolved, "test-shortname"));
        resolved = mfree(resolved);

        assert_se(rtnl_rename_link(&rtnl, "test-shortname", "test-shortname") >= 0);
        assert_se(rtnl_rename_link(&rtnl, "test-shortname", "test-shortname2") >= 0);
        assert_se(rtnl_rename_link(NULL, "test-shortname2", "test-shortname3") >= 0);

        assert_se(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", &resolved) == ifindex);
        assert_se(streq_ptr(resolved, "test-shortname3"));
        resolved = mfree(resolved);

        assert_se(rtnl_resolve_link_alternative_name(&rtnl, "test-shortname3", &resolved) == ifindex);
        assert_se(streq_ptr(resolved, "test-shortname3"));
        resolved = mfree(resolved);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

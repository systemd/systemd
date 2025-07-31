/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fou.h>
#include <linux/genetlink.h>
#include <linux/if_macsec.h>
#include <linux/l2tp.h>
#include <linux/nl80211.h>
#include <linux/unix_diag.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "missing-network.h"
#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-sock-diag.h"
#include "netlink-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(message_newlink_bridge) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        uint32_t cost;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 1));
        ASSERT_OK(sd_rtnl_message_link_set_family(message, AF_BRIDGE));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_PROTINFO));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFLA_BRPORT_COST, 10));
        ASSERT_OK(sd_netlink_message_close_container(message));

        ASSERT_OK(sd_netlink_message_rewind(message, rtnl));

        ASSERT_OK(sd_netlink_message_enter_container(message, IFLA_PROTINFO));
        ASSERT_OK(sd_netlink_message_read_u32(message, IFLA_BRPORT_COST, &cost));
        ASSERT_EQ(cost, 10U);
        ASSERT_OK(sd_netlink_message_exit_container(message));
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

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, ifindex));
        ASSERT_OK_EQ(sd_netlink_call(rtnl, message, 0, &reply), 1);

        /* u8 */
        ASSERT_OK(sd_netlink_message_read_u8(reply, IFLA_CARRIER, &u8_data));
        ASSERT_OK(sd_netlink_message_read_u8(reply, IFLA_OPERSTATE, &u8_data));
        ASSERT_OK(sd_netlink_message_read_u8(reply, IFLA_LINKMODE, &u8_data));

        /* u16 */
        ASSERT_OK(sd_netlink_message_get_type(reply, &u16_data));
        ASSERT_EQ(u16_data, RTM_NEWLINK);

        /* u32 */
        ASSERT_OK(sd_netlink_message_read_u32(reply, IFLA_MTU, &u32_data));
        ASSERT_OK(sd_netlink_message_read_u32(reply, IFLA_GROUP, &u32_data));
        ASSERT_OK(sd_netlink_message_read_u32(reply, IFLA_TXQLEN, &u32_data));
        ASSERT_OK(sd_netlink_message_read_u32(reply, IFLA_NUM_TX_QUEUES, &u32_data));

        /* string */
        ASSERT_OK(sd_netlink_message_read_string(reply, IFLA_IFNAME, &str_data));

        /* ether_addr */
        ASSERT_OK(sd_netlink_message_read_ether_addr(reply, IFLA_ADDRESS, &eth_data));
}

TEST(message_address) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        int ifindex;
        struct in_addr in_data;
        struct ifa_cacheinfo cache;
        const char *label;
        int r;

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        ASSERT_OK(sd_rtnl_message_new_addr(rtnl, &message, RTM_GETADDR, ifindex, AF_INET));
        ASSERT_OK(sd_netlink_message_set_request_dump(message, true));

        ASSERT_OK(r = sd_netlink_call(rtnl, message, 0, &reply));

        /* If the loopback device is down we won't get any results. */
        if (r > 0) {
                ASSERT_OK(sd_netlink_message_read_in_addr(reply, IFA_LOCAL, &in_data));
                ASSERT_OK(sd_netlink_message_read_in_addr(reply, IFA_ADDRESS, &in_data));
                ASSERT_OK(sd_netlink_message_read_string(reply, IFA_LABEL, &label));
                ASSERT_OK(sd_netlink_message_read_cache_info(reply, IFA_CACHEINFO, &cache));
        }
}

TEST(message_route) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        struct in_addr addr, addr_data;
        uint32_t index = 2, u32_data;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &req, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));

        addr.s_addr = htobe32(INADDR_LOOPBACK);

        ASSERT_OK(sd_netlink_message_append_in_addr(req, RTA_GATEWAY, &addr));
        ASSERT_OK(sd_netlink_message_append_u32(req, RTA_OIF, index));

        ASSERT_OK(sd_netlink_message_rewind(req, rtnl));

        ASSERT_OK(sd_netlink_message_read_in_addr(req, RTA_GATEWAY, &addr_data));
        ASSERT_EQ(addr_data.s_addr, addr.s_addr);

        ASSERT_OK(sd_netlink_message_read_u32(req, RTA_OIF, &u32_data));
        ASSERT_EQ(u32_data, index);

        ASSERT_NULL(req = sd_netlink_message_unref(req));
}

static int link_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        const char *data;

        ASSERT_NOT_NULL(rtnl);
        ASSERT_NOT_NULL(m);

        ASSERT_STREQ(userdata, "foo");

        ASSERT_OK(sd_netlink_message_read_string(m, IFLA_IFNAME, &data));
        ASSERT_STREQ(data, "lo");

        log_info("%s: got link info about %s", __func__, data);
        return 1;
}

TEST(netlink_event_loop) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        _cleanup_free_ char *userdata = NULL;
        int ifindex;

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        ASSERT_NOT_NULL((userdata = strdup("foo")));

        ASSERT_OK(sd_event_default(&event));
        ASSERT_OK(sd_netlink_attach_event(rtnl, event, 0));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_netlink_call_async(rtnl, NULL, m, link_handler, NULL, userdata, 0, NULL));

        ASSERT_OK(sd_event_run(event, 0));

        ASSERT_OK(sd_netlink_detach_event(rtnl));
        ASSERT_NULL(rtnl = sd_netlink_unref(rtnl));
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

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        ASSERT_NOT_NULL((userdata = strdup("foo")));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_netlink_call_async(rtnl, &slot, m, link_handler, test_async_destroy, userdata, 0, "hogehoge"));

        ASSERT_PTR_EQ(sd_netlink_slot_get_netlink(slot), rtnl);

        ASSERT_PTR_EQ(sd_netlink_slot_get_userdata(slot), userdata);
        ASSERT_PTR_EQ(sd_netlink_slot_set_userdata(slot, NULL), userdata);
        ASSERT_NULL(sd_netlink_slot_get_userdata(slot));
        ASSERT_NULL(sd_netlink_slot_set_userdata(slot, userdata));
        ASSERT_PTR_EQ(sd_netlink_slot_get_userdata(slot), userdata);

        ASSERT_OK_EQ(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback), 1);
        ASSERT_PTR_EQ(destroy_callback, test_async_destroy);
        ASSERT_OK(sd_netlink_slot_set_destroy_callback(slot, NULL));
        ASSERT_OK_ZERO(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback));
        ASSERT_NULL(destroy_callback);
        ASSERT_OK(sd_netlink_slot_set_destroy_callback(slot, test_async_destroy));
        ASSERT_OK_EQ(sd_netlink_slot_get_destroy_callback(slot, &destroy_callback), 1);
        ASSERT_PTR_EQ(destroy_callback, test_async_destroy);

        ASSERT_OK_ZERO(sd_netlink_slot_get_floating(slot));
        ASSERT_OK_EQ(sd_netlink_slot_set_floating(slot, 1), 1);
        ASSERT_OK_EQ(sd_netlink_slot_get_floating(slot), 1);

        ASSERT_OK_EQ(sd_netlink_slot_get_description(slot, &description), 1);
        ASSERT_STREQ(description, "hogehoge");
        ASSERT_OK(sd_netlink_slot_set_description(slot, NULL));
        ASSERT_OK_ZERO(sd_netlink_slot_get_description(slot, &description));
        ASSERT_NULL(description);

        ASSERT_OK(sd_netlink_wait(rtnl, 0));
        ASSERT_OK(sd_netlink_process(rtnl, &reply));

        ASSERT_NULL(rtnl = sd_netlink_unref(rtnl));
}

struct test_async_object {
        unsigned n_ref;
        char *ifname;
};

static struct test_async_object *test_async_object_free(struct test_async_object *t) {
        ASSERT_NOT_NULL(t);

        free(t->ifname);
        return mfree(t);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(struct test_async_object, test_async_object, test_async_object_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct test_async_object *, test_async_object_unref);

static int link_handler2(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        struct test_async_object *t = userdata;
        const char *data;

        ASSERT_NOT_NULL(rtnl);
        ASSERT_NOT_NULL(m);
        ASSERT_NOT_NULL(userdata);

        log_info("%s: got link info about %s", __func__, t->ifname);

        ASSERT_OK(sd_netlink_message_read_string(m, IFLA_IFNAME, &data));
        ASSERT_STREQ(data, "lo");

        return 1;
}

static void test_async_object_destroy(void *userdata) {
        struct test_async_object *t = userdata;

        ASSERT_NOT_NULL(userdata);

        log_info("%s: n_ref=%u", __func__, t->n_ref);
        test_async_object_unref(t);
}

TEST(async_destroy_callback) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_(test_async_object_unrefp) struct test_async_object *t = NULL;
        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *slot = NULL;
        int ifindex;

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        ASSERT_NOT_NULL((t = new(struct test_async_object, 1)));
        *t = (struct test_async_object) {
                .n_ref = 1,
        };
        ASSERT_NOT_NULL((t->ifname = strdup("lo")));

        /* destroy callback is called after processing message */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_netlink_call_async(rtnl, NULL, m, link_handler2, test_async_object_destroy, t, 0, NULL));

        ASSERT_EQ(t->n_ref, 1U);
        ASSERT_PTR_EQ(test_async_object_ref(t), t);
        ASSERT_EQ(t->n_ref, 2U);

        ASSERT_OK(sd_netlink_wait(rtnl, 0));
        ASSERT_OK_EQ(sd_netlink_process(rtnl, &reply), 1);
        ASSERT_EQ(t->n_ref, 1U);

        ASSERT_NULL(sd_netlink_message_unref(m));

        /* destroy callback is called when asynchronous call is cancelled, that is, slot is freed. */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_netlink_call_async(rtnl, &slot, m, link_handler2, test_async_object_destroy, t, 0, NULL));

        ASSERT_EQ(t->n_ref, 1U);
        ASSERT_PTR_EQ(test_async_object_ref(t), t);
        ASSERT_EQ(t->n_ref, 2U);

        ASSERT_NULL(slot = sd_netlink_slot_unref(slot));
        ASSERT_EQ(t->n_ref, 1U);

        ASSERT_NULL(sd_netlink_message_unref(m));

        /* destroy callback is also called by sd_netlink_unref() */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_netlink_call_async(rtnl, NULL, m, link_handler2, test_async_object_destroy, t, 0, NULL));

        ASSERT_EQ(t->n_ref, 1U);
        ASSERT_PTR_EQ(test_async_object_ref(t), t);
        ASSERT_EQ(t->n_ref, 2U);

        ASSERT_NULL(rtnl = sd_netlink_unref(rtnl));
        ASSERT_EQ(t->n_ref, 1U);
}

static int pipe_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        int r, *counter = userdata;

        (*counter)--;

        ASSERT_OK(r = sd_netlink_message_get_errno(m));
        log_info_errno(r, "%d left in pipe. got reply: %m", *counter);
        return 1;
}

TEST(pipe) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m1 = NULL, *m2 = NULL;
        int ifindex, counter = 0;

        ASSERT_OK(sd_netlink_open(&rtnl));
        ifindex = (int) if_nametoindex("lo");

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m1, RTM_GETLINK, ifindex));
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m2, RTM_GETLINK, ifindex));

        counter++;
        ASSERT_OK(sd_netlink_call_async(rtnl, NULL, m1, pipe_handler, NULL, &counter, 0, NULL));

        counter++;
        ASSERT_OK(sd_netlink_call_async(rtnl, NULL, m2, pipe_handler, NULL, &counter, 0, NULL));

        while (counter > 0) {
                ASSERT_OK(sd_netlink_wait(rtnl, 0));
                ASSERT_OK(sd_netlink_process(rtnl, NULL));
        }

        ASSERT_NULL(rtnl = sd_netlink_unref(rtnl));
}

TEST(message_container) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t u16_data;
        uint32_t u32_data;
        const char *string_data;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0));

        ASSERT_OK(sd_netlink_message_open_container(m, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "vlan"));
        ASSERT_OK(sd_netlink_message_append_u16(m, IFLA_VLAN_ID, 100));
        ASSERT_OK(sd_netlink_message_close_container(m));
        ASSERT_OK(sd_netlink_message_close_container(m));

        ASSERT_OK(sd_netlink_message_rewind(m, rtnl));

        ASSERT_OK(sd_netlink_message_enter_container(m, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_read_string(m, IFLA_INFO_KIND, &string_data));
        ASSERT_STREQ("vlan", string_data);

        ASSERT_OK(sd_netlink_message_enter_container(m, IFLA_INFO_DATA));
        ASSERT_OK(sd_netlink_message_read_u16(m, IFLA_VLAN_ID, &u16_data));
        ASSERT_OK(sd_netlink_message_exit_container(m));

        ASSERT_OK(sd_netlink_message_read_string(m, IFLA_INFO_KIND, &string_data));
        ASSERT_STREQ("vlan", string_data);
        ASSERT_OK(sd_netlink_message_exit_container(m));

        ASSERT_FAIL(sd_netlink_message_read_u32(m, IFLA_LINKINFO, &u32_data));
}

TEST(sd_netlink_add_match) {
        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *s1 = NULL, *s2 = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_netlink_add_match(rtnl, &s1, RTM_NEWLINK, link_handler, NULL, NULL, NULL));
        ASSERT_OK(sd_netlink_add_match(rtnl, &s2, RTM_NEWLINK, link_handler, NULL, NULL, NULL));
        ASSERT_OK(sd_netlink_add_match(rtnl, NULL, RTM_NEWLINK, link_handler, NULL, NULL, NULL));

        ASSERT_NULL(s1 = sd_netlink_slot_unref(s1));
        ASSERT_NULL(s2 = sd_netlink_slot_unref(s2));

        ASSERT_NULL(rtnl = sd_netlink_unref(rtnl));
}

TEST(dump_addresses) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC));
        ASSERT_OK(sd_netlink_message_set_request_dump(req, true));
        ASSERT_OK(sd_netlink_call(rtnl, req, 0, &reply));

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                uint16_t type;
                unsigned char scope;
                int family, ifindex;
                uint32_t flags;

                ASSERT_OK(sd_netlink_message_get_type(m, &type));
                ASSERT_EQ(type, RTM_NEWADDR);

                ASSERT_OK(sd_rtnl_message_addr_get_ifindex(m, &ifindex));
                ASSERT_OK(sd_rtnl_message_addr_get_family(m, &family));
                ASSERT_OK(sd_rtnl_message_addr_get_scope(m, &scope));
                ASSERT_OK(sd_netlink_message_read_u32(m, IFA_FLAGS, &flags));

                ASSERT_GT(ifindex, 0);
                ASSERT_TRUE(IN_SET(family, AF_INET, AF_INET6));

                log_info("got IPv%i address on ifindex %i", family == AF_INET ? 4 : 6, ifindex);
        }
}

TEST(sd_netlink_message_get_errno) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(message_new_synthetic_error(rtnl, -ETIMEDOUT, 1, &m));
        ASSERT_ERROR(sd_netlink_message_get_errno(m), ETIMEDOUT);
}

TEST(message_array) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *genl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        ASSERT_OK(sd_genl_socket_open(&genl));
        ASSERT_OK(sd_genl_message_new(genl, CTRL_GENL_NAME, CTRL_CMD_GETFAMILY, &m));

        ASSERT_OK(sd_netlink_message_open_container(m, CTRL_ATTR_MCAST_GROUPS));
        for (unsigned i = 0; i < 10; i++) {
                char name[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];
                uint32_t id = i + 1000;

                xsprintf(name, "hoge%" PRIu32, id);
                ASSERT_OK(sd_netlink_message_open_array(m, i + 1));
                ASSERT_OK(sd_netlink_message_append_u32(m, CTRL_ATTR_MCAST_GRP_ID, id));
                ASSERT_OK(sd_netlink_message_append_string(m, CTRL_ATTR_MCAST_GRP_NAME, name));
                ASSERT_OK(sd_netlink_message_close_container(m));
        }
        ASSERT_OK(sd_netlink_message_close_container(m));

        message_seal(m);
        ASSERT_OK(sd_netlink_message_rewind(m, genl));

        ASSERT_OK(sd_netlink_message_enter_container(m, CTRL_ATTR_MCAST_GROUPS));
        for (unsigned i = 0; i < 10; i++) {
                char expected[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];
                const char *name;
                uint32_t id;

                ASSERT_OK(sd_netlink_message_enter_array(m, i + 1));
                ASSERT_OK(sd_netlink_message_read_u32(m, CTRL_ATTR_MCAST_GRP_ID, &id));
                ASSERT_OK(sd_netlink_message_read_string(m, CTRL_ATTR_MCAST_GRP_NAME, &name));
                ASSERT_OK(sd_netlink_message_exit_container(m));

                ASSERT_EQ(id, i + 1000);
                xsprintf(expected, "hoge%" PRIu32, id);
                ASSERT_STREQ(name, expected);
        }
        ASSERT_OK(sd_netlink_message_exit_container(m));
}

TEST(message_strv) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        _cleanup_strv_free_ char **names_in = NULL, **names_out;
        const char *p;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINKPROP, 1));

        for (unsigned i = 0; i < 10; i++) {
                char name[STRLEN("hoge") + DECIMAL_STR_MAX(uint32_t)];

                xsprintf(name, "hoge%" PRIu32, i + 1000);
                ASSERT_OK(strv_extend(&names_in, name));
        }

        ASSERT_OK(sd_netlink_message_open_container(m, IFLA_PROP_LIST));
        ASSERT_OK(sd_netlink_message_append_strv(m, IFLA_ALT_IFNAME, (const char**) names_in));
        ASSERT_OK(sd_netlink_message_close_container(m));

        message_seal(m);
        ASSERT_OK(sd_netlink_message_rewind(m, rtnl));

        ASSERT_OK(sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &names_out));
        ASSERT_TRUE(strv_equal(names_in, names_out));

        ASSERT_OK(sd_netlink_message_enter_container(m, IFLA_PROP_LIST));
        ASSERT_OK(sd_netlink_message_read_string(m, IFLA_ALT_IFNAME, &p));
        ASSERT_STREQ(p, "hoge1009");
        ASSERT_OK(sd_netlink_message_exit_container(m));
}

static int genl_ctrl_match_callback(sd_netlink *genl, sd_netlink_message *m, void *userdata) {
        const char *name;
        uint16_t id;
        uint8_t cmd;

        ASSERT_NOT_NULL(genl);
        ASSERT_NOT_NULL(m);

        ASSERT_OK(sd_genl_message_get_family_name(genl, m, &name));
        ASSERT_STREQ(name, CTRL_GENL_NAME);

        ASSERT_OK(sd_genl_message_get_command(genl, m, &cmd));

        switch (cmd) {
        case CTRL_CMD_NEWFAMILY:
        case CTRL_CMD_DELFAMILY:
                ASSERT_OK(sd_netlink_message_read_string(m, CTRL_ATTR_FAMILY_NAME, &name));
                ASSERT_OK(sd_netlink_message_read_u16(m, CTRL_ATTR_FAMILY_ID, &id));
                log_debug("%s: %s (id=%"PRIu16") family is %s.",
                          __func__, name, id, cmd == CTRL_CMD_NEWFAMILY ? "added" : "removed");
                break;
        case CTRL_CMD_NEWMCAST_GRP:
        case CTRL_CMD_DELMCAST_GRP:
                ASSERT_OK(sd_netlink_message_read_string(m, CTRL_ATTR_FAMILY_NAME, &name));
                ASSERT_OK(sd_netlink_message_read_u16(m, CTRL_ATTR_FAMILY_ID, &id));
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

        ASSERT_OK(sd_genl_socket_open(&genl));
        ASSERT_OK(sd_event_default(&event));
        ASSERT_OK(sd_netlink_attach_event(genl, event, 0));

        ASSERT_OK(sd_genl_message_new(genl, CTRL_GENL_NAME, CTRL_CMD_GETFAMILY, &m));
        ASSERT_OK(sd_genl_message_get_family_name(genl, m, &name));
        ASSERT_STREQ(name, CTRL_GENL_NAME);
        ASSERT_OK(sd_genl_message_get_command(genl, m, &cmd));
        ASSERT_EQ(cmd, CTRL_CMD_GETFAMILY);

        ASSERT_OK(sd_genl_add_match(genl, NULL, CTRL_GENL_NAME, "notify", 0, genl_ctrl_match_callback, NULL, NULL, "genl-ctrl-notify"));

        ASSERT_NULL(m = sd_netlink_message_unref(m));
        ASSERT_FAIL(sd_genl_message_new(genl, "should-not-exist", CTRL_CMD_GETFAMILY, &m));
        ASSERT_ERROR(sd_genl_message_new(genl, "should-not-exist", CTRL_CMD_GETFAMILY, &m), EOPNOTSUPP);

        /* These families may not be supported by kernel. Hence, ignore results. */
        (void) sd_genl_message_new(genl, FOU_GENL_NAME, 0, &m);
        ASSERT_NULL(m = sd_netlink_message_unref(m));
        (void) sd_genl_message_new(genl, L2TP_GENL_NAME, 0, &m);
        ASSERT_NULL(m = sd_netlink_message_unref(m));
        (void) sd_genl_message_new(genl, MACSEC_GENL_NAME, 0, &m);
        ASSERT_NULL(m = sd_netlink_message_unref(m));
        (void) sd_genl_message_new(genl, NL80211_GENL_NAME, 0, &m);
        ASSERT_NULL(m = sd_netlink_message_unref(m));
        (void) sd_genl_message_new(genl, NETLBL_NLTYPE_UNLABELED_NAME, 0, &m);

        for (;;) {
                ASSERT_OK(r = sd_event_run(event, 500 * USEC_PER_MSEC));
                if (r == 0)
                        return;
        }
}

static void remove_dummy_interfacep(int *ifindex) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;

        if (!ifindex || *ifindex <= 0)
                return;

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, *ifindex));
        ASSERT_OK_EQ(sd_netlink_call(rtnl, message, 0, NULL), 1);
}

TEST(rtnl_set_link_name) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        _cleanup_(remove_dummy_interfacep) int ifindex = 0;
        _cleanup_strv_free_ char **alternative_names = NULL;
        int r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        ASSERT_OK(sd_netlink_open(&rtnl));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-netlink"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy"));
        r = sd_netlink_call(rtnl, message, 0, &reply);
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("dummy network interface is not supported");
        ASSERT_OK(r);

        ASSERT_NULL(message = sd_netlink_message_unref(message));
        ASSERT_NULL(reply = sd_netlink_message_unref(reply));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-netlink"));
        ASSERT_OK_EQ(sd_netlink_call(rtnl, message, 0, &reply), 1);

        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &ifindex));
        ASSERT_GT(ifindex, 0);

        /* Test that the new name (which is currently an alternative name) is
         * restored as an alternative name on error. Create an error by using
         * an invalid device name, namely one that exceeds IFNAMSIZ
         * (alternative names can exceed IFNAMSIZ, but not regular names). */
        r = rtnl_set_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename", "test-shortname"));
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("alternative name is not supported");
        ASSERT_OK(r);

        ASSERT_OK(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names));
        ASSERT_TRUE(strv_contains(alternative_names, "testlongalternativename"));
        ASSERT_TRUE(strv_contains(alternative_names, "test-shortname"));

        ASSERT_ERROR(rtnl_set_link_name(&rtnl, ifindex, "testlongalternativename", NULL), EINVAL);
        ASSERT_OK(rtnl_set_link_name(&rtnl, ifindex, "test-shortname", STRV_MAKE("testlongalternativename", "test-shortname", "test-additional-name")));

        ASSERT_NULL(alternative_names = strv_free(alternative_names));
        ASSERT_OK(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names));
        ASSERT_TRUE(strv_contains(alternative_names, "testlongalternativename"));
        ASSERT_TRUE(strv_contains(alternative_names, "test-additional-name"));
        ASSERT_FALSE(strv_contains(alternative_names, "test-shortname"));

        ASSERT_OK(rtnl_delete_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename")));

        ASSERT_NULL(alternative_names = strv_free(alternative_names));
        ASSERT_OK_EQ(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names), ifindex);
        ASSERT_FALSE(strv_contains(alternative_names, "testlongalternativename"));
        ASSERT_TRUE(strv_contains(alternative_names, "test-additional-name"));
        ASSERT_FALSE(strv_contains(alternative_names, "test-shortname"));

        _cleanup_free_ char *resolved = NULL;
        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", NULL), ifindex);
        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", &resolved), ifindex);
        ASSERT_STREQ(resolved, "test-shortname");
        ASSERT_NULL(resolved = mfree(resolved));

        ASSERT_OK(rtnl_rename_link(&rtnl, "test-shortname", "test-shortname"));
        ASSERT_OK(rtnl_rename_link(&rtnl, "test-shortname", "test-shortname2"));
        ASSERT_OK(rtnl_rename_link(NULL, "test-shortname2", "test-shortname3"));

        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", NULL), ifindex);
        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-additional-name", &resolved), ifindex);
        ASSERT_STREQ(resolved, "test-shortname3");
        ASSERT_NULL(resolved = mfree(resolved));

        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-shortname3", NULL), ifindex);
        ASSERT_OK_EQ(rtnl_resolve_link_alternative_name(&rtnl, "test-shortname3", &resolved), ifindex);
        ASSERT_STREQ(resolved, "test-shortname3");
        ASSERT_NULL(resolved = mfree(resolved));
}

TEST(sock_diag_unix) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        int r;

        ASSERT_OK(sd_sock_diag_socket_open(&nl));

        _cleanup_close_ int unix_fd = ASSERT_FD(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        ASSERT_OK(socket_autobind(unix_fd, /* ret_name= */ NULL));
        ASSERT_OK_ERRNO(listen(unix_fd, 123));

        struct stat st;
        ASSERT_OK_ERRNO(fstat(unix_fd, &st));

        uint64_t cookie;
        ASSERT_OK(socket_get_cookie(unix_fd, &cookie));

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        ASSERT_OK(sd_sock_diag_message_new_unix(nl, &message, st.st_ino, cookie, UDIAG_SHOW_RQLEN));

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        r = sd_netlink_call(nl, message, /* timeout= */ 0, &reply);
        if (r == -ENOENT)
                return (void) log_tests_skipped("CONFIG_UNIX_DIAG disabled");
        ASSERT_OK(r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

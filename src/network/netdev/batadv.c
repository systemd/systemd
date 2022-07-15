/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <inttypes.h>
#include <netinet/in.h>
#include <linux/genetlink.h>
#include <linux/if_arp.h>

#include "batadv.h"
#include "fileio.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"

static void batadv_init(NetDev *n) {
        BatmanAdvanced *b;

        b = BATADV(n);

        /* Set defaults */
        b->aggregation            = true;
        b->gateway_bandwidth_down = 10000;
        b->gateway_bandwidth_up   = 2000;
        b->bridge_loop_avoidance  = true;
        b->distributed_arp_table  = true;
        b->fragmentation          = true;
        b->hop_penalty            = 15;
        b->originator_interval    = 1000;
        b->routing_algorithm      = BATADV_ROUTING_ALGORITHM_BATMAN_V;
}

static const char* const batadv_gateway_mode_table[_BATADV_GATEWAY_MODE_MAX] = {
        [BATADV_GATEWAY_MODE_OFF]    = "off",
        [BATADV_GATEWAY_MODE_CLIENT] = "client",
        [BATADV_GATEWAY_MODE_SERVER] = "server",
};

static const char* const batadv_routing_algorithm_table[_BATADV_ROUTING_ALGORITHM_MAX] = {
        [BATADV_ROUTING_ALGORITHM_BATMAN_V]  = "batman-v",
        [BATADV_ROUTING_ALGORITHM_BATMAN_IV] = "batman-iv",
};

static const char* const batadv_routing_algorithm_kernel_table[_BATADV_ROUTING_ALGORITHM_MAX] = {
        [BATADV_ROUTING_ALGORITHM_BATMAN_V]  = "BATMAN_V",
        [BATADV_ROUTING_ALGORITHM_BATMAN_IV] = "BATMAN_IV",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(batadv_gateway_mode, BatadvGatewayModes);
DEFINE_CONFIG_PARSE_ENUM(config_parse_batadv_gateway_mode, batadv_gateway_mode, BatadvGatewayModes,
                         "Failed to parse GatewayMode=");

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(batadv_routing_algorithm, BatadvRoutingAlgorithm);
DEFINE_CONFIG_PARSE_ENUM(config_parse_batadv_routing_algorithm, batadv_routing_algorithm, BatadvRoutingAlgorithm,
                         "Failed to parse RoutingAlgorithm=");

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(batadv_routing_algorithm_kernel, BatadvRoutingAlgorithm);

int config_parse_badadv_bandwidth (
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t k;
        uint32_t *bandwidth = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_size(rvalue, 1000, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (k/1000/100 > UINT32_MAX)
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "The value of '%s=', is outside of 0...429496729500000 range: %s",
                           lvalue, rvalue);

        *bandwidth = k/1000/100;

        return 0;
}

/* callback for batman netdev's parameter set */
static int netdev_batman_set_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(m);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_netdev_warning_errno(netdev, r, "BATADV parameters could not be set: %m");
                return 1;
        }

        log_netdev_debug(netdev, "BATADV parameters set success");

        return 1;
}

static int netdev_batadv_post_create_message(NetDev *netdev, sd_netlink_message *message) {
        BatmanAdvanced *b;
        int r;

        assert_se(b = BATADV(netdev));

        r = sd_netlink_message_append_u32(message, BATADV_ATTR_MESH_IFINDEX, netdev->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_GW_MODE, b->gateway_mode);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_AGGREGATED_OGMS_ENABLED, b->aggregation);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED, b->bridge_loop_avoidance);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED, b->distributed_arp_table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_FRAGMENTATION_ENABLED, b->fragmentation);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, BATADV_ATTR_HOP_PENALTY, b->hop_penalty);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(message, BATADV_ATTR_ORIG_INTERVAL, DIV_ROUND_UP(b->originator_interval, USEC_PER_MSEC));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(message, BATADV_ATTR_GW_BANDWIDTH_DOWN, b->gateway_bandwidth_down);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(message, BATADV_ATTR_GW_BANDWIDTH_UP, b->gateway_bandwidth_up);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_batadv_post_create(NetDev *netdev, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int r;

        assert(netdev);

        r = sd_genl_message_new(netdev->manager->genl, BATADV_NL_NAME, BATADV_CMD_SET_MESH, &message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate netlink message: %m");

        r = netdev_batadv_post_create_message(netdev, message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not create netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, message, netdev_batman_set_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send netlink message: %m");

        netdev_ref(netdev);

        return r;
}

static int netdev_batadv_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        BatmanAdvanced *b;
        int r;

        assert(netdev);
        assert(m);

        b = BATADV(netdev);
        assert(b);

        r = sd_netlink_message_append_string(m, IFLA_BATADV_ALGO_NAME, batadv_routing_algorithm_kernel_to_string(b->routing_algorithm));
        if (r < 0)
                return r;

        return 0;
}

const NetDevVTable batadv_vtable = {
        .object_size = sizeof(BatmanAdvanced),
        .init = batadv_init,
        .sections = NETDEV_COMMON_SECTIONS "BatmanAdvanced\0",
        .fill_message_create = netdev_batadv_fill_message_create,
        .post_create = netdev_batadv_post_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};

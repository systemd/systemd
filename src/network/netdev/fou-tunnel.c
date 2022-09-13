/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fou.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ip.h>

#include "conf-parser.h"
#include "fou-tunnel.h"
#include "ip-protocol-list.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static const char* const fou_encap_type_table[_NETDEV_FOO_OVER_UDP_ENCAP_MAX] = {
        [NETDEV_FOO_OVER_UDP_ENCAP_DIRECT] = "FooOverUDP",
        [NETDEV_FOO_OVER_UDP_ENCAP_GUE] = "GenericUDPEncapsulation",
};

DEFINE_STRING_TABLE_LOOKUP(fou_encap_type, FooOverUDPEncapType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_fou_encap_type, fou_encap_type, FooOverUDPEncapType,
                         "Failed to parse Encapsulation=");

static int netdev_fill_fou_tunnel_message(NetDev *netdev, sd_netlink_message *m) {
        FouTunnel *t;
        uint8_t encap_type;
        int r;

        assert_se(t = FOU(netdev));

        r = sd_netlink_message_append_u16(m, FOU_ATTR_PORT, htobe16(t->port));
        if (r < 0)
                return r;

        if (IN_SET(t->peer_family, AF_INET, AF_INET6)) {
                r = sd_netlink_message_append_u16(m, FOU_ATTR_PEER_PORT, htobe16(t->peer_port));
                if (r < 0)
                        return r;
        }

        switch (t->fou_encap_type) {
        case NETDEV_FOO_OVER_UDP_ENCAP_DIRECT:
                encap_type = FOU_ENCAP_DIRECT;
                break;
        case NETDEV_FOO_OVER_UDP_ENCAP_GUE:
                encap_type = FOU_ENCAP_GUE;
                break;
        default:
                assert_not_reached();
        }

        r = sd_netlink_message_append_u8(m, FOU_ATTR_TYPE, encap_type);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, FOU_ATTR_AF, AF_INET);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, FOU_ATTR_IPPROTO, t->fou_protocol);
        if (r < 0)
                return r;

        if (t->local_family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, FOU_ATTR_LOCAL_V4, &t->local.in);
                if (r < 0)
                        return r;
        } else if (t->local_family == AF_INET6) {
                r = sd_netlink_message_append_in6_addr(m, FOU_ATTR_LOCAL_V6, &t->local.in6);
                if (r < 0)
                        return r;
        }

        if (t->peer_family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, FOU_ATTR_PEER_V4, &t->peer.in);
                if (r < 0)
                        return r;
        } else if (t->peer_family == AF_INET6){
                r = sd_netlink_message_append_in6_addr(m, FOU_ATTR_PEER_V6, &t->peer.in6);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netdev_create_fou_tunnel_message(NetDev *netdev, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);

        r = sd_genl_message_new(netdev->manager->genl, FOU_GENL_NAME, FOU_CMD_ADD, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate netlink message: %m");

        r = netdev_fill_fou_tunnel_message(netdev, m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not create netlink message: %m");

        *ret = TAKE_PTR(m);
        return 0;
}

static int fou_tunnel_create_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "netdev exists, using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "netdev could not be created: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "FooOverUDP tunnel is created");
        return 1;
}

static int netdev_fou_tunnel_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(FOU(netdev));

        r = netdev_create_fou_tunnel_message(netdev, &m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, m, fou_tunnel_create_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create FooOverUDP tunnel: %m");

        netdev_ref(netdev);
        return 0;
}

int config_parse_ip_protocol(
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

        uint8_t *ret = ASSERT_PTR(data);
        unsigned protocol;
        /* linux/fou.h defines the netlink field as one byte, so we need to reject protocols numbers that
         * don't fit in one byte. */
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = parse_ip_protocol(rvalue);
        if (r >= 0)
                protocol = r;
        else {
                r = safe_atou(rvalue, &protocol);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse IP protocol '%s' for FooOverUDP tunnel, "
                                   "ignoring assignment: %m", rvalue);
                return 0;
        }

        if (protocol > UINT8_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "IP protocol '%s' for FooOverUDP tunnel out of range, "
                           "ignoring assignment: %m", rvalue);
                return 0;
        }

        *ret = protocol;
        return 0;
}

int config_parse_fou_tunnel_address(
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

        union in_addr_union *addr = ASSERT_PTR(data);
        FouTunnel *t = userdata;
        int r, *f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(lvalue, "Local"))
                f = &t->local_family;
        else
                f = &t->peer_family;

        r = in_addr_from_string_auto(rvalue, f, addr);
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "FooOverUDP tunnel '%s' address is invalid, ignoring assignment: %s",
                           lvalue, rvalue);

        return 0;
}

static int netdev_fou_tunnel_verify(NetDev *netdev, const char *filename) {
        FouTunnel *t;

        assert(netdev);
        assert(filename);

        t = FOU(netdev);

        assert(t);

        switch (t->fou_encap_type) {
        case NETDEV_FOO_OVER_UDP_ENCAP_DIRECT:
                if (t->fou_protocol <= 0)
                        return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                      "FooOverUDP protocol not configured in %s. Rejecting configuration.",
                                                      filename);
                break;
        case NETDEV_FOO_OVER_UDP_ENCAP_GUE:
                if (t->fou_protocol > 0)
                        return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                      "FooOverUDP GUE can't be set with protocol configured in %s. Rejecting configuration.",
                                                      filename);
                break;
        default:
                assert_not_reached();
        }

        if (t->peer_family == AF_UNSPEC && t->peer_port > 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "FooOverUDP peer port is set but peer address not configured in %s. Rejecting configuration.",
                                              filename);
        else if (t->peer_family != AF_UNSPEC && t->peer_port == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "FooOverUDP peer port not set but peer address is configured in %s. Rejecting configuration.",
                                              filename);
        return 0;
}

static void fou_tunnel_init(NetDev *netdev) {
        FouTunnel *t;

        assert(netdev);

        t = FOU(netdev);

        assert(t);

        t->fou_encap_type = NETDEV_FOO_OVER_UDP_ENCAP_DIRECT;
}

const NetDevVTable foutnl_vtable = {
        .object_size = sizeof(FouTunnel),
        .init = fou_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "FooOverUDP\0",
        .create = netdev_fou_tunnel_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_fou_tunnel_verify,
};

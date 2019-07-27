/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/fou.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ip.h>

#include "conf-parser.h"
#include "ip-protocol-list.h"
#include "missing.h"
#include "netdev/fou-tunnel.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "sd-netlink.h"
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

static int netdev_fill_fou_tunnel_message(NetDev *netdev, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        FouTunnel *t;
        uint8_t encap_type;
        int r;

        assert(netdev);

        t = FOU(netdev);

        assert(t);

        r = sd_genl_message_new(netdev->manager->genl, SD_GENL_FOU, FOU_CMD_ADD, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to allocate generic netlink message: %m");

        r = sd_netlink_message_append_u16(m, FOU_ATTR_PORT, htobe16(t->port));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_PORT attribute: %m");

        if (IN_SET(t->peer_family, AF_INET, AF_INET6)) {
                r = sd_netlink_message_append_u16(m, FOU_ATTR_PEER_PORT, htobe16(t->peer_port));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_PEER_PORT attribute: %m");
        }

        switch (t->fou_encap_type) {
        case NETDEV_FOO_OVER_UDP_ENCAP_DIRECT:
                encap_type = FOU_ENCAP_DIRECT;
                break;
        case NETDEV_FOO_OVER_UDP_ENCAP_GUE:
                encap_type = FOU_ENCAP_GUE;
                break;
        default:
                assert_not_reached("invalid encap type");
        }

        r = sd_netlink_message_append_u8(m, FOU_ATTR_TYPE, encap_type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_TYPE attribute: %m");

        r = sd_netlink_message_append_u8(m, FOU_ATTR_AF, AF_INET);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_AF attribute: %m");

        r = sd_netlink_message_append_u8(m, FOU_ATTR_IPPROTO, t->fou_protocol);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_IPPROTO attribute: %m");

        if (t->local_family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, FOU_ATTR_LOCAL_V4, &t->local.in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_LOCAL_V4 attribute: %m");
        } else if (t->local_family == AF_INET6) {
                r = sd_netlink_message_append_in6_addr(m, FOU_ATTR_LOCAL_V6, &t->local.in6);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_LOCAL_V6 attribute: %m");
        }

        if (t->peer_family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, FOU_ATTR_PEER_V4, &t->peer.in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_PEER_V4 attribute: %m");
        } else if (t->peer_family == AF_INET6){
                r = sd_netlink_message_append_in6_addr(m, FOU_ATTR_PEER_V6, &t->peer.in6);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_PEER_V6 attribute: %m");
        }

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
                netdev_drop(netdev);

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

        r = netdev_fill_fou_tunnel_message(netdev, &m);
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

        uint8_t *protocol = data;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        assert_cc(IPPROTO_MAX-1 <= UINT8_MAX);

        r = parse_ip_protocol(rvalue);
        if (r < 0) {
                r = safe_atou8(rvalue, protocol);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse IP protocol '%s' for Foo over UDP tunnel, "
                                   "ignoring assignment: %m", rvalue);
                return 0;
        }

        *protocol = r;
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

        union in_addr_union *addr = data;
        FouTunnel *t = userdata;
        int r, *f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(lvalue, "Local"))
                f = &t->local_family;
        else
                f = &t->peer_family;

        r = in_addr_from_string_auto(rvalue, f, addr);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Foo over UDP tunnel '%s' address is invalid, ignoring assignment: %s",
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
                assert_not_reached("Invalid fou encap type");
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
        .sections = "Match\0NetDev\0FooOverUDP\0",
        .create = netdev_fou_tunnel_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_fou_tunnel_verify,
};

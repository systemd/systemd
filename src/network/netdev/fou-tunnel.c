/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>

#include "conf-parser.h"
#include "missing.h"
#include "netdev/fou-tunnel.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "sd-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static const char *const fou_encap_type_table[_NETDEV_FOO_OVER_UDP_ENCAP_MAX] = {
        [NETDEV_FOO_OVER_UDP_ENCAP_DIRECT] = "FooOverUDP",
        [NETDEV_FOO_OVER_UDP_ENCAP_GUE] = "GenericUDPEncapsulation",
};

DEFINE_STRING_TABLE_LOOKUP(fou_encap_type, FooOverUDPEncapType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_fou_encap_type, fou_encap_type, FooOverUDPEncapType, "Failed to parse Encapsulation=");

static int netdev_fill_fou_tunnel_message(NetDev *netdev, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        FouTunnel *t;
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

        r = sd_netlink_message_append_u8(m, FOU_ATTR_TYPE, FOU_ENCAP_GUE);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_TYPE attribute: %m");

        r = sd_netlink_message_append_u8(m, FOU_ATTR_AF, AF_INET);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_AF attribute: %m");

        r = sd_netlink_message_append_u8(m, FOU_ATTR_IPPROTO, t->fou_protocol);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append FOU_ATTR_IPPROTO attribute: %m");

        *ret = m;
        m = NULL;

        return 0;
}

static int netdev_fou_tunnel_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint32_t serial;
        FouTunnel *t;
        int r;

        assert(netdev);

        t = FOU(netdev);

        assert(t);

        r = netdev_fill_fou_tunnel_message(netdev, &m);
        if (r < 0)
                return r;

        r = sd_netlink_send(netdev->manager->genl, m, &serial);
        if (r < 0 && r != -EADDRINUSE)
                return log_netdev_error_errno(netdev, r, "Failed to add FooOverUDP tunnel: %m");

        return 0;
}

static int netdev_fou_tunnel_verify(NetDev *netdev, const char *filename) {
        FouTunnel *t;

        assert(netdev);
        assert(filename);

        t = FOU(netdev);

        assert(t);

        if (t->fou_encap_type == NETDEV_FOO_OVER_UDP_ENCAP_DIRECT && t->fou_protocol <= 0) {
                log_netdev_error(netdev, "FooOverUDP protocol not configured in %s. Rejecting configuration.", filename);
                return -EINVAL;
        }

        if (t->fou_encap_type == NETDEV_FOO_OVER_UDP_ENCAP_GUE && t->fou_protocol > 0) {
                log_netdev_error(netdev, "FooOverUDP GUE can't be set with protocol configured in %s. Rejecting configuration.", filename);
                return -EINVAL;
        }

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

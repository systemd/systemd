/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <getopt.h>
#include <linux/if_addrlabel.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-dhcp-client.h"
#include "sd-hwdb.h"
#include "sd-lldp.h"
#include "sd-netlink.h"
#include "sd-network.h"

#include "alloc-util.h"
#include "bond-util.h"
#include "bridge-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "device-util.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "geneve-util.h"
#include "glob-util.h"
#include "hwdb-util.h"
#include "ipvlan-util.h"
#include "local-addresses.h"
#include "locale-util.h"
#include "logs-show.h"
#include "macro.h"
#include "macvlan-util.h"
#include "main-func.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "network-util.h"
#include "pager.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "set.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "sort-util.h"
#include "sparse-endian.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "verbs.h"
#include "wifi-util.h"

/* Kernel defines MODULE_NAME_LEN as 64 - sizeof(unsigned long). So, 64 is enough. */
#define NETDEV_KIND_MAX 64

/* use 128 kB for receive socket kernel queue, we shouldn't need more here */
#define RCVBUF_SIZE    (128*1024)

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_all = false;
static bool arg_stats = false;
static bool arg_full = false;
static unsigned arg_lines = 10;

static void operational_state_to_color(const char *name, const char *state, const char **on, const char **off) {
        assert(on);
        assert(off);

        if (STRPTR_IN_SET(state, "routable", "enslaved") ||
            (streq_ptr(name, "lo") && streq_ptr(state, "carrier"))) {
                *on = ansi_highlight_green();
                *off = ansi_normal();
        } else if (streq_ptr(state, "degraded")) {
                *on = ansi_highlight_yellow();
                *off = ansi_normal();
        } else
                *on = *off = "";
}

static void setup_state_to_color(const char *state, const char **on, const char **off) {
        assert(on);
        assert(off);

        if (streq_ptr(state, "configured")) {
                *on = ansi_highlight_green();
                *off = ansi_normal();
        } else if (streq_ptr(state, "configuring")) {
                *on = ansi_highlight_yellow();
                *off = ansi_normal();
        } else if (STRPTR_IN_SET(state, "failed", "linger")) {
                *on = ansi_highlight_red();
                *off = ansi_normal();
        } else
                *on = *off = "";
}

typedef struct VxLanInfo {
        uint32_t vni;
        uint32_t link;

        int local_family;
        int group_family;

        union in_addr_union local;
        union in_addr_union group;

        uint16_t dest_port;

        uint8_t proxy;
        uint8_t learning;
        uint8_t inerit;
        uint8_t rsc;
        uint8_t l2miss;
        uint8_t l3miss;
        uint8_t tos;
        uint8_t ttl;
} VxLanInfo;

typedef struct LinkInfo {
        char name[IFNAMSIZ+1];
        char netdev_kind[NETDEV_KIND_MAX];
        sd_device *sd_device;
        int ifindex;
        unsigned short iftype;
        struct ether_addr mac_address;
        struct ether_addr permanent_mac_address;
        uint32_t master;
        uint32_t mtu;
        uint32_t min_mtu;
        uint32_t max_mtu;
        uint32_t tx_queues;
        uint32_t rx_queues;
        uint8_t addr_gen_mode;
        char *qdisc;
        char **alternative_names;

        union {
                struct rtnl_link_stats64 stats64;
                struct rtnl_link_stats stats;
        };

        uint64_t tx_bitrate;
        uint64_t rx_bitrate;

        /* bridge info */
        uint32_t forward_delay;
        uint32_t hello_time;
        uint32_t max_age;
        uint32_t ageing_time;
        uint32_t stp_state;
        uint32_t cost;
        uint16_t priority;
        uint8_t mcast_igmp_version;
        uint8_t port_state;

        /* vxlan info */
        VxLanInfo vxlan_info;

        /* vlan info */
        uint16_t vlan_id;

        /* tunnel info */
        uint8_t ttl;
        uint8_t tos;
        uint8_t inherit;
        uint8_t df;
        uint8_t csum;
        uint8_t csum6_tx;
        uint8_t csum6_rx;
        uint16_t tunnel_port;
        uint32_t vni;
        uint32_t label;
        union in_addr_union local;
        union in_addr_union remote;

        /* bonding info */
        uint8_t mode;
        uint32_t miimon;
        uint32_t updelay;
        uint32_t downdelay;

        /* macvlan and macvtap info */
        uint32_t macvlan_mode;

        /* ipvlan info */
        uint16_t ipvlan_mode;
        uint16_t ipvlan_flags;

        /* ethtool info */
        int autonegotiation;
        uint64_t speed;
        Duplex duplex;
        NetDevPort port;

        /* wlan info */
        enum nl80211_iftype wlan_iftype;
        char *ssid;
        struct ether_addr bssid;

        bool has_mac_address:1;
        bool has_permanent_mac_address:1;
        bool has_tx_queues:1;
        bool has_rx_queues:1;
        bool has_stats64:1;
        bool has_stats:1;
        bool has_bitrates:1;
        bool has_ethtool_link_info:1;
        bool has_wlan_link_info:1;
        bool has_tunnel_ipv4:1;
        bool has_ipv6_address_generation_mode:1;

        bool needs_freeing:1;
} LinkInfo;

static int link_info_compare(const LinkInfo *a, const LinkInfo *b) {
        return CMP(a->ifindex, b->ifindex);
}

static const LinkInfo* link_info_array_free(LinkInfo *array) {
        for (unsigned i = 0; array && array[i].needs_freeing; i++) {
                sd_device_unref(array[i].sd_device);
                free(array[i].ssid);
                free(array[i].qdisc);
                strv_free(array[i].alternative_names);
        }

        return mfree(array);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_array_free);

static int decode_netdev(sd_netlink_message *m, LinkInfo *info) {
        const char *received_kind;
        int r;

        assert(m);
        assert(info);

        r = sd_netlink_message_enter_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string(m, IFLA_INFO_KIND, &received_kind);
        if (r < 0)
                return r;

        r = sd_netlink_message_enter_container(m, IFLA_INFO_DATA);
        if (r < 0)
                return r;

        if (streq(received_kind, "bridge")) {
                (void) sd_netlink_message_read_u32(m, IFLA_BR_FORWARD_DELAY, &info->forward_delay);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_HELLO_TIME, &info->hello_time);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_MAX_AGE, &info->max_age);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_AGEING_TIME, &info->ageing_time);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_STP_STATE, &info->stp_state);
                (void) sd_netlink_message_read_u32(m, IFLA_BRPORT_COST, &info->cost);
                (void) sd_netlink_message_read_u16(m, IFLA_BR_PRIORITY, &info->priority);
                (void) sd_netlink_message_read_u8(m, IFLA_BR_MCAST_IGMP_VERSION, &info->mcast_igmp_version);
                (void) sd_netlink_message_read_u8(m, IFLA_BRPORT_STATE, &info->port_state);
        } if (streq(received_kind, "bond")) {
                (void) sd_netlink_message_read_u8(m, IFLA_BOND_MODE, &info->mode);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_MIIMON, &info->miimon);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_DOWNDELAY, &info->downdelay);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_UPDELAY, &info->updelay);
        } else if (streq(received_kind, "vxlan")) {
                (void) sd_netlink_message_read_u32(m, IFLA_VXLAN_ID, &info->vxlan_info.vni);

                r = sd_netlink_message_read_in_addr(m, IFLA_VXLAN_GROUP, &info->vxlan_info.group.in);
                if (r >= 0)
                        info->vxlan_info.group_family = AF_INET;
                else {
                        r = sd_netlink_message_read_in6_addr(m, IFLA_VXLAN_GROUP6, &info->vxlan_info.group.in6);
                        if (r >= 0)
                                info->vxlan_info.group_family = AF_INET6;
                }

                r = sd_netlink_message_read_in_addr(m, IFLA_VXLAN_LOCAL, &info->vxlan_info.local.in);
                if (r >= 0)
                        info->vxlan_info.local_family = AF_INET;
                else {
                        r = sd_netlink_message_read_in6_addr(m, IFLA_VXLAN_LOCAL6, &info->vxlan_info.local.in6);
                        if (r >= 0)
                                info->vxlan_info.local_family = AF_INET6;
                }

                (void) sd_netlink_message_read_u32(m, IFLA_VXLAN_LINK, &info->vxlan_info.link);
                (void) sd_netlink_message_read_u16(m, IFLA_VXLAN_PORT, &info->vxlan_info.dest_port);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_PROXY, &info->vxlan_info.proxy);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_LEARNING, &info->vxlan_info.learning);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_RSC, &info->vxlan_info.rsc);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_L3MISS, &info->vxlan_info.l3miss);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_L2MISS, &info->vxlan_info.l2miss);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_TOS, &info->vxlan_info.tos);
                (void) sd_netlink_message_read_u8(m, IFLA_VXLAN_TTL, &info->vxlan_info.ttl);
        } else if (streq(received_kind, "vlan"))
                (void) sd_netlink_message_read_u16(m, IFLA_VLAN_ID, &info->vlan_id);
        else if (STR_IN_SET(received_kind, "ipip", "sit")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_IPTUN_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_IPTUN_REMOTE, &info->remote.in);
        } else if (streq(received_kind, "geneve")) {
                (void) sd_netlink_message_read_u32(m, IFLA_GENEVE_ID, &info->vni);

                r = sd_netlink_message_read_in_addr(m, IFLA_GENEVE_REMOTE, &info->remote.in);
                if (r >= 0)
                        info->has_tunnel_ipv4 = true;
                else
                        (void) sd_netlink_message_read_in6_addr(m, IFLA_GENEVE_REMOTE6, &info->remote.in6);

                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_TTL, &info->ttl);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_TTL_INHERIT, &info->inherit);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_TOS, &info->tos);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_DF, &info->df);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_UDP_CSUM, &info->csum);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, &info->csum6_tx);
                (void) sd_netlink_message_read_u8(m, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, &info->csum6_rx);
                (void) sd_netlink_message_read_u16(m, IFLA_GENEVE_PORT, &info->tunnel_port);
                (void) sd_netlink_message_read_u32(m, IFLA_GENEVE_LABEL, &info->label);
        } else if (STR_IN_SET(received_kind, "gre", "gretap", "erspan")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_GRE_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_GRE_REMOTE, &info->remote.in);
        } else if (STR_IN_SET(received_kind, "ip6gre", "ip6gretap", "ip6erspan")) {
                (void) sd_netlink_message_read_in6_addr(m, IFLA_GRE_LOCAL, &info->local.in6);
                (void) sd_netlink_message_read_in6_addr(m, IFLA_GRE_REMOTE, &info->remote.in6);
        } else if (streq(received_kind, "vti")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_VTI_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_VTI_REMOTE, &info->remote.in);
        } else if (streq(received_kind, "vti6")) {
                (void) sd_netlink_message_read_in6_addr(m, IFLA_VTI_LOCAL, &info->local.in6);
                (void) sd_netlink_message_read_in6_addr(m, IFLA_VTI_REMOTE, &info->remote.in6);
        } else if (STR_IN_SET(received_kind, "macvlan", "macvtap"))
                (void) sd_netlink_message_read_u32(m, IFLA_MACVLAN_MODE, &info->macvlan_mode);
        else if (streq(received_kind, "ipvlan")) {
                (void) sd_netlink_message_read_u16(m, IFLA_IPVLAN_MODE, &info->ipvlan_mode);
                (void) sd_netlink_message_read_u16(m, IFLA_IPVLAN_FLAGS, &info->ipvlan_flags);
        }

        strncpy(info->netdev_kind, received_kind, IFNAMSIZ);

        (void) sd_netlink_message_exit_container(m);
        (void) sd_netlink_message_exit_container(m);

        return 0;
}

static int decode_link(sd_netlink_message *m, LinkInfo *info, char **patterns, bool matched_patterns[]) {
        _cleanup_strv_free_ char **altnames = NULL;
        const char *name, *qdisc;
        int ifindex, r;
        uint16_t type;

        assert(m);
        assert(info);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        if (type != RTM_NEWLINK)
                return 0;

        r = sd_rtnl_message_link_get_ifindex(m, &ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &name);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &altnames);
        if (r < 0 && r != -ENODATA)
                return r;

        if (patterns) {
                char str[DECIMAL_STR_MAX(int)];
                size_t pos;

                assert(matched_patterns);

                xsprintf(str, "%i", ifindex);
                if (!strv_fnmatch_full(patterns, str, 0, &pos) &&
                    !strv_fnmatch_full(patterns, name, 0, &pos)) {
                        bool match = false;
                        char **p;

                        STRV_FOREACH(p, altnames)
                                if (strv_fnmatch_full(patterns, *p, 0, &pos)) {
                                        match = true;
                                        break;
                                }
                        if (!match)
                                return 0;
                }

                matched_patterns[pos] = true;
        }

        r = sd_rtnl_message_link_get_type(m, &info->iftype);
        if (r < 0)
                return r;

        strscpy(info->name, sizeof info->name, name);
        info->ifindex = ifindex;
        info->alternative_names = TAKE_PTR(altnames);

        info->has_mac_address =
                sd_netlink_message_read_ether_addr(m, IFLA_ADDRESS, &info->mac_address) >= 0 &&
                memcmp(&info->mac_address, &ETHER_ADDR_NULL, sizeof(struct ether_addr)) != 0;

        info->has_permanent_mac_address =
                ethtool_get_permanent_macaddr(NULL, info->name, &info->permanent_mac_address) >= 0 &&
                memcmp(&info->permanent_mac_address, &ETHER_ADDR_NULL, sizeof(struct ether_addr)) != 0 &&
                memcmp(&info->permanent_mac_address, &info->mac_address, sizeof(struct ether_addr)) != 0;

        (void) sd_netlink_message_read_u32(m, IFLA_MTU, &info->mtu);
        (void) sd_netlink_message_read_u32(m, IFLA_MIN_MTU, &info->min_mtu);
        (void) sd_netlink_message_read_u32(m, IFLA_MAX_MTU, &info->max_mtu);

        info->has_rx_queues =
                sd_netlink_message_read_u32(m, IFLA_NUM_RX_QUEUES, &info->rx_queues) >= 0 &&
                info->rx_queues > 0;

        info->has_tx_queues =
                sd_netlink_message_read_u32(m, IFLA_NUM_TX_QUEUES, &info->tx_queues) >= 0 &&
                info->tx_queues > 0;

        if (sd_netlink_message_read(m, IFLA_STATS64, sizeof info->stats64, &info->stats64) >= 0)
                info->has_stats64 = true;
        else if (sd_netlink_message_read(m, IFLA_STATS, sizeof info->stats, &info->stats) >= 0)
                info->has_stats = true;

        r = sd_netlink_message_read_string(m, IFLA_QDISC, &qdisc);
        if (r >= 0) {
                info->qdisc = strdup(qdisc);
                if (!info->qdisc)
                        return log_oom();
        }

        (void) sd_netlink_message_read_u32(m, IFLA_MASTER, &info->master);

        r = sd_netlink_message_enter_container(m, IFLA_AF_SPEC);
        if (r >= 0) {
                r = sd_netlink_message_enter_container(m, AF_INET6);
                if (r >= 0) {
                        r = sd_netlink_message_read_u8(m, IFLA_INET6_ADDR_GEN_MODE, &info->addr_gen_mode);
                        if (r >= 0 && IN_SET(info->addr_gen_mode,
                                             IN6_ADDR_GEN_MODE_EUI64,
                                             IN6_ADDR_GEN_MODE_NONE,
                                             IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
                                             IN6_ADDR_GEN_MODE_RANDOM))
                                info->has_ipv6_address_generation_mode = true;

                        (void) sd_netlink_message_exit_container(m);
                }
                (void) sd_netlink_message_exit_container(m);
        }

        /* fill kind info */
        (void) decode_netdev(m, info);

        return 1;
}

static int link_get_property(
                sd_bus *bus,
                const LinkInfo *link,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *iface,
                const char *propname) {
        _cleanup_free_ char *path = NULL, *ifindex_str = NULL;
        int r;

        if (asprintf(&ifindex_str, "%i", link->ifindex) < 0)
                return -ENOMEM;

        r = sd_bus_path_encode("/org/freedesktop/network1/link", ifindex_str, &path);
        if (r < 0)
                return r;

        return sd_bus_call_method(
                        bus,
                        "org.freedesktop.network1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        error,
                        reply,
                        "ss",
                        iface,
                        propname);
}

static int acquire_link_bitrates(sd_bus *bus, LinkInfo *link) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = link_get_property(bus, link, &error, &reply, "org.freedesktop.network1.Link", "BitRates");
        if (r < 0) {
                bool quiet = sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                                            BUS_ERROR_SPEED_METER_INACTIVE);

                return log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING,
                                      r, "Failed to query link bit rates: %s", bus_error_message(&error, r));
        }

        r = sd_bus_message_enter_container(reply, 'v', "(tt)");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "(tt)", &link->tx_bitrate, &link->rx_bitrate);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        link->has_bitrates = link->tx_bitrate != UINT64_MAX && link->rx_bitrate != UINT64_MAX;

        return 0;
}

static void acquire_ether_link_info(int *fd, LinkInfo *link) {
        if (ethtool_get_link_info(fd, link->name,
                                  &link->autonegotiation,
                                  &link->speed,
                                  &link->duplex,
                                  &link->port) >= 0)
                link->has_ethtool_link_info = true;
}

static void acquire_wlan_link_info(LinkInfo *link) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *genl = NULL;
        const char *type = NULL;
        int r, k = 0;

        if (link->sd_device)
                (void) sd_device_get_devtype(link->sd_device, &type);
        if (!streq_ptr(type, "wlan"))
                return;

        r = sd_genl_socket_open(&genl);
        if (r < 0) {
                log_debug_errno(r, "Failed to open generic netlink socket: %m");
                return;
        }

        (void) sd_netlink_inc_rcvbuf(genl, RCVBUF_SIZE);

        r = wifi_get_interface(genl, link->ifindex, &link->wlan_iftype, &link->ssid);
        if (r < 0)
                log_debug_errno(r, "%s: failed to query ssid: %m", link->name);

        if (link->wlan_iftype == NL80211_IFTYPE_STATION) {
                k = wifi_get_station(genl, link->ifindex, &link->bssid);
                if (k < 0)
                        log_debug_errno(k, "%s: failed to query bssid: %m", link->name);
        }

        link->has_wlan_link_info = r > 0 || k > 0;
}

static int acquire_link_info(sd_bus *bus, sd_netlink *rtnl, char **patterns, LinkInfo **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_close_ int fd = -1;
        size_t allocated = 0, c = 0, j;
        sd_netlink_message *i;
        int r;

        assert(rtnl);
        assert(ret);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate links: %m");

        _cleanup_free_ bool *matched_patterns = NULL;
        if (patterns) {
                matched_patterns = new0(bool, strv_length(patterns));
                if (!matched_patterns)
                        return log_oom();
        }

        for (i = reply; i; i = sd_netlink_message_next(i)) {
                if (!GREEDY_REALLOC0(links, allocated, c + 2)) /* We keep one trailing one as marker */
                        return -ENOMEM;

                r = decode_link(i, links + c, patterns, matched_patterns);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                links[c].needs_freeing = true;

                char devid[2 + DECIMAL_STR_MAX(int)];
                xsprintf(devid, "n%i", links[c].ifindex);
                (void) sd_device_new_from_device_id(&links[c].sd_device, devid);

                acquire_ether_link_info(&fd, &links[c]);
                acquire_wlan_link_info(&links[c]);

                c++;
        }

        /* Look if we matched all our arguments that are not globs. It
         * is OK for a glob to match nothing, but not for an exact argument. */
        for (size_t pos = 0; pos < strv_length(patterns); pos++) {
                if (matched_patterns[pos])
                        continue;

                if (string_is_glob(patterns[pos]))
                        log_debug("Pattern \"%s\" doesn't match any interface, ignoring.",
                                  patterns[pos]);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                               "Interface \"%s\" not found.", patterns[pos]);
        }

        typesafe_qsort(links, c, link_info_compare);

        if (bus)
                for (j = 0; j < c; j++)
                        (void) acquire_link_bitrates(bus, links + j);

        *ret = TAKE_PTR(links);

        if (patterns && c == 0)
                log_warning("No interfaces matched.");

        return (int) c;
}

static int list_links(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int c, i, r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        c = acquire_link_info(NULL, rtnl, argc > 1 ? argv + 1 : NULL, &links);
        if (c < 0)
                return c;

        (void) pager_open(arg_pager_flags);

        table = table_new("idx", "link", "type", "operational", "setup");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        table_set_header(table, arg_legend);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_minimum_width(table, cell, 3);
        (void) table_set_weight(table, cell, 0);
        (void) table_set_ellipsize_percent(table, cell, 100);
        (void) table_set_align_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_ellipsize_percent(table, cell, 100);

        for (i = 0; i < c; i++) {
                _cleanup_free_ char *setup_state = NULL, *operational_state = NULL;
                const char *on_color_operational, *off_color_operational,
                           *on_color_setup, *off_color_setup;
                _cleanup_free_ char *t = NULL;

                (void) sd_network_link_get_operational_state(links[i].ifindex, &operational_state);
                operational_state_to_color(links[i].name, operational_state, &on_color_operational, &off_color_operational);

                r = sd_network_link_get_setup_state(links[i].ifindex, &setup_state);
                if (r == -ENODATA) /* If there's no info available about this iface, it's unmanaged by networkd */
                        setup_state = strdup("unmanaged");
                setup_state_to_color(setup_state, &on_color_setup, &off_color_setup);

                t = link_get_type_string(links[i].iftype, links[i].sd_device);

                r = table_add_many(table,
                                   TABLE_INT, links[i].ifindex,
                                   TABLE_STRING, links[i].name,
                                   TABLE_STRING, strna(t),
                                   TABLE_STRING, strna(operational_state),
                                   TABLE_SET_COLOR, on_color_operational,
                                   TABLE_STRING, strna(setup_state),
                                   TABLE_SET_COLOR, on_color_setup);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        if (arg_legend)
                printf("\n%i links listed.\n", c);

        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
static int ieee_oui(sd_hwdb *hwdb, const struct ether_addr *mac, char **ret) {
        const char *description;
        char modalias[STRLEN("OUI:XXYYXXYYXXYY") + 1], *desc;
        int r;

        assert(ret);

        if (!hwdb)
                return -EINVAL;

        if (!mac)
                return -EINVAL;

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (memcmp(mac, "\0\0\0", 3) == 0)
                return -EINVAL;

        xsprintf(modalias, "OUI:" ETHER_ADDR_FORMAT_STR,
                 ETHER_ADDR_FORMAT_VAL(*mac));

        r = sd_hwdb_get(hwdb, modalias, "ID_OUI_FROM_DATABASE", &description);
        if (r < 0)
                return r;

        desc = strdup(description);
        if (!desc)
                return -ENOMEM;

        *ret = desc;

        return 0;
}

static int get_gateway_description(
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                int ifindex,
                int family,
                union in_addr_union *gateway,
                char **gateway_description) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *m;
        int r;

        assert(rtnl);
        assert(ifindex >= 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(gateway);
        assert(gateway_description);

        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_GETNEIGH, ifindex, family);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union gw = IN_ADDR_NULL;
                struct ether_addr mac = ETHER_ADDR_NULL;
                uint16_t type;
                int ifi, fam;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "got error: %m");
                        continue;
                }

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0) {
                        log_error_errno(r, "could not get type: %m");
                        continue;
                }

                if (type != RTM_NEWNEIGH) {
                        log_error("type is not RTM_NEWNEIGH");
                        continue;
                }

                r = sd_rtnl_message_neigh_get_family(m, &fam);
                if (r < 0) {
                        log_error_errno(r, "could not get family: %m");
                        continue;
                }

                if (fam != family) {
                        log_error("family is not correct");
                        continue;
                }

                r = sd_rtnl_message_neigh_get_ifindex(m, &ifi);
                if (r < 0) {
                        log_error_errno(r, "could not get ifindex: %m");
                        continue;
                }

                if (ifindex > 0 && ifi != ifindex)
                        continue;

                switch (fam) {
                case AF_INET:
                        r = sd_netlink_message_read_in_addr(m, NDA_DST, &gw.in);
                        if (r < 0)
                                continue;

                        break;
                case AF_INET6:
                        r = sd_netlink_message_read_in6_addr(m, NDA_DST, &gw.in6);
                        if (r < 0)
                                continue;

                        break;
                default:
                        continue;
                }

                if (!in_addr_equal(fam, &gw, gateway))
                        continue;

                r = sd_netlink_message_read(m, NDA_LLADDR, sizeof(mac), &mac);
                if (r < 0)
                        continue;

                r = ieee_oui(hwdb, &mac, gateway_description);
                if (r < 0)
                        continue;

                return 0;
        }

        return -ENODATA;
}

static int dump_list(Table *table, const char *prefix, char * const *l) {
        int r;

        if (strv_isempty(l))
                return 0;

        r = table_add_many(table,
                           TABLE_EMPTY,
                           TABLE_STRING, prefix,
                           TABLE_STRV, l);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_gateways(
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                Table *table,
                int ifindex) {
        _cleanup_free_ struct local_address *local = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        int r, n, i;

        assert(rtnl);
        assert(table);

        n = local_gateways(rtnl, ifindex, AF_UNSPEC, &local);
        if (n <= 0)
                return n;

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *gateway = NULL, *description = NULL, *with_description = NULL;
                char name[IF_NAMESIZE+1];

                r = in_addr_to_string(local[i].family, &local[i].address, &gateway);
                if (r < 0)
                        return r;

                r = get_gateway_description(rtnl, hwdb, local[i].ifindex, local[i].family, &local[i].address, &description);
                if (r < 0)
                        log_debug_errno(r, "Could not get description of gateway, ignoring: %m");

                if (description) {
                        with_description = strjoin(gateway, " (", description, ")");
                        if (!with_description)
                                return log_oom();
                }

                /* Show interface name for the entry if we show entries for all interfaces */
                r = strv_extendf(&buf, "%s%s%s",
                                 with_description ?: gateway,
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? format_ifname_full(local[i].ifindex, name, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Gateway:", buf);
}

static int dump_addresses(
                sd_netlink *rtnl,
                sd_dhcp_lease *lease,
                Table *table,
                int ifindex) {

        _cleanup_free_ struct local_address *local = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        struct in_addr dhcp4_address = {};
        int r, n, i;

        assert(rtnl);
        assert(table);

        n = local_addresses(rtnl, ifindex, AF_UNSPEC, &local);
        if (n <= 0)
                return n;

        if (lease)
                (void) sd_dhcp_lease_get_address(lease, &dhcp4_address);

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *pretty = NULL;
                char name[IF_NAMESIZE+1];

                r = in_addr_to_string(local[i].family, &local[i].address, &pretty);
                if (r < 0)
                        return r;

                if (local[i].family == AF_INET && in4_addr_equal(&local[i].address.in, &dhcp4_address)) {
                        struct in_addr server_address;
                        char *p, s[INET_ADDRSTRLEN];

                        r = sd_dhcp_lease_get_server_identifier(lease, &server_address);
                        if (r >= 0 && inet_ntop(AF_INET, &server_address, s, sizeof(s)))
                                p = strjoin(pretty, " (DHCP4 via ", s, ")");
                        else
                                p = strjoin(pretty, " (DHCP4)");
                        if (!p)
                                return log_oom();

                        free_and_replace(pretty, p);
                }

                r = strv_extendf(&buf, "%s%s%s",
                                 pretty,
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? format_ifname_full(local[i].ifindex, name, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Address:", buf);
}

static int dump_address_labels(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_netlink_message *m;
        TableCell *cell;
        int r;

        assert(rtnl);

        r = sd_rtnl_message_new_addrlabel(rtnl, &req, RTM_GETADDRLABEL, 0, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_GETADDRLABEL message: %m");

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        table = table_new("label", "prefix/prefixlen");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = table_set_sort(table, (size_t) 0, (size_t) SIZE_MAX);
        if (r < 0)
                return r;

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_align_percent(table, cell, 100);

        for (m = reply; m; m = sd_netlink_message_next(m)) {
                _cleanup_free_ char *pretty = NULL;
                union in_addr_union prefix = IN_ADDR_NULL;
                uint8_t prefixlen;
                uint32_t label;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "got error: %m");
                        continue;
                }

                r = sd_netlink_message_read_u32(m, IFAL_LABEL, &label);
                if (r < 0 && r != -ENODATA) {
                        log_error_errno(r, "Could not read IFAL_LABEL, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_read_in6_addr(m, IFAL_ADDRESS, &prefix.in6);
                if (r < 0)
                        continue;

                r = in_addr_to_string(AF_INET6, &prefix, &pretty);
                if (r < 0)
                        continue;

                r = sd_rtnl_message_addrlabel_get_prefixlen(m, &prefixlen);
                if (r < 0)
                        continue;

                r = table_add_cell(table, NULL, TABLE_UINT32, &label);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%s/%u", pretty, prefixlen);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int list_address_labels(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        dump_address_labels(rtnl);

        return 0;
}

static int open_lldp_neighbors(int ifindex, FILE **ret) {
        _cleanup_free_ char *p = NULL;
        FILE *f;

        if (asprintf(&p, "/run/systemd/netif/lldp/%i", ifindex) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        if (!f)
                return -errno;

        *ret = f;
        return 0;
}

static int next_lldp_neighbor(FILE *f, sd_lldp_neighbor **ret) {
        _cleanup_free_ void *raw = NULL;
        size_t l;
        le64_t u;
        int r;

        assert(f);
        assert(ret);

        l = fread(&u, 1, sizeof(u), f);
        if (l == 0 && feof(f))
                return 0;
        if (l != sizeof(u))
                return -EBADMSG;

        /* each LLDP packet is at most MTU size, but let's allow up to 4KiB just in case */
        if (le64toh(u) >= 4096)
                return -EBADMSG;

        raw = new(uint8_t, le64toh(u));
        if (!raw)
                return -ENOMEM;

        if (fread(raw, 1, le64toh(u), f) != le64toh(u))
                return -EBADMSG;

        r = sd_lldp_neighbor_from_raw(ret, raw, le64toh(u));
        if (r < 0)
                return r;

        return 1;
}

static int dump_lldp_neighbors(Table *table, const char *prefix, int ifindex) {
        _cleanup_strv_free_ char **buf = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(table);
        assert(prefix);
        assert(ifindex > 0);

        r = open_lldp_neighbors(ifindex, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        for (;;) {
                const char *system_name = NULL, *port_id = NULL, *port_description = NULL;
                _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;

                r = next_lldp_neighbor(f, &n);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                (void) sd_lldp_neighbor_get_system_name(n, &system_name);
                (void) sd_lldp_neighbor_get_port_id_as_string(n, &port_id);
                (void) sd_lldp_neighbor_get_port_description(n, &port_description);

                r = strv_extendf(&buf, "%s on port %s%s%s%s",
                                 strna(system_name),
                                 strna(port_id),
                                 isempty(port_description) ? "" : " (",
                                 strempty(port_description),
                                 isempty(port_description) ? "" : ")");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, prefix, buf);
}

static int dump_dhcp_leases(Table *table, const char *prefix, sd_bus *bus, const LinkInfo *link) {
        _cleanup_strv_free_ char **buf = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = link_get_property(bus, link, &error, &reply, "org.freedesktop.network1.DHCPServer", "Leases");
        if (r < 0) {
                bool quiet = sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY);

                log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING,
                               r, "Failed to query link DHCP leases: %s", bus_error_message(&error, r));
                return 0;
        }

        r = sd_bus_message_enter_container(reply, 'v', "a(uayayayayt)");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(reply, 'a', "(uayayayayt)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "uayayayayt")) > 0) {
                _cleanup_free_ char *id = NULL, *ip = NULL;
                const void *client_id, *addr, *gtw, *hwaddr;
                size_t client_id_sz, sz;
                uint64_t expiration;
                uint32_t family;

                r = sd_bus_message_read(reply, "u", &family);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &client_id, &client_id_sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &addr, &sz);
                if (r < 0 || sz != 4)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &gtw, &sz);
                if (r < 0 || sz != 4)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &hwaddr, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_basic(reply, 't', &expiration);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_dhcp_client_id_to_string(client_id, client_id_sz, &id);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = in_addr_to_string(family, addr, &ip);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = strv_extendf(&buf, "%s (to %s)", ip, id);
                if (r < 0)
                        return log_oom();

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (strv_isempty(buf)) {
                r = strv_extendf(&buf, "none");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, prefix, buf);
}

static int dump_ifindexes(Table *table, const char *prefix, const int *ifindexes) {
        unsigned c;
        int r;

        assert(prefix);

        if (!ifindexes || ifindexes[0] <= 0)
                return 0;

        for (c = 0; ifindexes[c] > 0; c++) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, c == 0 ? prefix : "",
                                   TABLE_IFINDEX, ifindexes[c]);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return 0;
}

#define DUMP_STATS_ONE(name, val_name)                                  \
        r = table_add_many(table,                                       \
                           TABLE_EMPTY,                                 \
                           TABLE_STRING, name ":");                     \
        if (r < 0)                                                      \
                return table_log_add_error(r);                                               \
        r = table_add_cell(table, NULL,                                 \
                           info->has_stats64 ? TABLE_UINT64 : TABLE_UINT32, \
                           info->has_stats64 ? (void*) &info->stats64.val_name : (void*) &info->stats.val_name); \
        if (r < 0)                                                      \
                return table_log_add_error(r);

static int dump_statistics(Table *table, const LinkInfo *info) {
        int r;

        if (!arg_stats)
                return 0;

        if (!info->has_stats64 && !info->has_stats)
                return 0;

        DUMP_STATS_ONE("Rx Packets", rx_packets);
        DUMP_STATS_ONE("Tx Packets", tx_packets);
        DUMP_STATS_ONE("Rx Bytes", rx_bytes);
        DUMP_STATS_ONE("Tx Bytes", tx_bytes);
        DUMP_STATS_ONE("Rx Errors", rx_errors);
        DUMP_STATS_ONE("Tx Errors", tx_errors);
        DUMP_STATS_ONE("Rx Dropped", rx_dropped);
        DUMP_STATS_ONE("Tx Dropped", tx_dropped);
        DUMP_STATS_ONE("Multicast Packets", multicast);
        DUMP_STATS_ONE("Collisions", collisions);

        return 0;
}

static OutputFlags get_output_flags(void) {
        return
                arg_all * OUTPUT_SHOW_ALL |
                (arg_full || !on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                colors_enabled() * OUTPUT_COLOR;
}

static int show_logs(const LinkInfo *info) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        if (arg_lines == 0)
                return 0;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        r = add_match_this_boot(j, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add boot matches: %m");

        if (info) {
                char m1[STRLEN("_KERNEL_DEVICE=n") + DECIMAL_STR_MAX(int)];
                const char *m2, *m3;

                /* kernel */
                xsprintf(m1, "_KERNEL_DEVICE=n%i", info->ifindex);
                /* networkd */
                m2 = strjoina("INTERFACE=", info->name);
                /* udevd */
                m3 = strjoina("DEVICE=", info->name);

                (void)(
                       (r = sd_journal_add_match(j, m1, 0)) ||
                       (r = sd_journal_add_disjunction(j)) ||
                       (r = sd_journal_add_match(j, m2, 0)) ||
                       (r = sd_journal_add_disjunction(j)) ||
                       (r = sd_journal_add_match(j, m3, 0))
                );
                if (r < 0)
                        return log_error_errno(r, "Failed to add link matches: %m");
        } else {
                r = add_matches_for_unit(j, "systemd-networkd.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit matches: %m");

                r = add_matches_for_unit(j, "systemd-networkd-wait-online.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit matches: %m");
        }

        return show_journal(
                        stdout,
                        j,
                        OUTPUT_SHORT,
                        0,
                        0,
                        arg_lines,
                        get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                        NULL);
}

static int link_status_one(
                sd_bus *bus,
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                const LinkInfo *info) {

        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL, **sip = NULL, **search_domains = NULL, **route_domains = NULL;
        _cleanup_free_ char *t = NULL, *network = NULL, *iaid = NULL, *duid = NULL,
                *setup_state = NULL, *operational_state = NULL, *lease_file = NULL;
        const char *driver = NULL, *path = NULL, *vendor = NULL, *model = NULL, *link = NULL,
                *on_color_operational, *off_color_operational, *on_color_setup, *off_color_setup;
        _cleanup_free_ int *carrier_bound_to = NULL, *carrier_bound_by = NULL;
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int r;

        assert(rtnl);
        assert(info);

        (void) sd_network_link_get_operational_state(info->ifindex, &operational_state);
        operational_state_to_color(info->name, operational_state, &on_color_operational, &off_color_operational);

        r = sd_network_link_get_setup_state(info->ifindex, &setup_state);
        if (r == -ENODATA) /* If there's no info available about this iface, it's unmanaged by networkd */
                setup_state = strdup("unmanaged");
        setup_state_to_color(setup_state, &on_color_setup, &off_color_setup);

        (void) sd_network_link_get_dns(info->ifindex, &dns);
        (void) sd_network_link_get_search_domains(info->ifindex, &search_domains);
        (void) sd_network_link_get_route_domains(info->ifindex, &route_domains);
        (void) sd_network_link_get_ntp(info->ifindex, &ntp);
        (void) sd_network_link_get_sip(info->ifindex, &sip);

        if (info->sd_device) {
                (void) sd_device_get_property_value(info->sd_device, "ID_NET_LINK_FILE", &link);
                (void) sd_device_get_property_value(info->sd_device, "ID_NET_DRIVER", &driver);
                (void) sd_device_get_property_value(info->sd_device, "ID_PATH", &path);

                if (sd_device_get_property_value(info->sd_device, "ID_VENDOR_FROM_DATABASE", &vendor) < 0)
                        (void) sd_device_get_property_value(info->sd_device, "ID_VENDOR", &vendor);

                if (sd_device_get_property_value(info->sd_device, "ID_MODEL_FROM_DATABASE", &model) < 0)
                        (void) sd_device_get_property_value(info->sd_device, "ID_MODEL", &model);
        }

        t = link_get_type_string(info->iftype, info->sd_device);

        (void) sd_network_link_get_network_file(info->ifindex, &network);

        (void) sd_network_link_get_carrier_bound_to(info->ifindex, &carrier_bound_to);
        (void) sd_network_link_get_carrier_bound_by(info->ifindex, &carrier_bound_by);

        if (asprintf(&lease_file, "/run/systemd/netif/leases/%d", info->ifindex) < 0)
                return log_oom();

        (void) dhcp_lease_load(&lease, lease_file);

        table = table_new("dot", "key", "value");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_ellipsize_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_ellipsize_percent(table, cell, 100);

        table_set_header(table, false);

        r = table_add_many(table,
                           TABLE_STRING, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE),
                           TABLE_SET_COLOR, on_color_operational);
        if (r < 0)
                return table_log_add_error(r);
        r = table_add_cell_stringf(table, &cell, "%i: %s", info->ifindex, info->name);
        if (r < 0)
                return table_log_add_error(r);
        (void) table_set_align_percent(table, cell, 0);

        r = table_add_many(table,
                           TABLE_EMPTY,
                           TABLE_EMPTY,
                           TABLE_STRING, "Link File:",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_STRING, strna(link),
                           TABLE_EMPTY,
                           TABLE_STRING, "Network File:",
                           TABLE_STRING, strna(network),
                           TABLE_EMPTY,
                           TABLE_STRING, "Type:",
                           TABLE_STRING, strna(t),
                           TABLE_EMPTY,
                           TABLE_STRING, "State:");
        if (r < 0)
                return table_log_add_error(r);
        r = table_add_cell_stringf(table, NULL, "%s%s%s (%s%s%s)",
                                   on_color_operational, strna(operational_state), off_color_operational,
                                   on_color_setup, strna(setup_state), off_color_setup);
        if (r < 0)
                return table_log_add_error(r);

        strv_sort(info->alternative_names);
        r = dump_list(table, "Alternative Names:", info->alternative_names);
        if (r < 0)
                return r;

        if (path) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Path:",
                                   TABLE_STRING, path);
                if (r < 0)
                        return table_log_add_error(r);
        }
        if (driver) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Driver:",
                                   TABLE_STRING, driver);
                if (r < 0)
                        return table_log_add_error(r);
        }
        if (vendor) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Vendor:",
                                   TABLE_STRING, vendor);
                if (r < 0)
                        return table_log_add_error(r);
        }
        if (model) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Model:",
                                   TABLE_STRING, model);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_mac_address) {
                _cleanup_free_ char *description = NULL;
                char ea[ETHER_ADDR_TO_STRING_MAX];

                (void) ieee_oui(hwdb, &info->mac_address, &description);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "HW Address:");
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_cell_stringf(table, NULL, "%s%s%s%s",
                                           ether_addr_to_string(&info->mac_address, ea),
                                           description ? " (" : "",
                                           strempty(description),
                                           description ? ")" : "");
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_permanent_mac_address) {
                _cleanup_free_ char *description = NULL;
                char ea[ETHER_ADDR_TO_STRING_MAX];

                (void) ieee_oui(hwdb, &info->permanent_mac_address, &description);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "HW Permanent Address:");
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_cell_stringf(table, NULL, "%s%s%s%s",
                                           ether_addr_to_string(&info->permanent_mac_address, ea),
                                           description ? " (" : "",
                                           strempty(description),
                                           description ? ")" : "");
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->mtu > 0) {
                char min_str[DECIMAL_STR_MAX(uint32_t)], max_str[DECIMAL_STR_MAX(uint32_t)];

                xsprintf(min_str, "%" PRIu32, info->min_mtu);
                xsprintf(max_str, "%" PRIu32, info->max_mtu);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "MTU:");
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_cell_stringf(table, NULL, "%" PRIu32 "%s%s%s%s%s%s%s",
                                           info->mtu,
                                           info->min_mtu > 0 || info->max_mtu > 0 ? " (" : "",
                                           info->min_mtu > 0 ? "min: " : "",
                                           info->min_mtu > 0 ? min_str : "",
                                           info->min_mtu > 0 && info->max_mtu > 0 ? ", " : "",
                                           info->max_mtu > 0 ? "max: " : "",
                                           info->max_mtu > 0 ? max_str : "",
                                           info->min_mtu > 0 || info->max_mtu > 0 ? ")" : "");
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->qdisc) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "QDisc:",
                                   TABLE_STRING, info->qdisc);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->master > 0) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Master:",
                                   TABLE_IFINDEX, info->master);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_ipv6_address_generation_mode) {
                static const struct {
                        const char *mode;
                } mode_table[] = {
                        { "eui64" },
                        { "none" },
                        { "stable-privacy" },
                        { "random" },
                };

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "IPv6 Address Generation Mode:",
                                   TABLE_STRING, mode_table[info->addr_gen_mode]);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (streq_ptr(info->netdev_kind, "bridge")) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Forward Delay:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->forward_delay),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Hello Time:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->hello_time),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Max Age:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->max_age),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Ageing Time:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->ageing_time),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Priority:",
                                   TABLE_UINT16, info->priority,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "STP:",
                                   TABLE_BOOLEAN, info->stp_state > 0,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Multicast IGMP Version:",
                                   TABLE_UINT8, info->mcast_igmp_version,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Cost:",
                                   TABLE_UINT32, info->cost);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->port_state <= BR_STATE_BLOCKING) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Port State:",
                                           TABLE_STRING, bridge_state_to_string(info->port_state));
                }
        } else if (streq_ptr(info->netdev_kind, "bond")) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Mode:",
                                   TABLE_STRING, bond_mode_to_string(info->mode),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Miimon:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->miimon),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Updelay:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->updelay),
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Downdelay:",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->downdelay));
                if (r < 0)
                        return table_log_add_error(r);

        } else if (streq_ptr(info->netdev_kind, "vxlan")) {
                char ttl[CONST_MAX(STRLEN("auto") + 1, DECIMAL_STR_MAX(uint8_t))];

                if (info->vxlan_info.vni > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "VNI:",
                                           TABLE_UINT32, info->vxlan_info.vni);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (IN_SET(info->vxlan_info.group_family, AF_INET, AF_INET6)) {
                        const char *p;

                        r = in_addr_is_multicast(info->vxlan_info.group_family, &info->vxlan_info.group);
                        if (r <= 0)
                                p = "Remote:";
                        else
                                p = "Group:";

                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, p,
                                           info->vxlan_info.group_family == AF_INET ? TABLE_IN_ADDR : TABLE_IN6_ADDR,
                                           &info->vxlan_info.group);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (IN_SET(info->vxlan_info.local_family, AF_INET, AF_INET6)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Local:",
                                           info->vxlan_info.local_family == AF_INET ? TABLE_IN_ADDR : TABLE_IN6_ADDR,
                                           &info->vxlan_info.local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.dest_port > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Destination Port:",
                                           TABLE_UINT16, be16toh(info->vxlan_info.dest_port));
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.link > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Underlying Device:",
                                           TABLE_IFINDEX, info->vxlan_info.link);
                        if (r < 0)
                                 return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Learning:",
                                   TABLE_BOOLEAN, info->vxlan_info.learning);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "RSC:",
                                   TABLE_BOOLEAN, info->vxlan_info.rsc);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "L3MISS:",
                                   TABLE_BOOLEAN, info->vxlan_info.l3miss);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "L2MISS:",
                                   TABLE_BOOLEAN, info->vxlan_info.l2miss);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->vxlan_info.tos > 1) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "TOS:",
                                           TABLE_UINT8, info->vxlan_info.tos);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.ttl > 0)
                        xsprintf(ttl, "%" PRIu8, info->vxlan_info.ttl);
                else
                        strcpy(ttl, "auto");

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "TTL:",
                                   TABLE_STRING, ttl);
                if (r < 0)
                        return table_log_add_error(r);
        } else if (streq_ptr(info->netdev_kind, "vlan") && info->vlan_id > 0) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "VLan Id:",
                                   TABLE_UINT16, info->vlan_id);
                if (r < 0)
                        return table_log_add_error(r);
        } else if (STRPTR_IN_SET(info->netdev_kind, "ipip", "sit", "gre", "gretap", "erspan", "vti")) {
                if (!in_addr_is_null(AF_INET, &info->local)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Local:",
                                           TABLE_IN_ADDR, &info->local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (!in_addr_is_null(AF_INET, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Remote:",
                                           TABLE_IN_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        } else if (STRPTR_IN_SET(info->netdev_kind, "ip6gre", "ip6gretap", "ip6erspan", "vti6")) {
                if (!in_addr_is_null(AF_INET6, &info->local)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Local:",
                                           TABLE_IN6_ADDR, &info->local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (!in_addr_is_null(AF_INET6, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Remote:",
                                           TABLE_IN6_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        } else if (streq_ptr(info->netdev_kind, "geneve")) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "VNI:",
                                   TABLE_UINT32, info->vni);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->has_tunnel_ipv4 && !in_addr_is_null(AF_INET, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Remote:",
                                           TABLE_IN_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                } else if (!in_addr_is_null(AF_INET6, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Remote:",
                                           TABLE_IN6_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->ttl > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "TTL:",
                                           TABLE_UINT8, info->ttl);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->tos > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "TOS:",
                                           TABLE_UINT8, info->tos);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Port:",
                                   TABLE_UINT16, info->tunnel_port);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Inherit:",
                                   TABLE_STRING, geneve_df_to_string(info->inherit));
                if (r < 0)
                        return table_log_add_error(r);

                if (info->df > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "IPDoNotFragment:",
                                           TABLE_UINT8, info->df);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "UDPChecksum:",
                                   TABLE_BOOLEAN, info->csum);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "UDP6ZeroChecksumTx:",
                                   TABLE_BOOLEAN, info->csum6_tx);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "UDP6ZeroChecksumRx:",
                                   TABLE_BOOLEAN, info->csum6_rx);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->label > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "FlowLabel:",
                                           TABLE_UINT32, info->label);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        } else if (STRPTR_IN_SET(info->netdev_kind, "macvlan", "macvtap")) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Mode:",
                                   TABLE_STRING, macvlan_mode_to_string(info->macvlan_mode));
                if (r < 0)
                        return table_log_add_error(r);
        } else if (streq_ptr(info->netdev_kind, "ipvlan")) {
                _cleanup_free_ char *p = NULL, *s = NULL;

                if (info->ipvlan_flags & IPVLAN_F_PRIVATE)
                        p = strdup("private");
                else if (info->ipvlan_flags & IPVLAN_F_VEPA)
                        p = strdup("vepa");
                else
                        p = strdup("bridge");
                if (!p)
                        log_oom();

                s = strjoin(ipvlan_mode_to_string(info->ipvlan_mode), " (", p, ")");
                if (!s)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Mode:",
                                   TABLE_STRING, s);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_wlan_link_info) {
                _cleanup_free_ char *esc = NULL;
                char buf[ETHER_ADDR_TO_STRING_MAX];

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "WiFi access point:");
                if (r < 0)
                        return table_log_add_error(r);

                if (info->ssid)
                        esc = cescape(info->ssid);

                r = table_add_cell_stringf(table, NULL, "%s (%s)",
                                           strnull(esc),
                                           ether_addr_to_string(&info->bssid, buf));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_bitrates) {
                char tx[FORMAT_BYTES_MAX], rx[FORMAT_BYTES_MAX];

                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Bit Rate (Tx/Rx):");
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_cell_stringf(table, NULL, "%sbps/%sbps",
                                           format_bytes_full(tx, sizeof tx, info->tx_bitrate, 0),
                                           format_bytes_full(rx, sizeof rx, info->rx_bitrate, 0));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_tx_queues || info->has_rx_queues) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "Queue Length (Tx/Rx):");
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_cell_stringf(table, NULL, "%" PRIu32 "/%" PRIu32, info->tx_queues, info->rx_queues);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_ethtool_link_info) {
                const char *duplex = duplex_to_string(info->duplex);
                const char *port = port_to_string(info->port);

                if (IN_SET(info->autonegotiation, AUTONEG_DISABLE, AUTONEG_ENABLE)) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Auto negotiation:",
                                           TABLE_BOOLEAN, info->autonegotiation == AUTONEG_ENABLE);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->speed > 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Speed:",
                                           TABLE_BPS, info->speed);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (duplex) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Duplex:",
                                           TABLE_STRING, duplex);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (port) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Port:",
                                           TABLE_STRING, port);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        r = dump_addresses(rtnl, lease, table, info->ifindex);
        if (r < 0)
                return r;
        r = dump_gateways(rtnl, hwdb, table, info->ifindex);
        if (r < 0)
                return r;
        r = dump_list(table, "DNS:", dns);
        if (r < 0)
                return r;
        r = dump_list(table, "Search Domains:", search_domains);
        if (r < 0)
                return r;
        r = dump_list(table, "Route Domains:", route_domains);
        if (r < 0)
                return r;
        r = dump_list(table, "NTP:", ntp);
        if (r < 0)
                return r;
        r = dump_list(table, "SIP:", sip);
        if (r < 0)
                return r;
        r = dump_ifindexes(table, "Carrier Bound To:", carrier_bound_to);
        if (r < 0)
                return r;
        r = dump_ifindexes(table, "Carrier Bound By:", carrier_bound_by);
        if (r < 0)
                return r;

        if (lease) {
                const void *client_id;
                size_t client_id_len;
                const char *tz;

                r = sd_dhcp_lease_get_timezone(lease, &tz);
                if (r >= 0) {
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_STRING, "Time Zone:",
                                           TABLE_STRING, tz);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = sd_dhcp_lease_get_client_id(lease, &client_id, &client_id_len);
                if (r >= 0) {
                        _cleanup_free_ char *id = NULL;

                        r = sd_dhcp_client_id_to_string(client_id, client_id_len, &id);
                        if (r >= 0) {
                                r = table_add_many(table,
                                                   TABLE_EMPTY,
                                                   TABLE_STRING, "DHCP4 Client ID:",
                                                   TABLE_STRING, id);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                }
        }

        r = sd_network_link_get_dhcp6_client_iaid_string(info->ifindex, &iaid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "DHCP6 Client IAID:",
                                   TABLE_STRING, iaid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_network_link_get_dhcp6_client_duid_string(info->ifindex, &duid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_EMPTY,
                                   TABLE_STRING, "DHCP6 Client DUID:",
                                   TABLE_STRING, duid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = dump_lldp_neighbors(table, "Connected To:", info->ifindex);
        if (r < 0)
                return r;

        r = dump_dhcp_leases(table, "Offered DHCP leases:", bus, info);
        if (r < 0)
                return r;

        r = dump_statistics(table, info);
        if (r < 0)
                return r;

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return show_logs(info);
}

static int system_status(sd_netlink *rtnl, sd_hwdb *hwdb) {
        _cleanup_free_ char *operational_state = NULL;
        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        const char *on_color_operational, *off_color_operational;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int r;

        assert(rtnl);

        (void) sd_network_get_operational_state(&operational_state);
        operational_state_to_color(NULL, operational_state, &on_color_operational, &off_color_operational);

        table = table_new("dot", "key", "value");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_ellipsize_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        table_set_header(table, false);

        r = table_add_many(table,
                           TABLE_STRING, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE),
                           TABLE_SET_COLOR, on_color_operational,
                           TABLE_STRING, "State:",
                           TABLE_STRING, strna(operational_state),
                           TABLE_SET_COLOR, on_color_operational);
        if (r < 0)
                return table_log_add_error(r);

        r = dump_addresses(rtnl, NULL, table, 0);
        if (r < 0)
                return r;
        r = dump_gateways(rtnl, hwdb, table, 0);
        if (r < 0)
                return r;

        (void) sd_network_get_dns(&dns);
        r = dump_list(table, "DNS:", dns);
        if (r < 0)
                return r;

        (void) sd_network_get_search_domains(&search_domains);
        r = dump_list(table, "Search Domains:", search_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_route_domains(&route_domains);
        r = dump_list(table, "Route Domains:", route_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_ntp(&ntp);
        r = dump_list(table, "NTP:", ntp);
        if (r < 0)
                return r;

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return show_logs(NULL);
}

static int link_status(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        int r, c, i;

        (void) pager_open(arg_pager_flags);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                log_debug_errno(r, "Failed to open hardware database: %m");

        if (arg_all)
                c = acquire_link_info(bus, rtnl, NULL, &links);
        else if (argc <= 1)
                return system_status(rtnl, hwdb);
        else
                c = acquire_link_info(bus, rtnl, argv + 1, &links);
        if (c < 0)
                return c;

        for (i = 0; i < c; i++) {
                if (i > 0)
                        fputc('\n', stdout);

                link_status_one(bus, rtnl, hwdb, links + i);
        }

        return 0;
}

static char *lldp_capabilities_to_string(uint16_t x) {
        static const char characters[] = {
                'o', 'p', 'b', 'w', 'r', 't', 'd', 'a', 'c', 's', 'm',
        };
        char *ret;
        unsigned i;

        ret = new(char, ELEMENTSOF(characters) + 1);
        if (!ret)
                return NULL;

        for (i = 0; i < ELEMENTSOF(characters); i++)
                ret[i] = (x & (1U << i)) ? characters[i] : '.';

        ret[i] = 0;
        return ret;
}

static void lldp_capabilities_legend(uint16_t x) {
        unsigned w, i, cols = columns();
        static const char* const table[] = {
                "o - Other",
                "p - Repeater",
                "b - Bridge",
                "w - WLAN Access Point",
                "r - Router",
                "t - Telephone",
                "d - DOCSIS cable device",
                "a - Station",
                "c - Customer VLAN",
                "s - Service VLAN",
                "m - Two-port MAC Relay (TPMR)",
        };

        if (x == 0)
                return;

        printf("\nCapability Flags:\n");
        for (w = 0, i = 0; i < ELEMENTSOF(table); i++)
                if (x & (1U << i) || arg_all) {
                        bool newline;

                        newline = w + strlen(table[i]) + (w == 0 ? 0 : 2) > cols;
                        if (newline)
                                w = 0;
                        w += printf("%s%s%s", newline ? "\n" : "", w == 0 ? "" : "; ", table[i]);
                }
        puts("");
}

static int link_lldp_status(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int i, r, c, m = 0;
        uint16_t all = 0;
        TableCell *cell;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        c = acquire_link_info(NULL, rtnl, argc > 1 ? argv + 1 : NULL, &links);
        if (c < 0)
                return c;

        (void) pager_open(arg_pager_flags);

        table = table_new("link",
                          "chassis id",
                          "system name",
                          "caps",
                          "port id",
                          "port description");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        table_set_header(table, arg_legend);

        assert_se(cell = table_get_cell(table, 0, 0));
        table_set_minimum_width(table, cell, 16);

        assert_se(cell = table_get_cell(table, 0, 1));
        table_set_minimum_width(table, cell, 17);

        assert_se(cell = table_get_cell(table, 0, 2));
        table_set_minimum_width(table, cell, 16);

        assert_se(cell = table_get_cell(table, 0, 3));
        table_set_minimum_width(table, cell, 11);

        assert_se(cell = table_get_cell(table, 0, 4));
        table_set_minimum_width(table, cell, 17);

        assert_se(cell = table_get_cell(table, 0, 5));
        table_set_minimum_width(table, cell, 16);

        for (i = 0; i < c; i++) {
                _cleanup_fclose_ FILE *f = NULL;

                r = open_lldp_neighbors(links[i].ifindex, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to open LLDP data for %i, ignoring: %m", links[i].ifindex);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *cid = NULL, *pid = NULL, *sname = NULL, *pdesc = NULL, *capabilities = NULL;
                        const char *chassis_id = NULL, *port_id = NULL, *system_name = NULL, *port_description = NULL;
                        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
                        uint16_t cc;

                        r = next_lldp_neighbor(f, &n);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to read neighbor data: %m");
                                break;
                        }
                        if (r == 0)
                                break;

                        (void) sd_lldp_neighbor_get_chassis_id_as_string(n, &chassis_id);
                        (void) sd_lldp_neighbor_get_port_id_as_string(n, &port_id);
                        (void) sd_lldp_neighbor_get_system_name(n, &system_name);
                        (void) sd_lldp_neighbor_get_port_description(n, &port_description);

                        if (chassis_id) {
                                cid = ellipsize(chassis_id, 17, 100);
                                if (cid)
                                        chassis_id = cid;
                        }

                        if (port_id) {
                                pid = ellipsize(port_id, 17, 100);
                                if (pid)
                                        port_id = pid;
                        }

                        if (system_name) {
                                sname = ellipsize(system_name, 16, 100);
                                if (sname)
                                        system_name = sname;
                        }

                        if (port_description) {
                                pdesc = ellipsize(port_description, 16, 100);
                                if (pdesc)
                                        port_description = pdesc;
                        }

                        if (sd_lldp_neighbor_get_enabled_capabilities(n, &cc) >= 0) {
                                capabilities = lldp_capabilities_to_string(cc);
                                all |= cc;
                        }

                        r = table_add_many(table,
                                           TABLE_STRING, links[i].name,
                                           TABLE_STRING, strna(chassis_id),
                                           TABLE_STRING, strna(system_name),
                                           TABLE_STRING, strna(capabilities),
                                           TABLE_STRING, strna(port_id),
                                           TABLE_STRING, strna(port_description));
                        if (r < 0)
                                return table_log_add_error(r);

                        m++;
                }
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        if (arg_legend) {
                lldp_capabilities_legend(all);
                printf("\n%i neighbors listed.\n", m);
        }

        return 0;
}

static int link_delete_send_message(sd_netlink *rtnl, int index) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_DELLINK, index);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int link_up_down_send_message(sd_netlink *rtnl, char *command, int index) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, index);
        if (r < 0)
                return rtnl_log_create_error(r);

        if (streq(command, "up"))
                r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        else
                r = sd_rtnl_message_link_set_flags(req, 0, IFF_UP);
        if (r < 0)
                return log_error_errno(r, "Could not set link flags: %m");

        r = sd_netlink_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int link_up_down(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r, i;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (i = 1; i < argc; i++) {
                index = resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_up_down_send_message(rtnl, argv[0], index);
                if (r < 0) {
                        char ifname[IF_NAMESIZE + 1];

                        return log_error_errno(r, "Failed to %s interface %s: %m",
                                               argv[1], format_ifname_full(index, ifname, FORMAT_IFNAME_IFINDEX));
                }
        }

        return r;
}

static int link_delete(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r, i;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (i = 1; i < argc; i++) {
                index = resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_delete_send_message(rtnl, index);
                if (r < 0) {
                        char ifname[IF_NAMESIZE + 1];

                        return log_error_errno(r, "Failed to delete interface %s: %m",
                                               format_ifname_full(index, ifname, FORMAT_IFNAME_IFINDEX));
                }
        }

        return r;
}

static int link_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = bus_call_method(bus, bus_network_mgr, "RenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

static int link_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int index, i, k = 0, r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        for (i = 1; i < argc; i++) {
                index = resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = link_renew_one(bus, index, argv[i]);
                if (r < 0 && k >= 0)
                        k = r;
        }

        return k;
}

static int link_force_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = bus_call_method(bus, bus_network_mgr, "ForceRenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to force renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

static int link_force_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int index, i, k = 0, r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        for (i = 1; i < argc; i++) {
                index = resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = link_force_renew_one(bus, index, argv[i]);
                if (r < 0 && k >= 0)
                        k = r;
        }

        return k;
}

static int verb_reload(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        r = bus_call_method(bus, bus_network_mgr, "Reload", &error, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload network settings: %m");

        return 0;
}

static int verb_reconfigure(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, i, r;
        void *p;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (i = 1; i < argc; i++) {
                index = resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = bus_call_method(bus, bus_network_mgr, "ReconfigureLink", &error, NULL, "i", index);
                if (r < 0) {
                        char ifname[IF_NAMESIZE + 1];

                        return log_error_errno(r, "Failed to reconfigure network interface %s: %m",
                                               format_ifname_full(index, ifname, FORMAT_IFNAME_IFINDEX));
                }
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("networkctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sQuery and control the networking subsystem.%s\n"
               "\nCommands:\n"
               "  list [PATTERN...]      List links\n"
               "  status [PATTERN...]    Show link status\n"
               "  lldp [PATTERN...]      Show LLDP neighbors\n"
               "  label                  Show current address label entries in the kernel\n"
               "  delete DEVICES...      Delete virtual netdevs\n"
               "  up DEVICES...          Bring devices up\n"
               "  down DEVICES...        Bring devices down\n"
               "  renew DEVICES...       Renew dynamic configurations\n"
               "  forcerenew DEVICES...  Trigger DHCP reconfiguration of all connected clients\n"
               "  reconfigure DEVICES... Reconfigure interfaces\n"
               "  reload                 Reload .network and .netdev files\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-legend         Do not show the headers and footers\n"
               "  -a --all               Show status for all links\n"
               "  -s --stats             Show detailed link statics\n"
               "  -l --full              Do not ellipsize output\n"
               "  -n --lines=INTEGER     Number of journal entries to show\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , ansi_highlight()
               , ansi_normal()
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend", no_argument,       NULL, ARG_NO_LEGEND },
                { "all",       no_argument,       NULL, 'a'           },
                { "stats",     no_argument,       NULL, 's'           },
                { "full",      no_argument,       NULL, 'l'           },
                { "lines",     required_argument, NULL, 'n'           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hasln:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 's':
                        arg_stats = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'", optarg);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int networkctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list",        VERB_ANY, VERB_ANY, VERB_DEFAULT, list_links          },
                { "status",      VERB_ANY, VERB_ANY, 0,            link_status         },
                { "lldp",        VERB_ANY, VERB_ANY, 0,            link_lldp_status    },
                { "label",       1,        1,        0,            list_address_labels },
                { "delete",      2,        VERB_ANY, 0,            link_delete         },
                { "up",          2,        VERB_ANY, 0,            link_up_down        },
                { "down",        2,        VERB_ANY, 0,            link_up_down        },
                { "renew",       2,        VERB_ANY, 0,            link_renew          },
                { "forcerenew",  2,        VERB_ANY, 0,            link_force_renew    },
                { "reconfigure", 2,        VERB_ANY, 0,            verb_reconfigure    },
                { "reload",      1,        1,        0,            verb_reload         },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static void warn_networkd_missing(void) {

        if (access("/run/systemd/netif/state", F_OK) >= 0)
                return;

        fprintf(stderr, "WARNING: systemd-networkd is not running, output will be incomplete.\n\n");
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup_cli();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        warn_networkd_missing();

        return networkctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "sd-lldp-rx.h"
#include "sd-netlink.h"
#include "sd-network.h"

#include "alloc-util.h"
#include "bond-util.h"
#include "bridge-util.h"
#include "build.h"
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
#include "fs-util.h"
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
#include "netif-util.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "network-util.h"
#include "networkctl.h"
#include "networkctl-config-file.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pretty-print.h"
#include "set.h"
#include "sigbus.h"
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
#include "udev-util.h"
#include "unit-def.h"
#include "varlink.h"
#include "verbs.h"
#include "wifi-util.h"

/* Kernel defines MODULE_NAME_LEN as 64 - sizeof(unsigned long). So, 64 is enough. */
#define NETDEV_KIND_MAX 64

/* use 128 kB for receive socket kernel queue, we shouldn't need more here */
#define RCVBUF_SIZE    (128*1024)

PagerFlags arg_pager_flags = 0;
bool arg_legend = true;
bool arg_no_reload = false;
bool arg_all = false;
bool arg_stats = false;
bool arg_full = false;
bool arg_runtime = false;
unsigned arg_lines = 10;
char *arg_drop_in = NULL;
JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;

STATIC_DESTRUCTOR_REGISTER(arg_drop_in, freep);

static int check_netns_match(void) {
        struct stat st;
        uint64_t id;
        JsonVariant *reply = NULL;
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        int r;

        r = varlink_connect_address(&vl, "/run/systemd/netif/io.systemd.Network");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to network service /run/systemd/netif/io.systemd.Network: %m");

        r = varlink_call(vl, "io.systemd.Network.GetNamespaceId", NULL, &reply, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to issue GetNamespaceId() varlink call: %m");

        static const JsonDispatch dispatch_table[] = {
                { "NamespaceId", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, 0, JSON_MANDATORY },
                {},
        };

        r = json_dispatch(reply, dispatch_table, JSON_LOG, &id);
        if (r < 0)
                return r;

        if (id == 0) {
                log_debug("systemd-networkd.service not running in a network namespace (?), skipping netns check.");
                return 0;
        }

        if (stat("/proc/self/ns/net", &st) < 0)
                return log_error_errno(errno, "Failed to determine our own network namespace ID: %m");

        if (id != st.st_ino)
                return log_error_errno(SYNTHETIC_ERRNO(EREMOTE),
                                       "networkctl must be invoked in same network namespace as systemd-networkd.service.");

        return 0;
}

bool networkd_is_running(void) {
        static int cached = -1;
        int r;

        if (cached < 0) {
                r = access("/run/systemd/netif/state", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno,
                                                "Failed to determine whether networkd is running, assuming it's not: %m");

                        cached = false;
                } else
                        cached = true;
        }

        return cached;
}

int acquire_bus(sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        if (networkd_is_running()) {
                r = check_netns_match();
                if (r < 0)
                        return r;
        } else
                log_warning("systemd-networkd is not running, output might be incomplete.");

        *ret = TAKE_PTR(bus);
        return 0;
}

static int get_description(sd_bus *bus, JsonVariant **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *text;
        int r;

        assert(bus);
        assert(ret);

        r = bus_call_method(bus, bus_network_mgr, "Describe", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get description: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        r = json_parse(text, 0, ret, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        return 0;
}

static int dump_manager_description(sd_bus *bus) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(bus);

        r = get_description(bus, &v);
        if (r < 0)
                return r;

        json_variant_dump(v, arg_json_format_flags, NULL, NULL);
        return 0;
}

static int dump_link_description(sd_bus *bus, char * const *patterns) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ bool *matched_patterns = NULL;
        JsonVariant *i;
        size_t c = 0;
        int r;

        assert(bus);
        assert(patterns);

        r = get_description(bus, &v);
        if (r < 0)
                return r;

        matched_patterns = new0(bool, strv_length(patterns));
        if (!matched_patterns)
                return log_oom();

        JSON_VARIANT_ARRAY_FOREACH(i, json_variant_by_key(v, "Interfaces")) {
                char ifindex_str[DECIMAL_STR_MAX(int64_t)];
                const char *name;
                int64_t index;
                size_t pos;

                name = json_variant_string(json_variant_by_key(i, "Name"));
                index = json_variant_integer(json_variant_by_key(i, "Index"));
                xsprintf(ifindex_str, "%" PRIi64, index);

                if (!strv_fnmatch_full(patterns, ifindex_str, 0, &pos) &&
                    !strv_fnmatch_full(patterns, name, 0, &pos)) {
                        bool match = false;
                        JsonVariant *a;

                        JSON_VARIANT_ARRAY_FOREACH(a, json_variant_by_key(i, "AlternativeNames"))
                                if (strv_fnmatch_full(patterns, json_variant_string(a), 0, &pos)) {
                                        match = true;
                                        break;
                                }

                        if (!match)
                                continue;
                }

                matched_patterns[pos] = true;
                json_variant_dump(i, arg_json_format_flags, NULL, NULL);
                c++;
        }

        /* Look if we matched all our arguments that are not globs. It is OK for a glob to match
         * nothing, but not for an exact argument. */
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

        if (c == 0)
                log_warning("No interfaces matched.");

        return 0;
}

static void operational_state_to_color(
                const char *name,
                const char *state,
                const char **on,
                const char **off) {

        if (STRPTR_IN_SET(state, "routable", "enslaved") ||
            (streq_ptr(name, "lo") && streq_ptr(state, "carrier"))) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "degraded")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
}

static void setup_state_to_color(const char *state, const char **on, const char **off) {
        if (streq_ptr(state, "configured")) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "configuring")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else if (STRPTR_IN_SET(state, "failed", "linger")) {
                if (on)
                        *on = ansi_highlight_red();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
}

static void online_state_to_color(const char *state, const char **on, const char **off) {
        if (streq_ptr(state, "online")) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "partial")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
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
        uint8_t rsc;
        uint8_t l2miss;
        uint8_t l3miss;
        uint8_t tos;
        uint8_t ttl;
} VxLanInfo;

typedef struct LinkInfo {
        char name[IFNAMSIZ+1];
        char *netdev_kind;
        sd_device *sd_device;
        int ifindex;
        unsigned short iftype;
        struct hw_addr_data hw_address;
        struct hw_addr_data permanent_hw_address;
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

        bool has_hw_address:1;
        bool has_permanent_hw_address:1;
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

static LinkInfo* link_info_array_free(LinkInfo *array) {
        for (unsigned i = 0; array && array[i].needs_freeing; i++) {
                sd_device_unref(array[i].sd_device);
                free(array[i].netdev_kind);
                free(array[i].ssid);
                free(array[i].qdisc);
                strv_free(array[i].alternative_names);
        }

        return mfree(array);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_array_free);

static int decode_netdev(sd_netlink_message *m, LinkInfo *info) {
        int r;

        assert(m);
        assert(info);

        r = sd_netlink_message_enter_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(m, IFLA_INFO_KIND, &info->netdev_kind);
        if (r < 0) {
                (void) sd_netlink_message_exit_container(m);
                return r;
        }

        r = sd_netlink_message_enter_container(m, IFLA_INFO_DATA);
        if (r < 0)
                return r;

        if (streq(info->netdev_kind, "bridge")) {
                (void) sd_netlink_message_read_u32(m, IFLA_BR_FORWARD_DELAY, &info->forward_delay);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_HELLO_TIME, &info->hello_time);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_MAX_AGE, &info->max_age);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_AGEING_TIME, &info->ageing_time);
                (void) sd_netlink_message_read_u32(m, IFLA_BR_STP_STATE, &info->stp_state);
                (void) sd_netlink_message_read_u32(m, IFLA_BRPORT_COST, &info->cost);
                (void) sd_netlink_message_read_u16(m, IFLA_BR_PRIORITY, &info->priority);
                (void) sd_netlink_message_read_u8(m, IFLA_BR_MCAST_IGMP_VERSION, &info->mcast_igmp_version);
                (void) sd_netlink_message_read_u8(m, IFLA_BRPORT_STATE, &info->port_state);
        } if (streq(info->netdev_kind, "bond")) {
                (void) sd_netlink_message_read_u8(m, IFLA_BOND_MODE, &info->mode);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_MIIMON, &info->miimon);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_DOWNDELAY, &info->downdelay);
                (void) sd_netlink_message_read_u32(m, IFLA_BOND_UPDELAY, &info->updelay);
        } else if (streq(info->netdev_kind, "vxlan")) {
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
        } else if (streq(info->netdev_kind, "vlan"))
                (void) sd_netlink_message_read_u16(m, IFLA_VLAN_ID, &info->vlan_id);
        else if (STR_IN_SET(info->netdev_kind, "ipip", "sit")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_IPTUN_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_IPTUN_REMOTE, &info->remote.in);
        } else if (streq(info->netdev_kind, "geneve")) {
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
        } else if (STR_IN_SET(info->netdev_kind, "gre", "gretap", "erspan")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_GRE_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_GRE_REMOTE, &info->remote.in);
        } else if (STR_IN_SET(info->netdev_kind, "ip6gre", "ip6gretap", "ip6erspan")) {
                (void) sd_netlink_message_read_in6_addr(m, IFLA_GRE_LOCAL, &info->local.in6);
                (void) sd_netlink_message_read_in6_addr(m, IFLA_GRE_REMOTE, &info->remote.in6);
        } else if (streq(info->netdev_kind, "vti")) {
                (void) sd_netlink_message_read_in_addr(m, IFLA_VTI_LOCAL, &info->local.in);
                (void) sd_netlink_message_read_in_addr(m, IFLA_VTI_REMOTE, &info->remote.in);
        } else if (streq(info->netdev_kind, "vti6")) {
                (void) sd_netlink_message_read_in6_addr(m, IFLA_VTI_LOCAL, &info->local.in6);
                (void) sd_netlink_message_read_in6_addr(m, IFLA_VTI_REMOTE, &info->remote.in6);
        } else if (STR_IN_SET(info->netdev_kind, "macvlan", "macvtap"))
                (void) sd_netlink_message_read_u32(m, IFLA_MACVLAN_MODE, &info->macvlan_mode);
        else if (streq(info->netdev_kind, "ipvlan")) {
                (void) sd_netlink_message_read_u16(m, IFLA_IPVLAN_MODE, &info->ipvlan_mode);
                (void) sd_netlink_message_read_u16(m, IFLA_IPVLAN_FLAGS, &info->ipvlan_flags);
        }

        (void) sd_netlink_message_exit_container(m);
        (void) sd_netlink_message_exit_container(m);

        return 0;
}

static int decode_link(
                sd_netlink_message *m,
                LinkInfo *info,
                char * const *patterns,
                bool matched_patterns[]) {

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

        info->has_hw_address =
                netlink_message_read_hw_addr(m, IFLA_ADDRESS, &info->hw_address) >= 0 &&
                info->hw_address.length > 0;

        info->has_permanent_hw_address =
                (netlink_message_read_hw_addr(m, IFLA_PERM_ADDRESS, &info->permanent_hw_address) >= 0 ||
                 ethtool_get_permanent_hw_addr(NULL, info->name, &info->permanent_hw_address) >= 0) &&
                !hw_addr_is_null(&info->permanent_hw_address) &&
                !hw_addr_equal(&info->permanent_hw_address, &info->hw_address);

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
                const char *propname,
                const char *type) {

        _cleanup_free_ char *path = NULL;
        char ifindex_str[DECIMAL_STR_MAX(int)];
        int r;

        assert(bus);
        assert(link);
        assert(link->ifindex >= 0);
        assert(error);
        assert(reply);
        assert(iface);
        assert(propname);
        assert(type);

        xsprintf(ifindex_str, "%i", link->ifindex);

        r = sd_bus_path_encode("/org/freedesktop/network1/link", ifindex_str, &path);
        if (r < 0)
                return r;

        return sd_bus_get_property(bus, "org.freedesktop.network1", path, iface, propname, error, reply, type);
}

static int acquire_link_bitrates(sd_bus *bus, LinkInfo *link) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(link);

        r = link_get_property(bus, link, &error, &reply, "org.freedesktop.network1.Link", "BitRates", "(tt)");
        if (r < 0) {
                bool quiet = sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                                            BUS_ERROR_SPEED_METER_INACTIVE);

                return log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING,
                                      r, "Failed to query link bit rates: %s", bus_error_message(&error, r));
        }

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
        assert(fd);
        assert(link);

        if (ethtool_get_link_info(fd,
                                  link->name,
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

        assert(link);

        if (link->sd_device)
                (void) sd_device_get_devtype(link->sd_device, &type);
        if (!streq_ptr(type, "wlan"))
                return;

        r = sd_genl_socket_open(&genl);
        if (r < 0) {
                log_debug_errno(r, "Failed to open generic netlink socket: %m");
                return;
        }

        (void) sd_netlink_increase_rxbuf(genl, RCVBUF_SIZE);

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

static int acquire_link_info(sd_bus *bus, sd_netlink *rtnl, char * const *patterns, LinkInfo **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_free_ bool *matched_patterns = NULL;
        _cleanup_close_ int fd = -EBADF;
        size_t c = 0;
        int r;

        assert(rtnl);
        assert(ret);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate links: %m");

        if (patterns) {
                matched_patterns = new0(bool, strv_length(patterns));
                if (!matched_patterns)
                        return log_oom();
        }

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                if (!GREEDY_REALLOC0(links, c + 2)) /* We keep one trailing one as marker */
                        return -ENOMEM;

                r = decode_link(i, links + c, patterns, matched_patterns);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                links[c].needs_freeing = true;

                (void) sd_device_new_from_ifindex(&links[c].sd_device, links[c].ifindex);

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
                FOREACH_ARRAY(link, links, c)
                        (void) acquire_link_bitrates(bus, link);

        *ret = TAKE_PTR(links);

        if (patterns && c == 0)
                log_warning("No interfaces matched.");

        return (int) c;
}

static int list_links(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int c, r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (arg_json_format_flags != JSON_FORMAT_OFF) {
                if (arg_all || argc <= 1)
                        return dump_manager_description(bus);
                else
                        return dump_link_description(bus, strv_skip(argv, 1));
        }

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        c = acquire_link_info(NULL, rtnl, argc > 1 ? argv + 1 : NULL, &links);
        if (c < 0)
                return c;

        pager_open(arg_pager_flags);

        table = table_new("idx", "link", "type", "operational", "setup");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        table_set_header(table, arg_legend);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_minimum_width(table, cell, 3);
        (void) table_set_weight(table, cell, 0);
        (void) table_set_ellipsize_percent(table, cell, 100);
        (void) table_set_align_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_ellipsize_percent(table, cell, 100);

        FOREACH_ARRAY(link, links, c) {
                _cleanup_free_ char *setup_state = NULL, *operational_state = NULL;
                _cleanup_free_ char *t = NULL;
                const char *on_color_operational, *on_color_setup;

                (void) sd_network_link_get_operational_state(link->ifindex, &operational_state);
                operational_state_to_color(link->name, operational_state, &on_color_operational, NULL);

                (void) sd_network_link_get_setup_state(link->ifindex, &setup_state);
                setup_state_to_color(setup_state, &on_color_setup, NULL);

                r = net_get_type_string(link->sd_device, link->iftype, &t);
                if (r == -ENOMEM)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_INT, link->ifindex,
                                   TABLE_STRING, link->name,
                                   TABLE_STRING, t,
                                   TABLE_STRING, operational_state,
                                   TABLE_SET_COLOR, on_color_operational,
                                   TABLE_STRING, setup_state ?: "unmanaged",
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
        _cleanup_free_ char *desc = NULL;
        const char *description;
        char modalias[STRLEN("OUI:XXYYXXYYXXYY") + 1];
        int r;

        assert(ret);

        if (!hwdb || !mac)
                return -EINVAL;

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (memcmp(mac, "\0\0\0", 3) == 0)
                return -EINVAL;

        xsprintf(modalias, "OUI:" ETHER_ADDR_FORMAT_STR, ETHER_ADDR_FORMAT_VAL(*mac));

        r = sd_hwdb_get(hwdb, modalias, "ID_OUI_FROM_DATABASE", &description);
        if (r < 0)
                return r;

        desc = strdup(description);
        if (!desc)
                return -ENOMEM;

        *ret = TAKE_PTR(desc);

        return 0;
}

static int get_gateway_description(
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                int ifindex,
                int family,
                union in_addr_union *gateway,
                char **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(rtnl);
        assert(ifindex >= 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(gateway);
        assert(ret);

        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_GETNEIGH, ifindex, family);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union gw = IN_ADDR_NULL;
                struct ether_addr mac = ETHER_ADDR_NULL;
                uint16_t type;
                int ifi, fam;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message type, ignoring: %m");
                        continue;
                }

                if (type != RTM_NEWNEIGH) {
                        log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Got unexpected netlink message type %u, ignoring",
                                        type);
                        continue;
                }

                r = sd_rtnl_message_neigh_get_family(m, &fam);
                if (r < 0) {
                        log_error_errno(r, "Failed to get rtnl family, ignoring: %m");
                        continue;
                }

                if (fam != family) {
                        log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Got invalid rtnl family %d, ignoring", fam);
                        continue;
                }

                r = sd_rtnl_message_neigh_get_ifindex(m, &ifi);
                if (r < 0) {
                        log_error_errno(r, "Failed to get rtnl ifindex, ignoring: %m");
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

                r = ieee_oui(hwdb, &mac, ret);
                if (r < 0)
                        continue;

                return 0;
        }

        return -ENODATA;
}

static int dump_list(Table *table, const char *key, char * const *l) {
        int r;

        assert(table);
        assert(key);

        if (strv_isempty(l))
                return 0;

        r = table_add_many(table,
                           TABLE_FIELD, key,
                           TABLE_STRV, l);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_gateways(sd_netlink *rtnl, sd_hwdb *hwdb, Table *table, int ifindex) {
        _cleanup_free_ struct local_address *local_addrs = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        int r, n;

        assert(rtnl);
        assert(table);

        n = local_gateways(rtnl, ifindex, AF_UNSPEC, &local_addrs);
        if (n <= 0)
                return n;

        FOREACH_ARRAY(local, local_addrs, n) {
                _cleanup_free_ char *description = NULL;

                r = get_gateway_description(rtnl, hwdb, local->ifindex, local->family, &local->address, &description);
                if (r < 0)
                        log_debug_errno(r, "Could not get description of gateway, ignoring: %m");

                /* Show interface name for the entry if we show entries for all interfaces */
                r = strv_extendf(&buf, "%s%s%s%s%s%s",
                                 IN_ADDR_TO_STRING(local->family, &local->address),
                                 description ? " (" : "",
                                 strempty(description),
                                 description ? ")" : "",
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? FORMAT_IFNAME_FULL(local->ifindex, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Gateway", buf);
}

static int dump_addresses(
                sd_netlink *rtnl,
                sd_dhcp_lease *lease,
                Table *table,
                int ifindex) {

        _cleanup_free_ struct local_address *local_addrs = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        struct in_addr dhcp4_address = {};
        int r, n;

        assert(rtnl);
        assert(table);

        n = local_addresses(rtnl, ifindex, AF_UNSPEC, &local_addrs);
        if (n <= 0)
                return n;

        if (lease)
                (void) sd_dhcp_lease_get_address(lease, &dhcp4_address);

        FOREACH_ARRAY(local, local_addrs, n) {
                struct in_addr server_address;
                bool dhcp4 = false;

                if (local->family == AF_INET && in4_addr_equal(&local->address.in, &dhcp4_address))
                        dhcp4 = sd_dhcp_lease_get_server_identifier(lease, &server_address) >= 0;

                r = strv_extendf(&buf, "%s%s%s%s%s%s",
                                 IN_ADDR_TO_STRING(local->family, &local->address),
                                 dhcp4 ? " (DHCP4 via " : "",
                                 dhcp4 ? IN4_ADDR_TO_STRING(&server_address) : "",
                                 dhcp4 ? ")" : "",
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? FORMAT_IFNAME_FULL(local->ifindex, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Address", buf);
}

static int dump_address_labels(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int r;

        assert(rtnl);

        r = sd_rtnl_message_new_addrlabel(rtnl, &req, RTM_GETADDRLABEL, 0, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_GETADDRLABEL message: %m");

        r = sd_netlink_message_set_request_dump(req, true);
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

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return r;

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_align_percent(table, cell, 100);

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                struct in6_addr prefix;
                uint8_t prefixlen;
                uint32_t label;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_read_u32(m, IFAL_LABEL, &label);
                if (r < 0 && r != -ENODATA) {
                        log_error_errno(r, "Could not read IFAL_LABEL, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_read_in6_addr(m, IFAL_ADDRESS, &prefix);
                if (r < 0)
                        continue;

                r = sd_rtnl_message_addrlabel_get_prefixlen(m, &prefixlen);
                if (r < 0)
                        continue;

                r = table_add_cell(table, NULL, TABLE_UINT32, &label);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%s/%u", IN6_ADDR_TO_STRING(&prefix), prefixlen);
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

        return dump_address_labels(rtnl);
}

static int open_lldp_neighbors(int ifindex, FILE **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        char p[STRLEN("/run/systemd/netif/lldp/") + DECIMAL_STR_MAX(int)];

        assert(ifindex >= 0);
        assert(ret);

        xsprintf(p, "/run/systemd/netif/lldp/%i", ifindex);

        f = fopen(p, "re");
        if (!f)
                return -errno;

        *ret = TAKE_PTR(f);
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

        assert(table);
        assert(prefix);
        assert(bus);
        assert(link);

        r = link_get_property(bus, link, &error, &reply, "org.freedesktop.network1.DHCPServer", "Leases", "a(uayayayayt)");
        if (r < 0) {
                bool quiet = sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY);

                log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING,
                               r, "Failed to query link DHCP leases: %s", bus_error_message(&error, r));
                return 0;
        }

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
        int r;

        assert(table);
        assert(prefix);

        if (!ifindexes)
                return 0;

        for (unsigned c = 0; ifindexes[c] > 0; c++) {
                if (c == 0)
                        r = table_add_cell(table, NULL, TABLE_FIELD, prefix);
                else
                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell(table, NULL, TABLE_IFINDEX, &ifindexes[c]);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return 0;
}

#define DUMP_STATS_ONE(name, val_name)                                          \
        ({                                                                      \
                r = table_add_cell(table, NULL, TABLE_FIELD, name);             \
                if (r < 0)                                                      \
                        return table_log_add_error(r);                          \
                r = table_add_cell(table, NULL,                                 \
                                   info->has_stats64 ? TABLE_UINT64 : TABLE_UINT32, \
                                   info->has_stats64 ? (void*) &info->stats64.val_name : (void*) &info->stats.val_name); \
                if (r < 0)                                                      \
                        return table_log_add_error(r);                          \
        })

static int dump_statistics(Table *table, const LinkInfo *info) {
        int r;

        assert(table);
        assert(info);

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

static int dump_hw_address(Table *table, sd_hwdb *hwdb, const char *field, const struct hw_addr_data *addr) {
        _cleanup_free_ char *description = NULL;
        int r;

        assert(table);
        assert(field);
        assert(addr);

        if (addr->length == ETH_ALEN)
                (void) ieee_oui(hwdb, &addr->ether, &description);

        r = table_add_cell(table, NULL, TABLE_FIELD, field);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_cell_stringf(table, NULL, "%s%s%s%s",
                                   HW_ADDR_TO_STR(addr),
                                   description ? " (" : "",
                                   strempty(description),
                                   description ? ")" : "");
        if (r < 0)
                return table_log_add_error(r);

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

static int table_add_string_line(Table *table, const char *key, const char *value) {
        int r;

        assert(table);
        assert(key);

        if (isempty(value))
                return 0;

        r = table_add_many(table,
                           TABLE_FIELD, key,
                           TABLE_STRING, value);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int format_dropins(char **dropins) {
        STRV_FOREACH(d, dropins) {
                _cleanup_free_ char *s = NULL;
                int glyph = *(d + 1) == NULL ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH;

                s = strjoin(special_glyph(glyph), *d);
                if (!s)
                        return log_oom();

                free_and_replace(*d, s);
        }

        return 0;
}

static int link_status_one(
                sd_bus *bus,
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                const LinkInfo *info) {

        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL, **sip = NULL, **search_domains = NULL,
                **route_domains = NULL, **link_dropins = NULL, **network_dropins = NULL;
        _cleanup_free_ char *t = NULL, *network = NULL, *iaid = NULL, *duid = NULL, *captive_portal = NULL,
                *setup_state = NULL, *operational_state = NULL, *online_state = NULL, *activation_policy = NULL;
        const char *driver = NULL, *path = NULL, *vendor = NULL, *model = NULL, *link = NULL,
                *on_color_operational, *off_color_operational, *on_color_setup, *off_color_setup, *on_color_online;
        _cleanup_free_ int *carrier_bound_to = NULL, *carrier_bound_by = NULL;
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(bus);
        assert(rtnl);
        assert(info);

        (void) sd_network_link_get_operational_state(info->ifindex, &operational_state);
        operational_state_to_color(info->name, operational_state, &on_color_operational, &off_color_operational);

        (void) sd_network_link_get_online_state(info->ifindex, &online_state);
        online_state_to_color(online_state, &on_color_online, NULL);

        (void) sd_network_link_get_setup_state(info->ifindex, &setup_state);
        setup_state_to_color(setup_state, &on_color_setup, &off_color_setup);

        (void) sd_network_link_get_dns(info->ifindex, &dns);
        (void) sd_network_link_get_search_domains(info->ifindex, &search_domains);
        (void) sd_network_link_get_route_domains(info->ifindex, &route_domains);
        (void) sd_network_link_get_ntp(info->ifindex, &ntp);
        (void) sd_network_link_get_sip(info->ifindex, &sip);
        (void) sd_network_link_get_captive_portal(info->ifindex, &captive_portal);
        (void) sd_network_link_get_network_file(info->ifindex, &network);
        (void) sd_network_link_get_network_file_dropins(info->ifindex, &network_dropins);
        (void) sd_network_link_get_carrier_bound_to(info->ifindex, &carrier_bound_to);
        (void) sd_network_link_get_carrier_bound_by(info->ifindex, &carrier_bound_by);
        (void) sd_network_link_get_activation_policy(info->ifindex, &activation_policy);

        if (info->sd_device) {
                const char *joined;

                (void) sd_device_get_property_value(info->sd_device, "ID_NET_LINK_FILE", &link);

                if (sd_device_get_property_value(info->sd_device, "ID_NET_LINK_FILE_DROPINS", &joined) >= 0) {
                        r = strv_split_full(&link_dropins, joined, ":", EXTRACT_CUNESCAPE);
                        if (r < 0)
                                return r;
                }

                (void) sd_device_get_property_value(info->sd_device, "ID_NET_DRIVER", &driver);
                (void) sd_device_get_property_value(info->sd_device, "ID_PATH", &path);
                (void) device_get_vendor_string(info->sd_device, &vendor);
                (void) device_get_model_string(info->sd_device, &model);
        }

        r = net_get_type_string(info->sd_device, info->iftype, &t);
        if (r == -ENOMEM)
                return log_oom();

        char lease_file[STRLEN("/run/systemd/netif/leases/") + DECIMAL_STR_MAX(int)];
        xsprintf(lease_file, "/run/systemd/netif/leases/%i", info->ifindex);

        (void) dhcp_lease_load(&lease, lease_file);

        r = format_dropins(network_dropins);
        if (r < 0)
                return r;

        if (strv_prepend(&network_dropins, network) < 0)
                return log_oom();

        r = format_dropins(link_dropins);
        if (r < 0)
                return r;

        if (strv_prepend(&link_dropins, link) < 0)
                return log_oom();

        table = table_new_vertical();
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        /* unit files and basic states. */
        r = table_add_many(table,
                           TABLE_FIELD, "Link File",
                           TABLE_STRV, link_dropins ?: STRV_MAKE("n/a"),
                           TABLE_FIELD, "Network File",
                           TABLE_STRV, network_dropins ?: STRV_MAKE("n/a"),
                           TABLE_FIELD, "State");
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_cell_stringf(table, NULL, "%s%s%s (%s%s%s)",
                                   on_color_operational, strna(operational_state), off_color_operational,
                                   on_color_setup, setup_state ?: "unmanaged", off_color_setup);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(table,
                           TABLE_FIELD, "Online state",
                           TABLE_STRING, online_state ?: "unknown",
                           TABLE_SET_COLOR, on_color_online);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_string_line(table, "Type", t);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Kind", info->netdev_kind);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Path", path);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Driver", driver);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Vendor", vendor);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Model", model);
        if (r < 0)
                return r;

        strv_sort(info->alternative_names);
        r = dump_list(table, "Alternative Names", info->alternative_names);
        if (r < 0)
                return r;

        if (info->has_hw_address) {
                r = dump_hw_address(table, hwdb, "Hardware Address", &info->hw_address);
                if (r < 0)
                        return r;
        }

        if (info->has_permanent_hw_address) {
                r = dump_hw_address(table, hwdb, "Permanent Hardware Address", &info->permanent_hw_address);
                if (r < 0)
                        return r;
        }

        if (info->mtu > 0) {
                char min_str[DECIMAL_STR_MAX(uint32_t)], max_str[DECIMAL_STR_MAX(uint32_t)];

                xsprintf(min_str, "%" PRIu32, info->min_mtu);
                xsprintf(max_str, "%" PRIu32, info->max_mtu);

                r = table_add_cell(table, NULL, TABLE_FIELD, "MTU");
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

        r = table_add_string_line(table, "QDisc", info->qdisc);
        if (r < 0)
                return r;

        if (info->master > 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Master",
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
                                   TABLE_FIELD, "IPv6 Address Generation Mode",
                                   TABLE_STRING, mode_table[info->addr_gen_mode]);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (streq_ptr(info->netdev_kind, "bridge")) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Forward Delay",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->forward_delay),
                                   TABLE_FIELD, "Hello Time",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->hello_time),
                                   TABLE_FIELD, "Max Age",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->max_age),
                                   TABLE_FIELD, "Ageing Time",
                                   TABLE_TIMESPAN_MSEC, jiffies_to_usec(info->ageing_time),
                                   TABLE_FIELD, "Priority",
                                   TABLE_UINT16, info->priority,
                                   TABLE_FIELD, "STP",
                                   TABLE_BOOLEAN, info->stp_state > 0,
                                   TABLE_FIELD, "Multicast IGMP Version",
                                   TABLE_UINT8, info->mcast_igmp_version,
                                   TABLE_FIELD, "Cost",
                                   TABLE_UINT32, info->cost);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->port_state <= BR_STATE_BLOCKING) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Port State",
                                           TABLE_STRING, bridge_state_to_string(info->port_state));
                        if (r < 0)
                                return table_log_add_error(r);
                }

        } else if (streq_ptr(info->netdev_kind, "bond")) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Mode",
                                   TABLE_STRING, bond_mode_to_string(info->mode),
                                   TABLE_FIELD, "Miimon",
                                   TABLE_TIMESPAN_MSEC, info->miimon * USEC_PER_MSEC,
                                   TABLE_FIELD, "Updelay",
                                   TABLE_TIMESPAN_MSEC, info->updelay * USEC_PER_MSEC,
                                   TABLE_FIELD, "Downdelay",
                                   TABLE_TIMESPAN_MSEC, info->downdelay * USEC_PER_MSEC);
                if (r < 0)
                        return table_log_add_error(r);

        } else if (streq_ptr(info->netdev_kind, "vxlan")) {
                char ttl[CONST_MAX(STRLEN("auto") + 1, DECIMAL_STR_MAX(uint8_t))];

                if (info->vxlan_info.vni > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "VNI",
                                           TABLE_UINT32, info->vxlan_info.vni);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (IN_SET(info->vxlan_info.group_family, AF_INET, AF_INET6)) {
                        const char *p;

                        r = in_addr_is_multicast(info->vxlan_info.group_family, &info->vxlan_info.group);
                        if (r <= 0)
                                p = "Remote";
                        else
                                p = "Group";

                        r = table_add_many(table,
                                           TABLE_FIELD, p,
                                           info->vxlan_info.group_family == AF_INET ? TABLE_IN_ADDR : TABLE_IN6_ADDR, &info->vxlan_info.group);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (IN_SET(info->vxlan_info.local_family, AF_INET, AF_INET6)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Local",
                                           info->vxlan_info.local_family == AF_INET ? TABLE_IN_ADDR : TABLE_IN6_ADDR, &info->vxlan_info.local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.dest_port > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Destination Port",
                                           TABLE_UINT16, be16toh(info->vxlan_info.dest_port));
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.link > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Underlying Device",
                                           TABLE_IFINDEX, info->vxlan_info.link);
                        if (r < 0)
                                 return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_FIELD, "Learning",
                                   TABLE_BOOLEAN, info->vxlan_info.learning,
                                   TABLE_FIELD, "RSC",
                                   TABLE_BOOLEAN, info->vxlan_info.rsc,
                                   TABLE_FIELD, "L3MISS",
                                   TABLE_BOOLEAN, info->vxlan_info.l3miss,
                                   TABLE_FIELD, "L2MISS",
                                   TABLE_BOOLEAN, info->vxlan_info.l2miss);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->vxlan_info.tos > 1) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "TOS",
                                           TABLE_UINT8, info->vxlan_info.tos);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->vxlan_info.ttl > 0)
                        xsprintf(ttl, "%" PRIu8, info->vxlan_info.ttl);
                else
                        strcpy(ttl, "auto");

                r = table_add_many(table,
                                   TABLE_FIELD, "TTL",
                                   TABLE_STRING, ttl);
                if (r < 0)
                        return table_log_add_error(r);

        } else if (streq_ptr(info->netdev_kind, "vlan") && info->vlan_id > 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "VLan Id",
                                   TABLE_UINT16, info->vlan_id);
                if (r < 0)
                        return table_log_add_error(r);

        } else if (STRPTR_IN_SET(info->netdev_kind, "ipip", "sit", "gre", "gretap", "erspan", "vti")) {
                if (in_addr_is_set(AF_INET, &info->local)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Local",
                                           TABLE_IN_ADDR, &info->local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (in_addr_is_set(AF_INET, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Remote",
                                           TABLE_IN_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }

        } else if (STRPTR_IN_SET(info->netdev_kind, "ip6gre", "ip6gretap", "ip6erspan", "vti6")) {
                if (in_addr_is_set(AF_INET6, &info->local)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Local",
                                           TABLE_IN6_ADDR, &info->local);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (in_addr_is_set(AF_INET6, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Remote",
                                           TABLE_IN6_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }

        } else if (streq_ptr(info->netdev_kind, "geneve")) {
                r = table_add_many(table,
                                   TABLE_FIELD, "VNI",
                                   TABLE_UINT32, info->vni);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->has_tunnel_ipv4 && in_addr_is_set(AF_INET, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Remote",
                                           TABLE_IN_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                } else if (in_addr_is_set(AF_INET6, &info->remote)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Remote",
                                           TABLE_IN6_ADDR, &info->remote);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->ttl > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "TTL",
                                           TABLE_UINT8, info->ttl);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->tos > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "TOS",
                                           TABLE_UINT8, info->tos);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_FIELD, "Port",
                                   TABLE_UINT16, info->tunnel_port,
                                   TABLE_FIELD, "Inherit",
                                   TABLE_STRING, geneve_df_to_string(info->inherit));
                if (r < 0)
                        return table_log_add_error(r);

                if (info->df > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "IPDoNotFragment",
                                           TABLE_UINT8, info->df);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_FIELD, "UDPChecksum",
                                   TABLE_BOOLEAN, info->csum,
                                   TABLE_FIELD, "UDP6ZeroChecksumTx",
                                   TABLE_BOOLEAN, info->csum6_tx,
                                   TABLE_FIELD, "UDP6ZeroChecksumRx",
                                   TABLE_BOOLEAN, info->csum6_rx);
                if (r < 0)
                        return table_log_add_error(r);

                if (info->label > 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "FlowLabel",
                                           TABLE_UINT32, info->label);
                        if (r < 0)
                                return table_log_add_error(r);
                }

        } else if (STRPTR_IN_SET(info->netdev_kind, "macvlan", "macvtap")) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Mode",
                                   TABLE_STRING, macvlan_mode_to_string(info->macvlan_mode));
                if (r < 0)
                        return table_log_add_error(r);

        } else if (streq_ptr(info->netdev_kind, "ipvlan")) {
                const char *p;

                if (info->ipvlan_flags & IPVLAN_F_PRIVATE)
                        p = "private";
                else if (info->ipvlan_flags & IPVLAN_F_VEPA)
                        p = "vepa";
                else
                        p = "bridge";

                r = table_add_cell(table, NULL, TABLE_FIELD, "Mode");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%s (%s)",
                                           ipvlan_mode_to_string(info->ipvlan_mode), p);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_wlan_link_info) {
                _cleanup_free_ char *esc = NULL;

                r = table_add_cell(table, NULL, TABLE_FIELD, "Wi-Fi access point");
                if (r < 0)
                        return table_log_add_error(r);

                if (info->ssid)
                        esc = cescape(info->ssid);

                r = table_add_cell_stringf(table, NULL, "%s (%s)",
                                           strnull(esc),
                                           ETHER_ADDR_TO_STR(&info->bssid));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_bitrates) {
                r = table_add_cell(table, NULL, TABLE_FIELD, "Bit Rate (Tx/Rx)");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%sbps/%sbps",
                                           FORMAT_BYTES_FULL(info->tx_bitrate, 0),
                                           FORMAT_BYTES_FULL(info->rx_bitrate, 0));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_tx_queues || info->has_rx_queues) {
                r = table_add_cell(table, NULL, TABLE_FIELD, "Number of Queues (Tx/Rx)");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%" PRIu32 "/%" PRIu32, info->tx_queues, info->rx_queues);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info->has_ethtool_link_info) {
                if (IN_SET(info->autonegotiation, AUTONEG_DISABLE, AUTONEG_ENABLE)) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Auto negotiation",
                                           TABLE_BOOLEAN, info->autonegotiation == AUTONEG_ENABLE);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (info->speed > 0 && info->speed != UINT64_MAX) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Speed",
                                           TABLE_BPS, info->speed);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_string_line(table, "Duplex", duplex_to_string(info->duplex));
                if (r < 0)
                        return r;

                r = table_add_string_line(table, "Port", port_to_string(info->port));
                if (r < 0)
                        return r;
        }

        r = dump_addresses(rtnl, lease, table, info->ifindex);
        if (r < 0)
                return r;

        r = dump_gateways(rtnl, hwdb, table, info->ifindex);
        if (r < 0)
                return r;

        r = dump_list(table, "DNS", dns);
        if (r < 0)
                return r;

        r = dump_list(table, "Search Domains", search_domains);
        if (r < 0)
                return r;

        r = dump_list(table, "Route Domains", route_domains);
        if (r < 0)
                return r;

        r = dump_list(table, "NTP", ntp);
        if (r < 0)
                return r;

        r = dump_list(table, "SIP", sip);
        if (r < 0)
                return r;

        r = dump_ifindexes(table, "Carrier Bound To", carrier_bound_to);
        if (r < 0)
                return r;

        r = dump_ifindexes(table, "Carrier Bound By", carrier_bound_by);
        if (r < 0)
                return r;

        r = table_add_string_line(table, "Activation Policy", activation_policy);
        if (r < 0)
                return r;

        r = sd_network_link_get_required_for_online(info->ifindex);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Required For Online",
                                   TABLE_BOOLEAN, r);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (captive_portal) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Captive Portal",
                                   TABLE_STRING, captive_portal,
                                   TABLE_SET_URL, captive_portal);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (lease) {
                const void *client_id;
                size_t client_id_len;
                const char *tz;

                r = sd_dhcp_lease_get_timezone(lease, &tz);
                if (r >= 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Time Zone",
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
                                                   TABLE_FIELD, "DHCP4 Client ID",
                                                   TABLE_STRING, id);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                }
        }

        r = sd_network_link_get_dhcp6_client_iaid_string(info->ifindex, &iaid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "DHCP6 Client IAID",
                                   TABLE_STRING, iaid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_network_link_get_dhcp6_client_duid_string(info->ifindex, &duid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "DHCP6 Client DUID",
                                   TABLE_STRING, duid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = dump_lldp_neighbors(table, "Connected To", info->ifindex);
        if (r < 0)
                return r;

        r = dump_dhcp_leases(table, "Offered DHCP leases", bus, info);
        if (r < 0)
                return r;

        r = dump_statistics(table, info);
        if (r < 0)
                return r;

        /* First line: circle, ifindex, ifname. */
        printf("%s%s%s %d: %s\n",
               on_color_operational, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE), off_color_operational,
               info->ifindex, info->name);

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return show_logs(info);
}

static int system_status(sd_netlink *rtnl, sd_hwdb *hwdb) {
        _cleanup_free_ char *operational_state = NULL, *online_state = NULL, *netifs_joined = NULL;
        _cleanup_strv_free_ char **netifs = NULL, **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        const char *on_color_operational, *off_color_operational, *on_color_online;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(rtnl);

        (void) sd_network_get_operational_state(&operational_state);
        operational_state_to_color(NULL, operational_state, &on_color_operational, &off_color_operational);

        (void) sd_network_get_online_state(&online_state);
        online_state_to_color(online_state, &on_color_online, NULL);

        table = table_new_vertical();
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = get_files_in_directory("/run/systemd/netif/links/", &netifs);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to list network interfaces: %m");
        else if (r > 0) {
                netifs_joined = strv_join(netifs, ", ");
                if (!netifs_joined)
                        return log_oom();
        }

        r = table_add_many(table,
                           TABLE_FIELD, "State",
                           TABLE_STRING, strna(operational_state),
                           TABLE_SET_COLOR, on_color_operational,
                           TABLE_FIELD, "Online state",
                           TABLE_STRING, online_state ?: "unknown",
                           TABLE_SET_COLOR, on_color_online);
        if (r < 0)
                return table_log_add_error(r);

        r = dump_addresses(rtnl, NULL, table, 0);
        if (r < 0)
                return r;

        r = dump_gateways(rtnl, hwdb, table, 0);
        if (r < 0)
                return r;

        (void) sd_network_get_dns(&dns);
        r = dump_list(table, "DNS", dns);
        if (r < 0)
                return r;

        (void) sd_network_get_search_domains(&search_domains);
        r = dump_list(table, "Search Domains", search_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_route_domains(&route_domains);
        r = dump_list(table, "Route Domains", route_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_ntp(&ntp);
        r = dump_list(table, "NTP", ntp);
        if (r < 0)
                return r;

        printf("%s%s%s Interfaces: %s\n",
               on_color_operational, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE), off_color_operational,
               strna(netifs_joined));

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
        int r, c;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (arg_json_format_flags != JSON_FORMAT_OFF) {
                if (arg_all || argc <= 1)
                        return dump_manager_description(bus);
                else
                        return dump_link_description(bus, strv_skip(argv, 1));
        }

        pager_open(arg_pager_flags);

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

        r = 0;

        bool first = true;
        FOREACH_ARRAY(i, links, c) {
                if (!first)
                        putchar('\n');

                RET_GATHER(r, link_status_one(bus, rtnl, hwdb, i));

                first = false;
        }

        return r;
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
        unsigned cols = columns();
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
        for (unsigned w = 0, i = 0; i < ELEMENTSOF(table); i++)
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
        int r, c, m = 0;
        uint16_t all = 0;
        TableCell *cell;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        c = acquire_link_info(NULL, rtnl, argc > 1 ? argv + 1 : NULL, &links);
        if (c < 0)
                return c;

        pager_open(arg_pager_flags);

        table = table_new("link",
                          "chassis-id",
                          "system-name",
                          "caps",
                          "port-id",
                          "port-description");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        table_set_header(table, arg_legend);

        assert_se(cell = table_get_cell(table, 0, 3));
        table_set_minimum_width(table, cell, 11);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        FOREACH_ARRAY(link, links, c) {
                _cleanup_fclose_ FILE *f = NULL;

                r = open_lldp_neighbors(link->ifindex, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to open LLDP data for %i, ignoring: %m", link->ifindex);
                        continue;
                }

                for (;;) {
                        const char *chassis_id = NULL, *port_id = NULL, *system_name = NULL, *port_description = NULL;
                        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
                        _cleanup_free_ char *capabilities = NULL;
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

                        if (sd_lldp_neighbor_get_enabled_capabilities(n, &cc) >= 0) {
                                capabilities = lldp_capabilities_to_string(cc);
                                all |= cc;
                        }

                        r = table_add_many(table,
                                           TABLE_STRING, link->name,
                                           TABLE_STRING, chassis_id,
                                           TABLE_STRING, system_name,
                                           TABLE_STRING, capabilities,
                                           TABLE_STRING, port_id,
                                           TABLE_STRING, port_description);
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
        assert(index >= 0);

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
        assert(index >= 0);

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
        int index, r;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_up_down_send_message(rtnl, argv[0], index);
                if (r < 0)
                        return log_error_errno(r, "Failed to bring %s interface %s: %m",
                                               argv[0], FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX));
        }

        return r;
}

static int link_delete(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_delete_send_message(rtnl, index);
                if (r < 0)
                        return log_error_errno(r, "Failed to delete interface %s: %m",
                                               FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX));
        }

        return r;
}

static int link_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(index >= 0);
        assert(name);

        r = bus_call_method(bus, bus_network_mgr, "RenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

static int link_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = 0;

        for (int i = 1; i < argc; i++) {
                int index;

                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                RET_GATHER(r, link_renew_one(bus, index, argv[i]));
        }

        return r;
}

static int link_force_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(index >= 0);
        assert(name);

        r = bus_call_method(bus, bus_network_mgr, "ForceRenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to force renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

static int link_force_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int k = 0, r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        for (int i = 1; i < argc; i++) {
                int index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = link_force_renew_one(bus, index, argv[i]);
                if (r < 0 && k >= 0)
                        k = r;
        }

        return k;
}

static int verb_reload(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_network_mgr, "Reload", &error, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload network settings: %s", bus_error_message(&error, r));

        return 0;
}

static int verb_reconfigure(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r;
        void *p;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = bus_call_method(bus, bus_network_mgr, "ReconfigureLink", &error, NULL, "i", index);
                if (r < 0)
                        return log_error_errno(r, "Failed to reconfigure network interface %s: %s",
                                               FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX),
                                               bus_error_message(&error, r));
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
               "  edit FILES|DEVICES...  Edit network configuration files\n"
               "  cat FILES|DEVICES...   Show network configuration files\n"
               "  mask FILES...          Mask network configuration files\n"
               "  unmask FILES...        Unmask network configuration files\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-legend         Do not show the headers and footers\n"
               "  -a --all               Show status for all links\n"
               "  -s --stats             Show detailed link statistics\n"
               "  -l --full              Do not ellipsize output\n"
               "  -n --lines=INTEGER     Number of journal entries to show\n"
               "     --json=pretty|short|off\n"
               "                         Generate JSON output\n"
               "     --no-reload         Do not reload systemd-networkd or systemd-udevd\n"
               "                         after editing network config\n"
               "     --drop-in=NAME      Edit specified drop-in instead of main config file\n"
               "     --runtime           Edit runtime config files\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_JSON,
                ARG_NO_RELOAD,
                ARG_DROP_IN,
                ARG_RUNTIME,
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
                { "json",      required_argument, NULL, ARG_JSON      },
                { "no-reload", no_argument,       NULL, ARG_NO_RELOAD },
                { "drop-in",   required_argument, NULL, ARG_DROP_IN   },
                { "runtime",   no_argument,       NULL, ARG_RUNTIME   },
                {}
        };

        int c, r;

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

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case ARG_DROP_IN:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty drop-in file name.");

                        if (!endswith(optarg, ".conf")) {
                                char *conf;

                                conf = strjoin(optarg, ".conf");
                                if (!conf)
                                        return log_oom();

                                free_and_replace(arg_drop_in, conf);
                        } else {
                                r = free_and_strdup(&arg_drop_in, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (!filename_is_valid(arg_drop_in))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid drop-in file name '%s'.", arg_drop_in);

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

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        return 1;
}

static int networkctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list",        VERB_ANY, VERB_ANY, VERB_DEFAULT|VERB_ONLINE_ONLY, list_links          },
                { "status",      VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,              link_status         },
                { "lldp",        VERB_ANY, VERB_ANY, 0,                             link_lldp_status    },
                { "label",       1,        1,        0,                             list_address_labels },
                { "delete",      2,        VERB_ANY, 0,                             link_delete         },
                { "up",          2,        VERB_ANY, 0,                             link_up_down        },
                { "down",        2,        VERB_ANY, 0,                             link_up_down        },
                { "renew",       2,        VERB_ANY, VERB_ONLINE_ONLY,              link_renew          },
                { "forcerenew",  2,        VERB_ANY, VERB_ONLINE_ONLY,              link_force_renew    },
                { "reconfigure", 2,        VERB_ANY, VERB_ONLINE_ONLY,              verb_reconfigure    },
                { "reload",      1,        1,        VERB_ONLINE_ONLY,              verb_reload         },
                { "edit",        2,        VERB_ANY, 0,                             verb_edit           },
                { "cat",         2,        VERB_ANY, 0,                             verb_cat            },
                { "mask",        2,        VERB_ANY, 0,                             verb_mask           },
                { "unmask",      2,        VERB_ANY, 0,                             verb_unmask         },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        sigbus_install();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return networkctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);

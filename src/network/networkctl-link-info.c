/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_tunnel.h>

#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-util.h"
#include "device-util.h"
#include "fd-util.h"
#include "glob-util.h"
#include "netlink-util.h"
#include "networkctl-link-info.h"
#include "networkctl-util.h"
#include "sort-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "wifi-util.h"

/* use 128 kB for receive socket kernel queue, we shouldn't need more here */
#define RCVBUF_SIZE    (128*1024)

LinkInfo* link_info_array_free(LinkInfo *array) {
        for (unsigned i = 0; array && array[i].needs_freeing; i++) {
                sd_device_unref(array[i].sd_device);
                free(array[i].netdev_kind);
                free(array[i].ssid);
                free(array[i].qdisc);
                strv_free(array[i].alternative_names);
        }

        return mfree(array);
}

static int link_info_compare(const LinkInfo *a, const LinkInfo *b) {
        return CMP(a->ifindex, b->ifindex);
}

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
                if (sd_netlink_message_read_u32(m, IFLA_BR_FDB_MAX_LEARNED, &info->fdb_max_learned) >= 0 &&
                    sd_netlink_message_read_u32(m, IFLA_BR_FDB_N_LEARNED, &info->fdb_n_learned) >= 0)
                        info->has_fdb_learned = true;
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

static int acquire_link_bitrates(sd_bus *bus, LinkInfo *link) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(link);

        r = link_get_property(bus, link->ifindex, &error, &reply, "org.freedesktop.network1.Link", "BitRates", "(tt)");
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
        int r, k = 0;

        assert(link);

        if (!link->sd_device)
                return;

        if (!device_is_devtype(link->sd_device, "wlan"))
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

int acquire_link_info(sd_bus *bus, sd_netlink *rtnl, char * const *patterns, LinkInfo **ret) {
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

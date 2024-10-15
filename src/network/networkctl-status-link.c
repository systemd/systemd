/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>

#include "sd-network.h"

#include "bond-util.h"
#include "bridge-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "escape.h"
#include "format-util.h"
#include "geneve-util.h"
#include "glyph-util.h"
#include "ipvlan-util.h"
#include "macvlan-util.h"
#include "netif-util.h"
#include "network-internal.h"
#include "networkctl.h"
#include "networkctl-description.h"
#include "networkctl-dump-util.h"
#include "networkctl-journal.h"
#include "networkctl-link-info.h"
#include "networkctl-lldp.h"
#include "networkctl-status-link.h"
#include "networkctl-status-system.h"
#include "networkctl-util.h"
#include "strv.h"
#include "udev-util.h"

static int dump_dhcp_leases(Table *table, const char *prefix, sd_bus *bus, const LinkInfo *link) {
        _cleanup_strv_free_ char **buf = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(table);
        assert(prefix);
        assert(bus);
        assert(link);

        r = link_get_property(bus, link->ifindex, &error, &reply, "org.freedesktop.network1.DHCPServer", "Leases", "a(uayayayayt)");
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

                r = sd_dhcp_client_id_to_string_from_raw(client_id, client_id_sz, &id);
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

static int format_config_files(char ***files, const char *main_config) {
        assert(files);

        STRV_FOREACH(d, *files) {
                _cleanup_free_ char *s = NULL;
                int glyph = *(d + 1) == NULL ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH;

                s = strjoin(special_glyph(glyph), *d);
                if (!s)
                        return log_oom();

                free_and_replace(*d, s);
        }

        if (strv_prepend(files, main_config) < 0)
                return log_oom();

        return 0;
}

static int link_status_one(
                sd_bus *bus,
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                sd_varlink *vl,
                const LinkInfo *info) {

        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL, **sip = NULL, **search_domains = NULL,
                **route_domains = NULL, **link_dropins = NULL, **network_dropins = NULL, **netdev_dropins = NULL;
        _cleanup_free_ char *t = NULL, *network = NULL, *netdev = NULL, *iaid = NULL, *duid = NULL, *captive_portal = NULL,
                *setup_state = NULL, *operational_state = NULL, *online_state = NULL, *activation_policy = NULL;
        const char *driver = NULL, *path = NULL, *vendor = NULL, *model = NULL, *link = NULL,
                *on_color_operational, *off_color_operational, *on_color_setup, *off_color_setup, *on_color_online;
        _cleanup_free_ int *carrier_bound_to = NULL, *carrier_bound_by = NULL;
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(bus);
        assert(rtnl);
        assert(vl);
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
        (void) sd_network_link_get_netdev_file(info->ifindex, &netdev);
        (void) sd_network_link_get_netdev_file_dropins(info->ifindex, &netdev_dropins);
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

        r = format_config_files(&network_dropins, network);
        if (r < 0)
                return r;

        r = format_config_files(&link_dropins, link);
        if (r < 0)
                return r;

        r = format_config_files(&netdev_dropins, netdev);
        if (r < 0)
                return r;

        table = table_new_vertical();
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        /* Config files and basic states. */
        if (netdev_dropins) {
                r = table_add_many(table,
                                   TABLE_FIELD, "NetDev File",
                                   TABLE_STRV, netdev_dropins);
                if (r < 0)
                        return table_log_add_error(r);
        }

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

                if (info->has_fdb_learned) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "FDB Learned",
                                           TABLE_UINT32, info->fdb_n_learned,
                                           TABLE_FIELD, "FDB Max Learned",
                                           TABLE_UINT32, info->fdb_max_learned);
                        if (r < 0)
                                return table_log_add_error(r);
                }

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
                const sd_dhcp_client_id *client_id;
                const char *tz;

                r = sd_dhcp_lease_get_timezone(lease, &tz);
                if (r >= 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Time Zone",
                                           TABLE_STRING, tz);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = sd_dhcp_lease_get_client_id(lease, &client_id);
                if (r >= 0) {
                        _cleanup_free_ char *id = NULL;

                        r = sd_dhcp_client_id_to_string(client_id, &id);
                        if (r >= 0) {
                                r = table_add_many(table,
                                                   TABLE_FIELD, "DHCPv4 Client ID",
                                                   TABLE_STRING, id);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                }
        }

        r = sd_network_link_get_dhcp6_client_iaid_string(info->ifindex, &iaid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "DHCPv6 Client IAID",
                                   TABLE_STRING, iaid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_network_link_get_dhcp6_client_duid_string(info->ifindex, &duid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "DHCPv6 Client DUID",
                                   TABLE_STRING, duid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = dump_lldp_neighbors(vl, table, info->ifindex);
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

        return show_logs(info->ifindex, info->name);
}

int link_status(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        int r, c;

        r = dump_description(argc, argv);
        if (r != 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                log_debug_errno(r, "Failed to open hardware database: %m");

        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

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

                RET_GATHER(r, link_status_one(bus, rtnl, hwdb, vl, i));

                first = false;
        }

        return r;
}

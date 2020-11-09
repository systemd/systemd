/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bond.h"
#include "bridge.h"
#include "bus-util.h"
#include "dhcp-identifier.h"
#include "dhcp-lease-internal.h"
#include "env-file.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "ipvlan.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-can.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-fdb.h"
#include "networkd-ipv4ll.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "networkd-mdb.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-sriov.h"
#include "networkd-sysctl.h"
#include "networkd-radv.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-wifi.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tc.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "util.h"
#include "vrf.h"

bool link_ipv4ll_enabled(Link *link, AddressFamily mask) {
        assert(link);
        assert((mask & ~(ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_FALLBACK_IPV4)) == 0);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (STRPTR_IN_SET(link->kind,
                          "vrf", "wireguard", "ipip", "gre", "ip6gre","ip6tnl", "sit", "vti",
                          "vti6", "nlmon", "xfrm", "bareudp"))
                return false;

        /* L3 or L3S mode do not support ARP. */
        if (IN_SET(link_get_ipvlan_mode(link), NETDEV_IPVLAN_MODE_L3, NETDEV_IPVLAN_MODE_L3S))
                return false;

        if (link->network->bond)
                return false;

        return link->network->link_local & mask;
}

bool link_ipv6ll_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (STRPTR_IN_SET(link->kind, "vrf", "wireguard", "ipip", "gre", "sit", "vti", "nlmon"))
                return false;

        if (link->network->bond)
                return false;

        return link->network->link_local & ADDRESS_FAMILY_IPV6;
}

bool link_ipv6_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->network->bond)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        /* DHCPv6 client will not be started if no IPv6 link-local address is configured. */
        if (link_ipv6ll_enabled(link))
                return true;

        if (network_has_static_ipv6_configurations(link->network))
                return true;

        return false;
}

static bool link_is_enslaved(Link *link) {
        if (link->flags & IFF_SLAVE)
                /* Even if the link is not managed by networkd, honor IFF_SLAVE flag. */
                return true;

        if (!link->network)
                return false;

        if (link->master_ifindex > 0 && link->network->bridge)
                return true;

        /* TODO: add conditions for other netdevs. */

        return false;
}

static void link_update_master_operstate(Link *link, NetDev *netdev) {
        Link *master;

        if (!netdev)
                return;

        if (netdev->ifindex <= 0)
                return;

        if (link_get(link->manager, netdev->ifindex, &master) < 0)
                return;

        link_update_operstate(master, true);
}

void link_update_operstate(Link *link, bool also_update_master) {
        LinkOperationalState operstate;
        LinkCarrierState carrier_state;
        LinkAddressState address_state;
        _cleanup_strv_free_ char **p = NULL;
        uint8_t scope = RT_SCOPE_NOWHERE;
        bool changed = false;
        Address *address;

        assert(link);

        if (link->kernel_operstate == IF_OPER_DORMANT)
                carrier_state = LINK_CARRIER_STATE_DORMANT;
        else if (link_has_carrier(link)) {
                if (link_is_enslaved(link))
                        carrier_state = LINK_CARRIER_STATE_ENSLAVED;
                else
                        carrier_state = LINK_CARRIER_STATE_CARRIER;
        } else if (link->flags & IFF_UP)
                carrier_state = LINK_CARRIER_STATE_NO_CARRIER;
        else
                carrier_state = LINK_CARRIER_STATE_OFF;

        if (carrier_state >= LINK_CARRIER_STATE_CARRIER) {
                Link *slave;

                SET_FOREACH(slave, link->slaves) {
                        link_update_operstate(slave, false);

                        if (slave->carrier_state < LINK_CARRIER_STATE_CARRIER)
                                carrier_state = LINK_CARRIER_STATE_DEGRADED_CARRIER;
                }
        }

        SET_FOREACH(address, link->addresses) {
                if (!address_is_ready(address))
                        continue;

                if (address->scope < scope)
                        scope = address->scope;
        }

        /* for operstate we also take foreign addresses into account */
        SET_FOREACH(address, link->addresses_foreign) {
                if (!address_is_ready(address))
                        continue;

                if (address->scope < scope)
                        scope = address->scope;
        }

        if (scope < RT_SCOPE_SITE)
                /* universally accessible addresses found */
                address_state = LINK_ADDRESS_STATE_ROUTABLE;
        else if (scope < RT_SCOPE_HOST)
                /* only link or site local addresses found */
                address_state = LINK_ADDRESS_STATE_DEGRADED;
        else
                /* no useful addresses found */
                address_state = LINK_ADDRESS_STATE_OFF;

        /* Mapping of address and carrier state vs operational state
         *                                                     carrier state
         *                          | off | no-carrier | dormant | degraded-carrier | carrier  | enslaved
         *                 ------------------------------------------------------------------------------
         *                 off      | off | no-carrier | dormant | degraded-carrier | carrier  | enslaved
         * address_state   degraded | off | no-carrier | dormant | degraded-carrier | degraded | enslaved
         *                 routable | off | no-carrier | dormant | degraded-carrier | routable | routable
         */

        if (carrier_state < LINK_CARRIER_STATE_CARRIER || address_state == LINK_ADDRESS_STATE_OFF)
                operstate = (LinkOperationalState) carrier_state;
        else if (address_state == LINK_ADDRESS_STATE_ROUTABLE)
                operstate = LINK_OPERSTATE_ROUTABLE;
        else if (carrier_state == LINK_CARRIER_STATE_CARRIER)
                operstate = LINK_OPERSTATE_DEGRADED;
        else
                operstate = LINK_OPERSTATE_ENSLAVED;

        if (link->carrier_state != carrier_state) {
                link->carrier_state = carrier_state;
                changed = true;
                if (strv_extend(&p, "CarrierState") < 0)
                        log_oom();
        }

        if (link->address_state != address_state) {
                link->address_state = address_state;
                changed = true;
                if (strv_extend(&p, "AddressState") < 0)
                        log_oom();
        }

        if (link->operstate != operstate) {
                link->operstate = operstate;
                changed = true;
                if (strv_extend(&p, "OperationalState") < 0)
                        log_oom();
        }

        if (p)
                link_send_changed_strv(link, p);
        if (changed)
                link_dirty(link);

        if (also_update_master && link->network) {
                link_update_master_operstate(link, link->network->bond);
                link_update_master_operstate(link, link->network->bridge);
        }
}

#define FLAG_STRING(string, flag, old, new) \
        (((old ^ new) & flag) \
                ? ((old & flag) ? (" -" string) : (" +" string)) \
                : "")

static int link_update_flags(Link *link, sd_netlink_message *m, bool force_update_operstate) {
        unsigned flags, unknown_flags_added, unknown_flags_removed, unknown_flags;
        uint8_t operstate;
        int r;

        assert(link);

        r = sd_rtnl_message_link_get_flags(m, &flags);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not get link flags: %m");

        r = sd_netlink_message_read_u8(m, IFLA_OPERSTATE, &operstate);
        if (r < 0)
                /* if we got a message without operstate, take it to mean
                   the state was unchanged */
                operstate = link->kernel_operstate;

        if (!force_update_operstate && (link->flags == flags) && (link->kernel_operstate == operstate))
                return 0;

        if (link->flags != flags) {
                log_link_debug(link, "Flags change:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                               FLAG_STRING("LOOPBACK", IFF_LOOPBACK, link->flags, flags),
                               FLAG_STRING("MASTER", IFF_MASTER, link->flags, flags),
                               FLAG_STRING("SLAVE", IFF_SLAVE, link->flags, flags),
                               FLAG_STRING("UP", IFF_UP, link->flags, flags),
                               FLAG_STRING("DORMANT", IFF_DORMANT, link->flags, flags),
                               FLAG_STRING("LOWER_UP", IFF_LOWER_UP, link->flags, flags),
                               FLAG_STRING("RUNNING", IFF_RUNNING, link->flags, flags),
                               FLAG_STRING("MULTICAST", IFF_MULTICAST, link->flags, flags),
                               FLAG_STRING("BROADCAST", IFF_BROADCAST, link->flags, flags),
                               FLAG_STRING("POINTOPOINT", IFF_POINTOPOINT, link->flags, flags),
                               FLAG_STRING("PROMISC", IFF_PROMISC, link->flags, flags),
                               FLAG_STRING("ALLMULTI", IFF_ALLMULTI, link->flags, flags),
                               FLAG_STRING("PORTSEL", IFF_PORTSEL, link->flags, flags),
                               FLAG_STRING("AUTOMEDIA", IFF_AUTOMEDIA, link->flags, flags),
                               FLAG_STRING("DYNAMIC", IFF_DYNAMIC, link->flags, flags),
                               FLAG_STRING("NOARP", IFF_NOARP, link->flags, flags),
                               FLAG_STRING("NOTRAILERS", IFF_NOTRAILERS, link->flags, flags),
                               FLAG_STRING("DEBUG", IFF_DEBUG, link->flags, flags),
                               FLAG_STRING("ECHO", IFF_ECHO, link->flags, flags));

                unknown_flags = ~(IFF_LOOPBACK | IFF_MASTER | IFF_SLAVE | IFF_UP |
                                  IFF_DORMANT | IFF_LOWER_UP | IFF_RUNNING |
                                  IFF_MULTICAST | IFF_BROADCAST | IFF_POINTOPOINT |
                                  IFF_PROMISC | IFF_ALLMULTI | IFF_PORTSEL |
                                  IFF_AUTOMEDIA | IFF_DYNAMIC | IFF_NOARP |
                                  IFF_NOTRAILERS | IFF_DEBUG | IFF_ECHO);
                unknown_flags_added = ((link->flags ^ flags) & flags & unknown_flags);
                unknown_flags_removed = ((link->flags ^ flags) & link->flags & unknown_flags);

                /* link flags are currently at most 18 bits, let's align to
                 * printing 20 */
                if (unknown_flags_added)
                        log_link_debug(link,
                                       "Unknown link flags gained: %#.5x (ignoring)",
                                       unknown_flags_added);

                if (unknown_flags_removed)
                        log_link_debug(link,
                                       "Unknown link flags lost: %#.5x (ignoring)",
                                       unknown_flags_removed);
        }

        link->flags = flags;
        link->kernel_operstate = operstate;

        link_update_operstate(link, true);

        return 0;
}

static int link_new(Manager *manager, sd_netlink_message *message, Link **ret) {
        _cleanup_(link_unrefp) Link *link = NULL;
        const char *ifname, *kind = NULL;
        unsigned short iftype;
        int r, ifindex;
        uint16_t type;

        assert(manager);
        assert(message);
        assert(ret);

        /* check for link kind */
        r = sd_netlink_message_enter_container(message, IFLA_LINKINFO);
        if (r == 0) {
                (void) sd_netlink_message_read_string(message, IFLA_INFO_KIND, &kind);
                r = sd_netlink_message_exit_container(message);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0)
                return r;
        else if (type != RTM_NEWLINK)
                return -EINVAL;

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return r;
        else if (ifindex <= 0)
                return -EINVAL;

        r = sd_rtnl_message_link_get_type(message, &iftype);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &ifname);
        if (r < 0)
                return r;

        link = new(Link, 1);
        if (!link)
                return -ENOMEM;

        *link = (Link) {
                .n_ref = 1,
                .manager = manager,
                .state = LINK_STATE_PENDING,
                .ifindex = ifindex,
                .iftype = iftype,

                .n_dns = (unsigned) -1,
                .dns_default_route = -1,
                .llmnr = _RESOLVE_SUPPORT_INVALID,
                .mdns = _RESOLVE_SUPPORT_INVALID,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,
        };

        link->ifname = strdup(ifname);
        if (!link->ifname)
                return -ENOMEM;

        if (kind) {
                link->kind = strdup(kind);
                if (!link->kind)
                        return -ENOMEM;
        }

        r = sd_netlink_message_read_u32(message, IFLA_MASTER, (uint32_t *)&link->master_ifindex);
        if (r < 0)
                log_link_debug_errno(link, r, "New device has no master, continuing without");

        r = netlink_message_read_hw_addr(message, IFLA_ADDRESS, &link->hw_addr);
        if (r < 0)
                log_link_debug_errno(link, r, "Hardware address not found for new device, continuing without");

        r = netlink_message_read_hw_addr(message, IFLA_BROADCAST, &link->bcast_addr);
        if (r < 0)
                log_link_debug_errno(link, r, "Broadcast address not found for new device, continuing without");

        r = ethtool_get_permanent_macaddr(&manager->ethtool_fd, link->ifname, &link->permanent_mac);
        if (r < 0)
                log_link_debug_errno(link, r, "Permanent MAC address not found for new device, continuing without: %m");

        r = ethtool_get_driver(&manager->ethtool_fd, link->ifname, &link->driver);
        if (r < 0)
                log_link_debug_errno(link, r, "Failed to get driver, continuing without: %m");

        r = sd_netlink_message_read_strv(message, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &link->alternative_names);
        if (r < 0 && r != -ENODATA)
                return r;

        if (asprintf(&link->state_file, "/run/systemd/netif/links/%d", link->ifindex) < 0)
                return -ENOMEM;

        if (asprintf(&link->lease_file, "/run/systemd/netif/leases/%d", link->ifindex) < 0)
                return -ENOMEM;

        if (asprintf(&link->lldp_file, "/run/systemd/netif/lldp/%d", link->ifindex) < 0)
                return -ENOMEM;

        r = hashmap_ensure_allocated(&manager->links, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(manager->links, INT_TO_PTR(link->ifindex), link);
        if (r < 0)
                return r;

        r = link_update_flags(link, message, false);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(link);

        return 0;
}

void link_ntp_settings_clear(Link *link) {
        link->ntp = strv_free(link->ntp);
}

void link_dns_settings_clear(Link *link) {
        if (link->n_dns != (unsigned) -1)
                for (unsigned i = 0; i < link->n_dns; i++)
                        in_addr_full_free(link->dns[i]);
        link->dns = mfree(link->dns);
        link->n_dns = (unsigned) -1;

        link->search_domains = ordered_set_free_free(link->search_domains);
        link->route_domains = ordered_set_free_free(link->route_domains);

        link->dns_default_route = -1;
        link->llmnr = _RESOLVE_SUPPORT_INVALID;
        link->mdns = _RESOLVE_SUPPORT_INVALID;
        link->dnssec_mode = _DNSSEC_MODE_INVALID;
        link->dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID;

        link->dnssec_negative_trust_anchors = set_free_free(link->dnssec_negative_trust_anchors);
}

static void link_free_engines(Link *link) {
        if (!link)
                return;

        link->dhcp_server = sd_dhcp_server_unref(link->dhcp_server);
        link->dhcp_client = sd_dhcp_client_unref(link->dhcp_client);
        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp_acd = sd_ipv4acd_unref(link->dhcp_acd);

        link->lldp = sd_lldp_unref(link->lldp);
        link_lldp_emit_stop(link);

        ndisc_flush(link);

        link->ipv4ll = sd_ipv4ll_unref(link->ipv4ll);
        link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
        link->dhcp6_lease = sd_dhcp6_lease_unref(link->dhcp6_lease);
        link->ndisc = sd_ndisc_unref(link->ndisc);
        link->radv = sd_radv_unref(link->radv);

        ipv4_dad_unref(link);
}

static Link *link_free(Link *link) {
        assert(link);

        link_ntp_settings_clear(link);
        link_dns_settings_clear(link);

        link->routes = set_free(link->routes);
        link->routes_foreign = set_free(link->routes_foreign);
        link->dhcp_routes = set_free(link->dhcp_routes);
        link->dhcp_routes_old = set_free(link->dhcp_routes_old);
        link->dhcp6_routes = set_free(link->dhcp6_routes);
        link->dhcp6_routes_old = set_free(link->dhcp6_routes_old);
        link->dhcp6_pd_routes = set_free(link->dhcp6_pd_routes);
        link->dhcp6_pd_routes_old = set_free(link->dhcp6_pd_routes_old);
        link->ndisc_routes = set_free(link->ndisc_routes);

        link->nexthops = set_free(link->nexthops);
        link->nexthops_foreign = set_free(link->nexthops_foreign);

        link->neighbors = set_free(link->neighbors);
        link->neighbors_foreign = set_free(link->neighbors_foreign);

        link->addresses = set_free(link->addresses);
        link->addresses_foreign = set_free(link->addresses_foreign);
        link->pool_addresses = set_free(link->pool_addresses);
        link->static_addresses = set_free(link->static_addresses);
        link->dhcp6_addresses = set_free(link->dhcp6_addresses);
        link->dhcp6_addresses_old = set_free(link->dhcp6_addresses_old);
        link->dhcp6_pd_addresses = set_free(link->dhcp6_pd_addresses);
        link->dhcp6_pd_addresses_old = set_free(link->dhcp6_pd_addresses_old);
        link->ndisc_addresses = set_free(link->ndisc_addresses);

        link_free_engines(link);
        free(link->lease_file);
        free(link->lldp_file);

        free(link->ifname);
        strv_free(link->alternative_names);
        free(link->kind);
        free(link->ssid);
        free(link->driver);

        (void) unlink(link->state_file);
        free(link->state_file);

        sd_device_unref(link->sd_device);

        hashmap_free(link->bound_to_links);
        hashmap_free(link->bound_by_links);

        set_free_with_destructor(link->slaves, link_unref);

        network_unref(link->network);

        return mfree(link);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Link, link, link_free);

int link_get(Manager *m, int ifindex, Link **ret) {
        Link *link;

        assert(m);
        assert(ifindex > 0);
        assert(ret);

        link = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!link)
                return -ENODEV;

        *ret = link;

        return 0;
}

void link_set_state(Link *link, LinkState state) {
        assert(link);

        if (link->state == state)
                return;

        log_link_debug(link, "State changed: %s -> %s",
                       link_state_to_string(link->state),
                       link_state_to_string(state));

        link->state = state;

        link_send_changed(link, "AdministrativeState", NULL);
}

static void link_enter_unmanaged(Link *link) {
        assert(link);

        link_set_state(link, LINK_STATE_UNMANAGED);

        link_dirty(link);
}

int link_stop_engines(Link *link, bool may_keep_dhcp) {
        int r = 0, k;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        bool keep_dhcp = may_keep_dhcp &&
                         link->network &&
                         (link->manager->restarting ||
                          FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP_ON_STOP));

        if (!keep_dhcp) {
                k = sd_dhcp_client_stop(link->dhcp_client);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop DHCPv4 client: %m");
        }

        k = sd_ipv4acd_stop(link->dhcp_acd);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv4 ACD client for DHCPv4: %m");

        k = sd_dhcp_server_stop(link->dhcp_server);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop DHCPv4 server: %m");

        k = sd_lldp_stop(link->lldp);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop LLDP: %m");

        k = sd_ipv4ll_stop(link->ipv4ll);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv4 link-local: %m");

        k = ipv4_dad_stop(link);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv4 ACD client: %m");

        k = sd_dhcp6_client_stop(link->dhcp6_client);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop DHCPv6 client: %m");

        k = dhcp6_pd_remove(link);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not remove DHCPv6 PD addresses and routes: %m");

        k = sd_ndisc_stop(link->ndisc);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Discovery: %m");

        k = sd_radv_stop(link->radv);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Advertisement: %m");

        link_lldp_emit_stop(link);
        return r;
}

void link_enter_failed(Link *link) {
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        log_link_warning(link, "Failed");

        link_set_state(link, LINK_STATE_FAILED);

        (void) link_stop_engines(link, false);

        link_dirty(link);
}

static int link_join_netdevs_after_configured(Link *link) {
        NetDev *netdev;
        int r;

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs) {
                if (netdev->ifindex > 0)
                        /* Assume already enslaved. */
                        continue;

                if (netdev_get_create_type(netdev) != NETDEV_CREATE_AFTER_CONFIGURED)
                        continue;

                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(netdev),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", netdev->ifname));

                r = netdev_join(netdev, link, NULL);
                if (r < 0)
                        return log_struct_errno(LOG_WARNING, r,
                                                LOG_LINK_INTERFACE(link),
                                                LOG_NETDEV_INTERFACE(netdev),
                                                LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", netdev->ifname));
        }

        return 0;
}

static void link_enter_configured(Link *link) {
        assert(link);
        assert(link->network);

        if (link->state != LINK_STATE_CONFIGURING)
                return;

        link_set_state(link, LINK_STATE_CONFIGURED);

        (void) link_join_netdevs_after_configured(link);

        link_dirty(link);
}

void link_check_ready(Link *link) {
        Address *a;

        assert(link);

        if (link->state == LINK_STATE_CONFIGURED)
                return;

        if (link->state != LINK_STATE_CONFIGURING) {
                log_link_debug(link, "%s(): link is in %s state.", __func__, link_state_to_string(link->state));
                return;
        }

        if (!link->network)
                return;

        if (!link->addresses_configured) {
                log_link_debug(link, "%s(): static addresses are not configured.", __func__);
                return;
        }

        if (!link->neighbors_configured) {
                log_link_debug(link, "%s(): static neighbors are not configured.", __func__);
                return;
        }

        SET_FOREACH(a, link->addresses)
                if (!address_is_ready(a)) {
                        _cleanup_free_ char *str = NULL;

                        (void) in_addr_to_string(a->family, &a->in_addr, &str);
                        log_link_debug(link, "%s(): an address %s/%d is not ready.", __func__, strnull(str), a->prefixlen);
                        return;
                }

        if (!link->static_routes_configured) {
                log_link_debug(link, "%s(): static routes are not configured.", __func__);
                return;
        }

        if (!link->static_nexthops_configured) {
                log_link_debug(link, "%s(): static nexthops are not configured.", __func__);
                return;
        }

        if (!link->routing_policy_rules_configured) {
                log_link_debug(link, "%s(): static routing policy rules are not configured.", __func__);
                return;
        }

        if (!link->tc_configured) {
                log_link_debug(link, "%s(): traffic controls are not configured.", __func__);
                return;
        }

        if (!link->sr_iov_configured) {
                log_link_debug(link, "%s(): SR-IOV is not configured.", __func__);
                return;
        }

        if (!link->bridge_mdb_configured) {
                log_link_debug(link, "%s(): Bridge MDB is not configured.", __func__);
                return;
        }

        if (link_has_carrier(link) || !link->network->configure_without_carrier) {
                bool has_ndisc_address = false;
                NDiscAddress *n;

                if (link_ipv4ll_enabled(link, ADDRESS_FAMILY_IPV4) && !link->ipv4ll_address_configured) {
                        log_link_debug(link, "%s(): IPv4LL is not configured.", __func__);
                        return;
                }

                if (link_ipv6ll_enabled(link) &&
                    in_addr_is_null(AF_INET6, (const union in_addr_union*) &link->ipv6ll_address)) {
                        log_link_debug(link, "%s(): IPv6LL is not configured.", __func__);
                        return;
                }

                SET_FOREACH(n, link->ndisc_addresses)
                        if (!n->marked) {
                                has_ndisc_address = true;
                                break;
                        }

                if ((link_dhcp4_enabled(link) || link_dhcp6_enabled(link)) &&
                    !link->dhcp_address && set_isempty(link->dhcp6_addresses) && !has_ndisc_address &&
                    !(link_ipv4ll_enabled(link, ADDRESS_FAMILY_FALLBACK_IPV4) && link->ipv4ll_address_configured)) {
                        log_link_debug(link, "%s(): DHCP4 or DHCP6 is enabled but no dynamic address is assigned yet.", __func__);
                        return;
                }

                if (link_dhcp4_enabled(link) || link_dhcp6_enabled(link) || link_dhcp6_pd_is_enabled(link) || link_ipv6_accept_ra_enabled(link)) {
                        if (!link->dhcp4_configured &&
                            !(link->dhcp6_address_configured && link->dhcp6_route_configured) &&
                            !(link->dhcp6_pd_address_configured && link->dhcp6_pd_route_configured) &&
                            !(link->ndisc_addresses_configured && link->ndisc_routes_configured) &&
                            !(link_ipv4ll_enabled(link, ADDRESS_FAMILY_FALLBACK_IPV4) && link->ipv4ll_address_configured)) {
                                /* When DHCP or RA is enabled, at least one protocol must provide an address, or
                                 * an IPv4ll fallback address must be configured. */
                                log_link_debug(link, "%s(): dynamic addresses or routes are not configured.", __func__);
                                return;
                        }

                        log_link_debug(link, "%s(): dhcp4:%s dhcp6_addresses:%s dhcp_routes:%s dhcp_pd_addresses:%s dhcp_pd_routes:%s ndisc_addresses:%s ndisc_routes:%s",
                                       __func__,
                                       yes_no(link->dhcp4_configured),
                                       yes_no(link->dhcp6_address_configured),
                                       yes_no(link->dhcp6_route_configured),
                                       yes_no(link->dhcp6_pd_address_configured),
                                       yes_no(link->dhcp6_pd_route_configured),
                                       yes_no(link->ndisc_addresses_configured),
                                       yes_no(link->ndisc_routes_configured));
                }
        }

        link_enter_configured(link);

        return;
}

static int link_set_static_configs(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        /* Reset all *_configured flags we are configuring. */
        link->request_static_addresses = false;
        link->addresses_configured = false;
        link->addresses_ready = false;
        link->neighbors_configured = false;
        link->static_routes_configured = false;
        link->static_nexthops_configured = false;
        link->routing_policy_rules_configured = false;

        r = link_set_bridge_fdb(link);
        if (r < 0)
                return r;

        r = link_set_bridge_mdb(link);
        if (r < 0)
                return r;

        r = link_set_neighbors(link);
        if (r < 0)
                return r;

        r = link_set_addresses(link);
        if (r < 0)
                return r;

        r = link_set_address_labels(link);
        if (r < 0)
                return r;

        /* now that we can figure out a default address for the dhcp server, start it */
        r = dhcp4_server_configure(link);
        if (r < 0)
                return r;

        return 0;
}

static int link_configure_continue(Link *link);

static int link_mac_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set MAC address, ignoring");
        else
                log_link_debug(link, "Setting MAC address done.");

        return 1;
}

static int link_set_mac(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (!link->network->mac)
                return 0;

        log_link_debug(link, "Setting MAC address");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_append_ether_addr(req, IFLA_ADDRESS, link->network->mac);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set MAC address: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_mac_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_nomaster_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set nomaster, ignoring");
        else
                log_link_debug(link, "Setting nomaster done.");

        return 1;
}

static int link_set_nomaster(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        /* set it free if not enslaved with networkd */
        if (link->network->bridge || link->network->bond || link->network->vrf)
                return 0;

        log_link_debug(link, "Setting nomaster");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_append_u32(req, IFLA_MASTER, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_MASTER attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_nomaster_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        link->setting_mtu = false;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set MTU, ignoring");
        else
                log_link_debug(link, "Setting MTU done.");

        if (link->state == LINK_STATE_INITIALIZED) {
                r = link_configure_continue(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

int link_set_mtu(Link *link, uint32_t mtu) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (mtu == 0 || link->setting_mtu)
                return 0;

        if (link->mtu == mtu)
                return 0;

        log_link_debug(link, "Setting MTU: %" PRIu32, mtu);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        /* IPv6 protocol requires a minimum MTU of IPV6_MTU_MIN(1280) bytes
         * on the interface. Bump up MTU bytes to IPV6_MTU_MIN. */
        if (link_ipv6_enabled(link) && mtu < IPV6_MIN_MTU) {

                log_link_warning(link, "Bumping MTU to " STRINGIFY(IPV6_MIN_MTU) ", as "
                                 "IPv6 is requested and requires a minimum MTU of " STRINGIFY(IPV6_MIN_MTU) " bytes");

                mtu = IPV6_MIN_MTU;
        }

        r = sd_netlink_message_append_u32(req, IFLA_MTU, mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append MTU: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, set_mtu_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->setting_mtu = true;

        return 0;
}

static bool link_reduces_vlan_mtu(Link *link) {
        /* See netif_reduces_vlan_mtu() in kernel. */
        return streq_ptr(link->kind, "macsec");
}

static uint32_t link_get_requested_mtu_by_stacked_netdevs(Link *link) {
        uint32_t mtu = 0;
        NetDev *dev;

        HASHMAP_FOREACH(dev, link->network->stacked_netdevs)
                if (dev->kind == NETDEV_KIND_VLAN && dev->mtu > 0)
                        /* See vlan_dev_change_mtu() in kernel. */
                        mtu = MAX(mtu, link_reduces_vlan_mtu(link) ? dev->mtu + 4 : dev->mtu);

                else if (dev->kind == NETDEV_KIND_MACVLAN && dev->mtu > mtu)
                        /* See macvlan_change_mtu() in kernel. */
                        mtu = dev->mtu;

        return mtu;
}

static int link_configure_mtu(Link *link) {
        uint32_t mtu;

        assert(link);
        assert(link->network);

        if (link->network->mtu > 0)
                return link_set_mtu(link, link->network->mtu);

        mtu = link_get_requested_mtu_by_stacked_netdevs(link);
        if (link->mtu >= mtu)
                return 0;

        log_link_notice(link, "Bumping MTU bytes from %"PRIu32" to %"PRIu32" because of stacked device. "
                        "If it is not desired, then please explicitly specify MTUBytes= setting.",
                        link->mtu, mtu);

        return link_set_mtu(link, mtu);
}

static int set_flags_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set link flags, ignoring");

        return 1;
}

static int link_set_flags(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        unsigned ifi_change = 0;
        unsigned ifi_flags = 0;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->arp < 0 && link->network->multicast < 0 && link->network->allmulticast < 0)
                return 0;

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        if (link->network->arp >= 0) {
                ifi_change |= IFF_NOARP;
                SET_FLAG(ifi_flags, IFF_NOARP, link->network->arp == 0);
        }

        if (link->network->multicast >= 0) {
                ifi_change |= IFF_MULTICAST;
                SET_FLAG(ifi_flags, IFF_MULTICAST, link->network->multicast);
        }

        if (link->network->allmulticast >= 0) {
                ifi_change |= IFF_ALLMULTI;
                SET_FLAG(ifi_flags, IFF_ALLMULTI, link->network->allmulticast);
        }

        r = sd_rtnl_message_link_set_flags(req, ifi_flags, ifi_change);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, set_flags_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_acquire_ipv6_conf(Link *link) {
        int r;

        assert(link);

        if (link->ndisc) {
                log_link_debug(link, "Discovering IPv6 routers");

                r = sd_ndisc_start(link->ndisc);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not start IPv6 Router Discovery: %m");
        }

        if (link->radv) {
                assert(link->radv);
                assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

                log_link_debug(link, "Starting IPv6 Router Advertisements");

                r = radv_emit_dns(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to configure DNS or Domains in IPv6 Router Advertisement: %m");

                r = sd_radv_start(link->radv);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not start IPv6 Router Advertisement: %m");
        }

        if (link_dhcp6_enabled(link) && IN_SET(link->network->dhcp6_without_ra,
                                               DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST,
                                               DHCP6_CLIENT_START_MODE_SOLICIT)) {
                assert(link->dhcp6_client);
                assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

                r = dhcp6_request_address(link, link->network->dhcp6_without_ra == DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not acquire DHCPv6 lease: %m");
                else
                        log_link_debug(link, "Acquiring DHCPv6 lease");
        }

        r = dhcp6_request_prefix_delegation(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request DHCPv6 prefix delegation: %m");

        return 0;
}

static int link_acquire_ipv4_conf(Link *link) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        if (link_ipv4ll_enabled(link, ADDRESS_FAMILY_IPV4)) {
                assert(link->ipv4ll);

                log_link_debug(link, "Acquiring IPv4 link-local address");

                r = sd_ipv4ll_start(link->ipv4ll);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not acquire IPv4 link-local address: %m");
        }

        if (link->dhcp_client) {
                log_link_debug(link, "Acquiring DHCPv4 lease");

                r = sd_dhcp_client_start(link->dhcp_client);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not acquire DHCPv4 lease: %m");
        }

        return 0;
}

static int link_acquire_conf(Link *link) {
        int r;

        assert(link);

        r = link_acquire_ipv4_conf(link);
        if (r < 0)
                return r;

        if (!in_addr_is_null(AF_INET6, (const union in_addr_union*) &link->ipv6ll_address)) {
                r = link_acquire_ipv6_conf(link);
                if (r < 0)
                        return r;
        }

        r = link_lldp_emit_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start LLDP transmission: %m");

        return 0;
}

bool link_has_carrier(Link *link) {
        /* see Documentation/networking/operstates.txt in the kernel sources */

        if (link->kernel_operstate == IF_OPER_UP)
                return true;

        if (link->kernel_operstate == IF_OPER_UNKNOWN)
                /* operstate may not be implemented, so fall back to flags */
                if (FLAGS_SET(link->flags, IFF_LOWER_UP | IFF_RUNNING) &&
                    !FLAGS_SET(link->flags, IFF_DORMANT))
                        return true;

        return false;
}

static int link_address_genmode_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        link->setting_genmode = false;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set address genmode for interface, ignoring");
        else
                log_link_debug(link, "Setting address genmode done.");

        if (link->state == LINK_STATE_INITIALIZED) {
                r = link_configure_continue(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int link_configure_addrgen_mode(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        uint8_t ipv6ll_mode;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (!socket_ipv6_is_supported() || link->setting_genmode)
                return 0;

        log_link_debug(link, "Setting address genmode for link");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_open_container(req, IFLA_AF_SPEC);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open IFLA_AF_SPEC container: %m");

        r = sd_netlink_message_open_container(req, AF_INET6);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open AF_INET6 container: %m");

        if (!link_ipv6ll_enabled(link))
                ipv6ll_mode = IN6_ADDR_GEN_MODE_NONE;
        else if (link->network->ipv6ll_address_gen_mode < 0) {
                r = sysctl_read_ip_property(AF_INET6, link->ifname, "stable_secret", NULL);
                if (r < 0) {
                        /* The file may not exist. And even if it exists, when stable_secret is unset,
                         * reading the file fails with EIO. */
                        log_link_debug_errno(link, r, "Failed to read sysctl property stable_secret: %m");

                        ipv6ll_mode = IN6_ADDR_GEN_MODE_EUI64;
                } else
                        ipv6ll_mode = IN6_ADDR_GEN_MODE_STABLE_PRIVACY;
        } else
                ipv6ll_mode = link->network->ipv6ll_address_gen_mode;

        r = sd_netlink_message_append_u8(req, IFLA_INET6_ADDR_GEN_MODE, ipv6ll_mode);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_INET6_ADDR_GEN_MODE: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close AF_INET6 container: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close IFLA_AF_SPEC container: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_address_genmode_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->setting_genmode = true;

        return 0;
}

static int link_up_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                /* we warn but don't fail the link, as it may be brought up later */
                log_link_message_warning_errno(link, m, r, "Could not bring up interface");

        return 1;
}

static int link_up(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Bringing link up");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_up_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_down_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not bring down interface");

        return 1;
}

int link_down(Link *link, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Bringing link down");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req,
                                     RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, 0, IFF_UP);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: link_down_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_group_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not set group for the interface");

        return 1;
}

static int link_set_group(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (link->network->group <= 0)
                return 0;

        log_link_debug(link, "Setting group");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_append_u32(req, IFLA_GROUP, link->network->group);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link group: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_group_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_handle_bound_to_list(Link *link) {
        Link *l;
        int r;
        bool required_up = false;
        bool link_is_up = false;

        assert(link);

        if (hashmap_isempty(link->bound_to_links))
                return 0;

        if (link->flags & IFF_UP)
                link_is_up = true;

        HASHMAP_FOREACH (l, link->bound_to_links)
                if (link_has_carrier(l)) {
                        required_up = true;
                        break;
                }

        if (!required_up && link_is_up) {
                r = link_down(link, NULL);
                if (r < 0)
                        return r;
        } else if (required_up && !link_is_up) {
                r = link_up(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_handle_bound_by_list(Link *link) {
        Link *l;
        int r;

        assert(link);

        if (hashmap_isempty(link->bound_by_links))
                return 0;

        HASHMAP_FOREACH (l, link->bound_by_links) {
                r = link_handle_bound_to_list(l);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_put_carrier(Link *link, Link *carrier, Hashmap **h) {
        int r;

        assert(link);
        assert(carrier);

        if (link == carrier)
                return 0;

        if (hashmap_get(*h, INT_TO_PTR(carrier->ifindex)))
                return 0;

        r = hashmap_ensure_allocated(h, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(*h, INT_TO_PTR(carrier->ifindex), carrier);
        if (r < 0)
                return r;

        return 0;
}

static int link_new_bound_by_list(Link *link) {
        Manager *m;
        Link *carrier;
        int r;
        bool list_updated = false;

        assert(link);
        assert(link->manager);

        m = link->manager;

        HASHMAP_FOREACH(carrier, m->links) {
                if (!carrier->network)
                        continue;

                if (strv_isempty(carrier->network->bind_carrier))
                        continue;

                if (strv_fnmatch(carrier->network->bind_carrier, link->ifname)) {
                        r = link_put_carrier(link, carrier, &link->bound_by_links);
                        if (r < 0)
                                return r;

                        list_updated = true;
                }
        }

        if (list_updated)
                link_dirty(link);

        HASHMAP_FOREACH(carrier, link->bound_by_links) {
                r = link_put_carrier(carrier, link, &carrier->bound_to_links);
                if (r < 0)
                        return r;

                link_dirty(carrier);
        }

        return 0;
}

static int link_new_bound_to_list(Link *link) {
        Manager *m;
        Link *carrier;
        int r;
        bool list_updated = false;

        assert(link);
        assert(link->manager);

        if (!link->network)
                return 0;

        if (strv_isempty(link->network->bind_carrier))
                return 0;

        m = link->manager;

        HASHMAP_FOREACH (carrier, m->links) {
                if (strv_fnmatch(link->network->bind_carrier, carrier->ifname)) {
                        r = link_put_carrier(link, carrier, &link->bound_to_links);
                        if (r < 0)
                                return r;

                        list_updated = true;
                }
        }

        if (list_updated)
                link_dirty(link);

        HASHMAP_FOREACH (carrier, link->bound_to_links) {
                r = link_put_carrier(carrier, link, &carrier->bound_by_links);
                if (r < 0)
                        return r;

                link_dirty(carrier);
        }

        return 0;
}

static int link_new_carrier_maps(Link *link) {
        int r;

        r = link_new_bound_by_list(link);
        if (r < 0)
                return r;

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        r = link_new_bound_to_list(link);
        if (r < 0)
                return r;

        r = link_handle_bound_to_list(link);
        if (r < 0)
                return r;

        return 0;
}

static void link_free_bound_to_list(Link *link) {
        Link *bound_to;

        HASHMAP_FOREACH (bound_to, link->bound_to_links) {
                hashmap_remove(link->bound_to_links, INT_TO_PTR(bound_to->ifindex));

                if (hashmap_remove(bound_to->bound_by_links, INT_TO_PTR(link->ifindex)))
                        link_dirty(bound_to);
        }

        return;
}

static void link_free_bound_by_list(Link *link) {
        Link *bound_by;

        HASHMAP_FOREACH (bound_by, link->bound_by_links) {
                hashmap_remove(link->bound_by_links, INT_TO_PTR(bound_by->ifindex));

                if (hashmap_remove(bound_by->bound_to_links, INT_TO_PTR(link->ifindex))) {
                        link_dirty(bound_by);
                        link_handle_bound_to_list(bound_by);
                }
        }

        return;
}

static void link_free_carrier_maps(Link *link) {
        bool list_updated = false;

        assert(link);

        if (!hashmap_isempty(link->bound_to_links)) {
                link_free_bound_to_list(link);
                list_updated = true;
        }

        if (!hashmap_isempty(link->bound_by_links)) {
                link_free_bound_by_list(link);
                list_updated = true;
        }

        if (list_updated)
                link_dirty(link);

        return;
}

static int link_append_to_master(Link *link, NetDev *netdev) {
        Link *master;
        int r;

        assert(link);
        assert(netdev);

        r = link_get(link->manager, netdev->ifindex, &master);
        if (r < 0)
                return r;

        r = set_ensure_put(&master->slaves, NULL, link);
        if (r <= 0)
                return r;

        link_ref(link);
        return 0;
}

static void link_drop_from_master(Link *link, NetDev *netdev) {
        Link *master;

        assert(link);

        if (!link->manager || !netdev)
                return;

        if (link_get(link->manager, netdev->ifindex, &master) < 0)
                return;

        link_unref(set_remove(master->slaves, link));
}

static void link_detach_from_manager(Link *link) {
        if (!link || !link->manager)
                return;

        link_unref(set_remove(link->manager->links_requesting_uuid, link));
        link_clean(link);

        /* The following must be called at last. */
        assert_se(hashmap_remove(link->manager->links, INT_TO_PTR(link->ifindex)) == link);
        link_unref(link);
}

void link_drop(Link *link) {
        if (!link || link->state == LINK_STATE_LINGER)
                return;

        link_set_state(link, LINK_STATE_LINGER);

        link_free_carrier_maps(link);

        if (link->network) {
                link_drop_from_master(link, link->network->bridge);
                link_drop_from_master(link, link->network->bond);
        }

        log_link_debug(link, "Link removed");

        (void) unlink(link->state_file);
        link_detach_from_manager(link);
}

static int link_joined(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (!hashmap_isempty(link->bound_to_links)) {
                r = link_handle_bound_to_list(link);
                if (r < 0)
                        return r;
        } else if (!(link->flags & IFF_UP)) {
                r = link_up(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        if (link->network->bridge) {
                r = link_set_bridge(link);
                if (r < 0)
                        log_link_error_errno(link, r, "Could not set bridge message: %m");

                r = link_append_to_master(link, link->network->bridge);
                if (r < 0)
                        log_link_error_errno(link, r, "Failed to add to bridge master's slave list: %m");
        }

        if (link->network->bond) {
                r = link_set_bond(link);
                if (r < 0)
                        log_link_error_errno(link, r, "Could not set bond message: %m");

                r = link_append_to_master(link, link->network->bond);
                if (r < 0)
                        log_link_error_errno(link, r, "Failed to add to bond master's slave list: %m");
        }

        r = link_set_bridge_vlan(link);
        if (r < 0)
                log_link_error_errno(link, r, "Could not set bridge vlan: %m");

        /* Skip setting up addresses until it gets carrier,
           or it would try to set addresses twice,
           which is bad for non-idempotent steps. */
        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                return 0;

        link_set_state(link, LINK_STATE_CONFIGURING);

        r = link_acquire_conf(link);
        if (r < 0)
                return r;

        return link_set_static_configs(link);
}

static int netdev_join_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->enslaving > 0);

        link->enslaving--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not join netdev");
                link_enter_failed(link);
                return 1;
        }

        log_link_debug(link, "Joined netdev");

        if (link->enslaving == 0) {
                r = link_joined(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int link_enter_join_netdev(Link *link) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        link_set_state(link, LINK_STATE_CONFIGURING);

        link_dirty(link);
        link->enslaving = 0;

        if (link->network->bond) {
                if (link->network->bond->state == NETDEV_STATE_READY &&
                    link->network->bond->ifindex == link->master_ifindex)
                        return link_joined(link);

                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->bond),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->bond->ifname));

                link->enslaving++;

                r = netdev_join(link->network->bond, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->bond),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->bond->ifname));
                        link_enter_failed(link);
                        return r;
                }
        }

        if (link->network->bridge) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->bridge),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->bridge->ifname));

                link->enslaving++;

                r = netdev_join(link->network->bridge, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->bridge),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->bridge->ifname));
                        link_enter_failed(link);
                        return r;
                }
        }

        if (link->network->vrf) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->vrf),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->vrf->ifname));

                link->enslaving++;

                r = netdev_join(link->network->vrf, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->vrf),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->vrf->ifname));
                        link_enter_failed(link);
                        return r;
                }
        }

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs) {

                if (netdev->ifindex > 0)
                        /* Assume already enslaved. */
                        continue;

                if (netdev_get_create_type(netdev) != NETDEV_CREATE_STACKED)
                        continue;

                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(netdev),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", netdev->ifname));

                link->enslaving++;

                r = netdev_join(netdev, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(netdev),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", netdev->ifname));
                        link_enter_failed(link);
                        return r;
                }
        }

        if (link->enslaving == 0)
                return link_joined(link);

        return 0;
}

static int link_drop_foreign_config(Link *link) {
        int r;

        r = link_drop_foreign_addresses(link);
        if (r < 0)
                return r;

        r = link_drop_foreign_neighbors(link);
        if (r < 0)
                return r;

        return link_drop_foreign_routes(link);
}

static int link_drop_config(Link *link) {
        int r;

        r = link_drop_addresses(link);
        if (r < 0)
                return r;

        r = link_drop_neighbors(link);
        if (r < 0)
                return r;

        r = link_drop_routes(link);
        if (r < 0)
                return r;

        ndisc_flush(link);

        return 0;
}

int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        r = link_configure_traffic_control(link);
        if (r < 0)
                return r;

        r = link_configure_sr_iov(link);
        if (r < 0)
                return r;

        if (link->iftype == ARPHRD_CAN)
                return link_configure_can(link);

        r = link_set_sysctl(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_proxy_ndp_addresses(link);
        if (r < 0)
                return r;

        r = link_set_mac(link);
        if (r < 0)
                return r;

        r = link_set_nomaster(link);
        if (r < 0)
                return r;

        r = link_set_flags(link);
        if (r < 0)
                return r;

        r = link_set_group(link);
        if (r < 0)
                return r;

        r = ipv4ll_configure(link);
        if (r < 0)
                return r;

        r = dhcp4_configure(link);
        if (r < 0)
                return r;

        r = dhcp6_configure(link);
        if (r < 0)
                return r;

        r = ndisc_configure(link);
        if (r < 0)
                return r;

        r = radv_configure(link);
        if (r < 0)
                return r;

        r = link_lldp_rx_configure(link);
        if (r < 0)
                return r;

        r = link_configure_mtu(link);
        if (r < 0)
                return r;

        r = link_configure_addrgen_mode(link);
        if (r < 0)
                return r;

        return link_configure_continue(link);
}

/* The configuration continues in this separate function, instead of
 * including this in the above link_configure() function, for two
 * reasons:
 * 1) some devices reset the link when the mtu is set, which caused
 *    an infinite loop here in networkd; see:
 *    https://github.com/systemd/systemd/issues/6593
 *    https://github.com/systemd/systemd/issues/9831
 * 2) if ipv6ll is disabled, then bringing the interface up must be
 *    delayed until after we get confirmation from the kernel that
 *    the addr_gen_mode parameter has been set (via netlink), see:
 *    https://github.com/systemd/systemd/issues/13882
 */
static int link_configure_continue(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        if (link->setting_mtu || link->setting_genmode)
                return 0;

        /* Drop foreign config, but ignore loopback or critical devices.
         * We do not want to remove loopback address or addresses used for root NFS. */
        if (!(link->flags & IFF_LOOPBACK) &&
            link->network->keep_configuration != KEEP_CONFIGURATION_YES) {
                r = link_drop_foreign_config(link);
                if (r < 0)
                        return r;
        }

        /* The kernel resets ipv6 mtu after changing device mtu;
         * we must set this here, after we've set device mtu */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 MTU for interface, ignoring: %m");

        return link_enter_join_netdev(link);
}

static int link_reconfigure_internal(Link *link, sd_netlink_message *m, bool force) {
        Network *network;
        int r;

        if (m) {
                _cleanup_strv_free_ char **s = NULL;

                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &s);
                if (r < 0 && r != -ENODATA)
                        return r;

                strv_free_and_replace(link->alternative_names, s);
        }

        r = network_get(link->manager, link->iftype, link->sd_device,
                        link->ifname, link->alternative_names, link->driver,
                        &link->hw_addr.addr.ether, &link->permanent_mac,
                        link->wlan_iftype, link->ssid, &link->bssid, &network);
        if (r == -ENOENT) {
                link_enter_unmanaged(link);
                return 0;
        } else if (r == 0 && network->unmanaged) {
                link_enter_unmanaged(link);
                return 0;
        } else if (r < 0)
                return r;

        if (link->network == network && !force)
                return 0;

        log_link_info(link, "Re-configuring with %s", network->filename);

        /* Dropping old .network file */
        r = link_stop_engines(link, false);
        if (r < 0)
                return r;

        r = link_drop_config(link);
        if (r < 0)
                return r;

        if (!IN_SET(link->state, LINK_STATE_UNMANAGED, LINK_STATE_PENDING, LINK_STATE_INITIALIZED)) {
                log_link_debug(link, "State is %s, dropping config", link_state_to_string(link->state));
                r = link_drop_foreign_config(link);
                if (r < 0)
                        return r;
        }

        link_free_carrier_maps(link);
        link_free_engines(link);
        link->network = network_unref(link->network);

        /* Then, apply new .network file */
        r = network_apply(network, link);
        if (r < 0)
                return r;

        r = link_new_carrier_maps(link);
        if (r < 0)
                return r;

        link_set_state(link, LINK_STATE_INITIALIZED);
        link_dirty(link);

        /* link_configure_duid() returns 0 if it requests product UUID. In that case,
         * link_configure() is called later asynchronously. */
        r = link_configure_duid(link);
        if (r <= 0)
                return r;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 0;
}

static int link_reconfigure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = link_reconfigure_internal(link, m, false);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int link_force_reconfigure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = link_reconfigure_internal(link, m, true);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

int link_reconfigure(Link *link, bool force) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        if (IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_LINGER))
                return 0;

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_GETLINK,
                                     link->ifindex);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               force ? link_force_reconfigure_handler : link_reconfigure_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return r;

        link_ref(link);

        return 0;
}

static int link_initialized_and_synced(Link *link) {
        Network *network;
        int r;

        assert(link);
        assert(link->ifname);
        assert(link->manager);

        /* We may get called either from the asynchronous netlink callback,
         * or directly for link_add() if running in a container. See link_add(). */
        if (!IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_INITIALIZED))
                return 0;

        log_link_debug(link, "Link state is up-to-date");
        link_set_state(link, LINK_STATE_INITIALIZED);

        r = link_new_bound_by_list(link);
        if (r < 0)
                return r;

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        if (!link->network) {
                r = wifi_get_info(link);
                if (r < 0)
                        return r;

                r = network_get(link->manager, link->iftype, link->sd_device,
                                link->ifname, link->alternative_names, link->driver,
                                &link->hw_addr.addr.ether, &link->permanent_mac,
                                link->wlan_iftype, link->ssid, &link->bssid, &network);
                if (r == -ENOENT) {
                        link_enter_unmanaged(link);
                        return 0;
                } else if (r == 0 && network->unmanaged) {
                        link_enter_unmanaged(link);
                        return 0;
                } else if (r < 0)
                        return r;

                if (link->flags & IFF_LOOPBACK) {
                        if (network->link_local != ADDRESS_FAMILY_NO)
                                log_link_debug(link, "Ignoring link-local autoconfiguration for loopback link");

                        if (network->dhcp != ADDRESS_FAMILY_NO)
                                log_link_debug(link, "Ignoring DHCP clients for loopback link");

                        if (network->dhcp_server)
                                log_link_debug(link, "Ignoring DHCP server for loopback link");
                }

                r = network_apply(network, link);
                if (r < 0)
                        return r;
        }

        r = link_new_bound_to_list(link);
        if (r < 0)
                return r;

        /* link_configure_duid() returns 0 if it requests product UUID. In that case,
         * link_configure() is called later asynchronously. */
        r = link_configure_duid(link);
        if (r <= 0)
                return r;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 0;
}

static int link_initialized_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        _cleanup_strv_free_ char **s = NULL;
        int r;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to wait for the interface to be initialized: %m");
                link_enter_failed(link);
                return 0;
        }

        r = sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &s);
        if (r < 0 && r != -ENODATA) {
                link_enter_failed(link);
                return 0;
        }

        strv_free_and_replace(link->alternative_names, s);

        r = link_initialized_and_synced(link);
        if (r < 0)
                link_enter_failed(link);
        return 1;
}

int link_initialized(Link *link, sd_device *device) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(device);

        if (link->state != LINK_STATE_PENDING)
                return 0;

        if (link->sd_device)
                return 0;

        log_link_debug(link, "udev initialized link");
        link_set_state(link, LINK_STATE_INITIALIZED);

        link->sd_device = sd_device_ref(device);

        /* udev has initialized the link, but we don't know if we have yet
         * processed the NEWLINK messages with the latest state. Do a GETLINK,
         * when it returns we know that the pending NEWLINKs have already been
         * processed and that we are up-to-date */

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_GETLINK,
                                     link->ifindex);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_initialized_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return r;

        link_ref(link);

        return 0;
}

static int link_load(Link *link) {
        _cleanup_free_ char *network_file = NULL,
                            *addresses = NULL,
                            *routes = NULL,
                            *dhcp4_address = NULL,
                            *ipv4ll_address = NULL;
        int r;

        assert(link);

        r = parse_env_file(NULL, link->state_file,
                           "NETWORK_FILE", &network_file,
                           "ADDRESSES", &addresses,
                           "ROUTES", &routes,
                           "DHCP4_ADDRESS", &dhcp4_address,
                           "IPV4LL_ADDRESS", &ipv4ll_address);
        if (r < 0 && r != -ENOENT)
                return log_link_error_errno(link, r, "Failed to read %s: %m", link->state_file);

        if (network_file) {
                Network *network;
                char *suffix;

                /* drop suffix */
                suffix = strrchr(network_file, '.');
                if (!suffix) {
                        log_link_debug(link, "Failed to get network name from %s", network_file);
                        goto network_file_fail;
                }
                *suffix = '\0';

                r = network_get_by_name(link->manager, basename(network_file), &network);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Failed to get network %s: %m", basename(network_file));
                        goto network_file_fail;
                }

                r = network_apply(network, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to apply network %s: %m", basename(network_file));
        }

network_file_fail:

        r = link_deserialize_addresses(link, addresses);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to load addresses from %s, ignoring: %m", link->state_file);

        r = link_deserialize_routes(link, routes);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to load routes from %s, ignoring: %m", link->state_file);

        r = link_deserialize_dhcp4(link, dhcp4_address);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to load DHCPv4 address from %s, ignoring: %m", link->state_file);

        r = link_deserialize_ipv4ll(link, ipv4ll_address);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to load IPv4LL address from %s, ignoring: %m", link->state_file);

        return 0;
}

int link_add(Manager *m, sd_netlink_message *message, Link **ret) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        char ifindex_str[2 + DECIMAL_STR_MAX(int)];
        Link *link;
        int r;

        assert(m);
        assert(m->rtnl);
        assert(message);
        assert(ret);

        r = link_new(m, message, ret);
        if (r < 0)
                return r;

        link = *ret;

        log_link_debug(link, "Link %d added", link->ifindex);

        r = link_load(link);
        if (r < 0)
                return r;

        if (path_is_read_only_fs("/sys") <= 0) {
                /* udev should be around */
                sprintf(ifindex_str, "n%d", link->ifindex);
                r = sd_device_new_from_device_id(&device, ifindex_str);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not find device, waiting for device initialization: %m");
                        return 0;
                }

                r = sd_device_get_is_initialized(device);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not determine whether the device is initialized: %m");
                        goto failed;
                }
                if (r == 0) {
                        /* not yet ready */
                        log_link_debug(link, "link pending udev initialization...");
                        return 0;
                }

                r = device_is_renaming(device);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to determine the device is being renamed: %m");
                        goto failed;
                }
                if (r > 0) {
                        log_link_debug(link, "Interface is being renamed, pending initialization.");
                        return 0;
                }

                r = link_initialized(link, device);
                if (r < 0)
                        goto failed;
        } else {
                r = link_initialized_and_synced(link);
                if (r < 0)
                        goto failed;
        }

        return 0;
failed:
        link_enter_failed(link);
        return r;
}

int link_ipv6ll_gained(Link *link, const struct in6_addr *address) {
        int r;

        assert(link);

        log_link_info(link, "Gained IPv6LL");

        link->ipv6ll_address = *address;
        link_check_ready(link);

        if (IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED)) {
                r = link_acquire_ipv6_conf(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        return 0;
}

static int link_carrier_gained(Link *link) {
        int r;

        assert(link);

        r = wifi_get_info(link);
        if (r < 0)
                return r;
        if (r > 0) {
                r = link_reconfigure_internal(link, NULL, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        if (IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED)) {
                r = link_acquire_conf(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }

                link_set_state(link, LINK_STATE_CONFIGURING);
                r = link_set_static_configs(link);
                if (r < 0)
                        return r;
        }

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        if (!link->bridge_mdb_configured) {
                r = link_set_bridge_mdb(link);
                if (r < 0)
                        return r;
        }

        if (streq_ptr(link->kind, "bridge")) {
                Link *slave;

                SET_FOREACH(slave, link->slaves) {
                        if (slave->bridge_mdb_configured)
                                continue;

                        r = link_set_bridge_mdb(slave);
                        if (r < 0)
                                link_enter_failed(slave);
                }
        }

        return 0;
}

static int link_carrier_lost(Link *link) {
        int r;

        assert(link);

        if (link->network && link->network->ignore_carrier_loss)
                return 0;

        /* Some devices reset itself while setting the MTU. This causes the DHCP client fall into a loop.
         * setting_mtu keep track whether the device got reset because of setting MTU and does not drop the
         * configuration and stop the clients as well. */
        if (link->setting_mtu)
                return 0;

        r = link_stop_engines(link, false);
        if (r < 0) {
                link_enter_failed(link);
                return r;
        }

        r = link_drop_config(link);
        if (r < 0)
                return r;

        if (!IN_SET(link->state, LINK_STATE_UNMANAGED, LINK_STATE_PENDING, LINK_STATE_INITIALIZED)) {
                log_link_debug(link, "State is %s, dropping config", link_state_to_string(link->state));
                r = link_drop_foreign_config(link);
                if (r < 0)
                        return r;
        }

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        return 0;
}

int link_carrier_reset(Link *link) {
        int r;

        assert(link);

        if (link_has_carrier(link)) {
                r = link_carrier_lost(link);
                if (r < 0)
                        return r;

                r = link_carrier_gained(link);
                if (r < 0)
                        return r;

                log_link_info(link, "Reset carrier");
        }

        return 0;
}

/* This is called every time an interface admin state changes to up;
 * specifically, when IFF_UP flag changes from unset to set */
static int link_admin_state_up(Link *link) {
        int r;

        /* We set the ipv6 mtu after the device mtu, but the kernel resets
         * ipv6 mtu on NETDEV_UP, so we need to reset it.  The check for
         * ipv6_mtu_set prevents this from trying to set it too early before
         * the link->network has been setup; we only need to reset it
         * here if we've already set it during normal initialization. */
        if (link->ipv6_mtu_set) {
                r = link_set_ipv6_mtu(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_update(Link *link, sd_netlink_message *m) {
        _cleanup_strv_free_ char **s = NULL;
        hw_addr_data hw_addr;
        const char *ifname;
        uint32_t mtu;
        bool had_carrier, carrier_gained, carrier_lost, link_was_admin_up;
        int old_master, r;

        assert(link);
        assert(link->ifname);
        assert(m);

        if (link->state == LINK_STATE_LINGER) {
                log_link_info(link, "Link re-added");
                link_set_state(link, LINK_STATE_CONFIGURING);

                r = link_new_carrier_maps(link);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r >= 0 && !streq(ifname, link->ifname)) {
                Manager *manager = link->manager;

                log_link_info(link, "Interface name change detected, %s has been renamed to %s.", link->ifname, ifname);

                link_drop(link);
                r = link_add(manager, m, &link);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &s);
        if (r >= 0)
                strv_free_and_replace(link->alternative_names, s);

        r = sd_netlink_message_read_u32(m, IFLA_MTU, &mtu);
        if (r >= 0 && mtu > 0) {
                link->mtu = mtu;
                if (link->original_mtu == 0) {
                        link->original_mtu = mtu;
                        log_link_debug(link, "Saved original MTU: %" PRIu32, link->original_mtu);
                }

                if (link->dhcp_client) {
                        r = sd_dhcp_client_set_mtu(link->dhcp_client,
                                                   link->mtu);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not update MTU in DHCP client: %m");
                }

                if (link->radv) {
                        r = sd_radv_set_mtu(link->radv, link->mtu);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not set MTU for Router Advertisement: %m");
                }
        }

        /* The kernel may broadcast NEWLINK messages without the MAC address
           set, simply ignore them. */
        r = netlink_message_read_hw_addr(m, IFLA_ADDRESS, &hw_addr);
        if (r >= 0 && (link->hw_addr.length != hw_addr.length ||
                       memcmp(link->hw_addr.addr.bytes, hw_addr.addr.bytes, hw_addr.length) != 0)) {

                memcpy(link->hw_addr.addr.bytes, hw_addr.addr.bytes, hw_addr.length);

                log_link_debug(link, "Gained new hardware address: %s", HW_ADDR_TO_STR(&hw_addr));

                r = ipv4ll_update_mac(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not update MAC address in IPv4LL client: %m");

                r = dhcp4_update_mac(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCP client: %m");

                r = dhcp6_update_mac(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCPv6 client: %m");

                r = radv_update_mac(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not update MAC address for Router Advertisement: %m");

                if (link->ndisc) {
                        r = sd_ndisc_set_mac(link->ndisc, &link->hw_addr.addr.ether);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not update MAC for NDisc: %m");
                }

                r = ipv4_dad_update_mac(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not update MAC address in IPv4 ACD client: %m");
        }

        old_master = link->master_ifindex;
        (void) sd_netlink_message_read_u32(m, IFLA_MASTER, (uint32_t *) &link->master_ifindex);

        link_was_admin_up = link->flags & IFF_UP;
        had_carrier = link_has_carrier(link);

        r = link_update_flags(link, m, old_master != link->master_ifindex);
        if (r < 0)
                return r;

        if (!link_was_admin_up && (link->flags & IFF_UP)) {
                log_link_info(link, "Link UP");

                r = link_admin_state_up(link);
                if (r < 0)
                        return r;
        } else if (link_was_admin_up && !(link->flags & IFF_UP))
                log_link_info(link, "Link DOWN");

        r = link_update_lldp(link);
        if (r < 0)
                return r;

        carrier_gained = !had_carrier && link_has_carrier(link);
        carrier_lost = had_carrier && !link_has_carrier(link);

        if (carrier_gained) {
                log_link_info(link, "Gained carrier");

                r = link_carrier_gained(link);
                if (r < 0)
                        return r;
        } else if (carrier_lost) {
                log_link_info(link, "Lost carrier");

                r = link_carrier_lost(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void print_link_hashmap(FILE *f, const char *prefix, Hashmap* h) {
        bool space = false;
        Link *link;

        assert(f);
        assert(prefix);

        if (hashmap_isempty(h))
                return;

        fputs(prefix, f);
        HASHMAP_FOREACH(link, h) {
                if (space)
                        fputc(' ', f);

                fprintf(f, "%i", link->ifindex);
                space = true;
        }

        fputc('\n', f);
}

static void link_save_dns(Link *link, FILE *f, struct in_addr_full **dns, unsigned n_dns, bool *space) {
        for (unsigned j = 0; j < n_dns; j++) {
                const char *str;

                if (dns[j]->ifindex != 0 && dns[j]->ifindex != link->ifindex)
                        continue;

                str = in_addr_full_to_string(dns[j]);
                if (!str)
                        continue;

                if (*space)
                        fputc(' ', f);
                fputs(str, f);
                *space = true;
        }
}

static void serialize_addresses(
                FILE *f,
                const char *lvalue,
                bool *space,
                char **addresses,
                sd_dhcp_lease *lease,
                bool conditional,
                sd_dhcp_lease_server_type what,
                sd_dhcp6_lease *lease6,
                bool conditional6,
                int (*lease6_get_addr)(sd_dhcp6_lease*, const struct in6_addr**),
                int (*lease6_get_fqdn)(sd_dhcp6_lease*, char ***)) {
        int r;

        bool _space = false;
        if (!space)
                space = &_space;

        if (lvalue)
                fprintf(f, "%s=", lvalue);
        fputstrv(f, addresses, NULL, space);

        if (lease && conditional) {
                const struct in_addr *lease_addresses;

                r = sd_dhcp_lease_get_servers(lease, what, &lease_addresses);
                if (r > 0)
                        serialize_in_addrs(f, lease_addresses, r, space, in4_addr_is_non_local);
        }

        if (lease6 && conditional6 && lease6_get_addr) {
                const struct in6_addr *in6_addrs;

                r = lease6_get_addr(lease6, &in6_addrs);
                if (r > 0)
                        serialize_in6_addrs(f, in6_addrs, r, space);
        }

        if (lease6 && conditional6 && lease6_get_fqdn) {
                char **in6_hosts;

                r = lease6_get_fqdn(lease6, &in6_hosts);
                if (r > 0)
                        fputstrv(f, in6_hosts, NULL, space);
        }

        if (lvalue)
                fputc('\n', f);
}

int link_save(Link *link) {
        const char *admin_state, *oper_state, *carrier_state, *address_state;
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(link);
        assert(link->state_file);
        assert(link->lease_file);
        assert(link->manager);

        if (link->state == LINK_STATE_LINGER) {
                (void) unlink(link->state_file);
                return 0;
        }

        link_lldp_save(link);

        admin_state = link_state_to_string(link->state);
        assert(admin_state);

        oper_state = link_operstate_to_string(link->operstate);
        assert(oper_state);

        carrier_state = link_carrier_state_to_string(link->carrier_state);
        assert(carrier_state);

        address_state = link_address_state_to_string(link->address_state);
        assert(address_state);

        r = fopen_temporary(link->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADMIN_STATE=%s\n"
                "OPER_STATE=%s\n"
                "CARRIER_STATE=%s\n"
                "ADDRESS_STATE=%s\n",
                admin_state, oper_state, carrier_state, address_state);

        if (link->network) {
                char **dhcp6_domains = NULL, **dhcp_domains = NULL;
                const char *dhcp_domainname = NULL, *p;
                bool space;

                fprintf(f, "REQUIRED_FOR_ONLINE=%s\n",
                        yes_no(link->network->required_for_online));

                LinkOperationalStateRange st = link->network->required_operstate_for_online;
                fprintf(f, "REQUIRED_OPER_STATE_FOR_ONLINE=%s%s%s\n",
                        strempty(link_operstate_to_string(st.min)),
                        st.max != LINK_OPERSTATE_RANGE_DEFAULT.max ? ":" : "",
                        st.max != LINK_OPERSTATE_RANGE_DEFAULT.max ? strempty(link_operstate_to_string(st.max)) : "");

                fprintf(f, "NETWORK_FILE=%s\n", link->network->filename);

                /************************************************************/

                fputs("DNS=", f);
                space = false;
                if (link->n_dns != (unsigned) -1)
                        link_save_dns(link, f, link->dns, link->n_dns, &space);
                else
                        link_save_dns(link, f, link->network->dns, link->network->n_dns, &space);

                serialize_addresses(f, NULL, &space,
                                    NULL,
                                    link->dhcp_lease,
                                    link->network->dhcp_use_dns,
                                    SD_DHCP_LEASE_DNS,
                                    link->dhcp6_lease,
                                    link->network->dhcp6_use_dns,
                                    sd_dhcp6_lease_get_dns,
                                    NULL);

                /* Make sure to flush out old entries before we use the NDisc data */
                ndisc_vacuum(link);

                if (link->network->ipv6_accept_ra_use_dns && link->ndisc_rdnss) {
                        NDiscRDNSS *dd;

                        SET_FOREACH(dd, link->ndisc_rdnss)
                                serialize_in6_addrs(f, &dd->address, 1, &space);
                }

                fputc('\n', f);

                /************************************************************/

                serialize_addresses(f, "NTP", NULL,
                                    link->ntp ?: link->network->ntp,
                                    link->dhcp_lease,
                                    link->network->dhcp_use_ntp,
                                    SD_DHCP_LEASE_NTP,
                                    link->dhcp6_lease,
                                    link->network->dhcp6_use_ntp,
                                    sd_dhcp6_lease_get_ntp_addrs,
                                    sd_dhcp6_lease_get_ntp_fqdn);

                serialize_addresses(f, "SIP", NULL,
                                    NULL,
                                    link->dhcp_lease,
                                    link->network->dhcp_use_sip,
                                    SD_DHCP_LEASE_SIP,
                                    NULL, false, NULL, NULL);

                /************************************************************/

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        if (link->dhcp_lease) {
                                (void) sd_dhcp_lease_get_domainname(link->dhcp_lease, &dhcp_domainname);
                                (void) sd_dhcp_lease_get_search_domains(link->dhcp_lease, &dhcp_domains);
                        }
                        if (link->dhcp6_lease)
                                (void) sd_dhcp6_lease_get_domains(link->dhcp6_lease, &dhcp6_domains);
                }

                fputs("DOMAINS=", f);
                space = false;
                ORDERED_SET_FOREACH(p, link->search_domains ?: link->network->search_domains)
                        fputs_with_space(f, p, NULL, &space);

                if (link->network->dhcp_use_domains == DHCP_USE_DOMAINS_YES) {
                        if (dhcp_domainname)
                                fputs_with_space(f, dhcp_domainname, NULL, &space);
                        if (dhcp_domains)
                                fputstrv(f, dhcp_domains, NULL, &space);
                        if (dhcp6_domains)
                                fputstrv(f, dhcp6_domains, NULL, &space);
                }

                if (link->network->ipv6_accept_ra_use_domains == DHCP_USE_DOMAINS_YES) {
                        NDiscDNSSL *dd;

                        SET_FOREACH(dd, link->ndisc_dnssl)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                /************************************************************/

                fputs("ROUTE_DOMAINS=", f);
                space = false;
                ORDERED_SET_FOREACH(p, link->route_domains ?: link->network->route_domains)
                        fputs_with_space(f, p, NULL, &space);

                if (link->network->dhcp_use_domains == DHCP_USE_DOMAINS_ROUTE) {
                        if (dhcp_domainname)
                                fputs_with_space(f, dhcp_domainname, NULL, &space);
                        if (dhcp_domains)
                                fputstrv(f, dhcp_domains, NULL, &space);
                        if (dhcp6_domains)
                                fputstrv(f, dhcp6_domains, NULL, &space);
                }

                if (link->network->ipv6_accept_ra_use_domains == DHCP_USE_DOMAINS_ROUTE) {
                        NDiscDNSSL *dd;

                        SET_FOREACH(dd, link->ndisc_dnssl)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                /************************************************************/

                fprintf(f, "LLMNR=%s\n",
                        resolve_support_to_string(link->llmnr >= 0 ? link->llmnr : link->network->llmnr));

                /************************************************************/

                fprintf(f, "MDNS=%s\n",
                        resolve_support_to_string(link->mdns >= 0 ? link->mdns : link->network->mdns));

                /************************************************************/

                int dns_default_route =
                        link->dns_default_route >= 0 ? link->dns_default_route :
                        link->network->dns_default_route;
                if (dns_default_route >= 0)
                        fprintf(f, "DNS_DEFAULT_ROUTE=%s\n", yes_no(dns_default_route));

                /************************************************************/

                DnsOverTlsMode dns_over_tls_mode =
                        link->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID ? link->dns_over_tls_mode :
                        link->network->dns_over_tls_mode;
                if (dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                        fprintf(f, "DNS_OVER_TLS=%s\n", dns_over_tls_mode_to_string(dns_over_tls_mode));

                /************************************************************/

                DnssecMode dnssec_mode =
                        link->dnssec_mode != _DNSSEC_MODE_INVALID ? link->dnssec_mode :
                        link->network->dnssec_mode;
                if (dnssec_mode != _DNSSEC_MODE_INVALID)
                        fprintf(f, "DNSSEC=%s\n", dnssec_mode_to_string(dnssec_mode));

                /************************************************************/

                Set *nta_anchors = link->dnssec_negative_trust_anchors;
                if (set_isempty(nta_anchors))
                        nta_anchors = link->network->dnssec_negative_trust_anchors;

                if (!set_isempty(nta_anchors)) {
                        const char *n;

                        fputs("DNSSEC_NTA=", f);
                        space = false;
                        SET_FOREACH(n, nta_anchors)
                                fputs_with_space(f, n, NULL, &space);
                        fputc('\n', f);
                }

                /************************************************************/

                r = link_serialize_addresses(link, f);
                if (r < 0)
                        goto fail;

                /************************************************************/

                r = link_serialize_routes(link, f);
                if (r < 0)
                        goto fail;
        }

        print_link_hashmap(f, "CARRIER_BOUND_TO=", link->bound_to_links);
        print_link_hashmap(f, "CARRIER_BOUND_BY=", link->bound_by_links);

        if (link->dhcp_lease) {
                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        goto fail;

                fprintf(f,
                        "DHCP_LEASE=%s\n",
                        link->lease_file);
        } else
                (void) unlink(link->lease_file);

        r = link_serialize_ipv4ll(link, f);
        if (r < 0)
                goto fail;

        r = link_serialize_dhcp6_client(link, f);
        if (r < 0)
                goto fail;

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, link->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(link->state_file);
        if (temp_path)
                (void) unlink(temp_path);

        return log_link_error_errno(link, r, "Failed to save link data to %s: %m", link->state_file);
}

/* The serialized state in /run is no longer up-to-date. */
void link_dirty(Link *link) {
        int r;

        assert(link);

        /* mark manager dirty as link is dirty */
        manager_dirty(link->manager);

        r = set_ensure_put(&link->manager->dirty_links, NULL, link);
        if (r <= 0)
                /* Ignore allocation errors and don't take another ref if the link was already dirty */
                return;
        link_ref(link);
}

/* The serialized state in /run is up-to-date */
void link_clean(Link *link) {
        assert(link);
        assert(link->manager);

        link_unref(set_remove(link->manager->dirty_links, link));
}

int link_save_and_clean(Link *link) {
        int r;

        r = link_save(link);
        if (r < 0)
                return r;

        link_clean(link);
        return 0;
}

static const char* const link_state_table[_LINK_STATE_MAX] = {
        [LINK_STATE_PENDING] = "pending",
        [LINK_STATE_INITIALIZED] = "initialized",
        [LINK_STATE_CONFIGURING] = "configuring",
        [LINK_STATE_CONFIGURED] = "configured",
        [LINK_STATE_UNMANAGED] = "unmanaged",
        [LINK_STATE_FAILED] = "failed",
        [LINK_STATE_LINGER] = "linger",
};

DEFINE_STRING_TABLE_LOOKUP(link_state, LinkState);

int log_link_message_full_errno(Link *link, sd_netlink_message *m, int level, int err, const char *msg) {
        const char *err_msg = NULL;

        (void) sd_netlink_message_read_string(m, NLMSGERR_ATTR_MSG, &err_msg);
        return log_link_full_errno(link, level, err,
                                   "%s: %s%s%s%m",
                                   msg,
                                   strempty(err_msg),
                                   err_msg && !endswith(err_msg, ".") ? "." : "",
                                   err_msg ? " " : "");
}

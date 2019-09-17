/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "dhcp-identifier.h"
#include "dhcp-lease-internal.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "missing_network.h"
#include "netdev/bond.h"
#include "netdev/bridge.h"
#include "netdev/ipvlan.h"
#include "netdev/vrf.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-can.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-ipv4ll.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-radv.h"
#include "networkd-routing-policy-rule.h"
#include "set.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "util.h"
#include "virt.h"

uint32_t link_get_vrf_table(Link *link) {
        return link->network->vrf ? VRF(link->network->vrf)->table : RT_TABLE_MAIN;
}

uint32_t link_get_dhcp_route_table(Link *link) {
        /* When the interface is part of an VRF use the VRFs routing table, unless
         * another table is explicitly specified. */
        if (link->network->dhcp_route_table_set)
                return link->network->dhcp_route_table;
        return link_get_vrf_table(link);
}

uint32_t link_get_ipv6_accept_ra_route_table(Link *link) {
        if (link->network->ipv6_accept_ra_route_table_set)
                return link->network->ipv6_accept_ra_route_table;
        return link_get_vrf_table(link);
}

DUID* link_get_duid(Link *link) {
        if (link->network->duid.type != _DUID_TYPE_INVALID)
                return &link->network->duid;
        else
                return &link->manager->duid;
}

static bool link_dhcp6_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->bond)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->dhcp & ADDRESS_FAMILY_IPV6;
}

static bool link_dhcp4_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->bond)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->dhcp & ADDRESS_FAMILY_IPV4;
}

static bool link_dhcp4_server_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->bond)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->dhcp_server;
}

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
                          "vti6", "nlmon", "xfrm"))
                return false;

        /* L3 or L3S mode do not support ARP. */
        if (IN_SET(link_get_ipvlan_mode(link), NETDEV_IPVLAN_MODE_L3, NETDEV_IPVLAN_MODE_L3S))
                return false;

        if (link->network->bond)
                return false;

        return link->network->link_local & mask;
}

static bool link_ipv6ll_enabled(Link *link) {
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

static bool link_ipv6_enabled(Link *link) {
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

static bool link_radv_enabled(Link *link) {
        assert(link);

        if (!link_ipv6ll_enabled(link))
                return false;

        return link->network->router_prefix_delegation != RADV_PREFIX_DELEGATION_NONE;
}

static bool link_ipv4_forward_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->ip_forward == _ADDRESS_FAMILY_INVALID)
                return false;

        return link->network->ip_forward & ADDRESS_FAMILY_IPV4;
}

static bool link_ipv6_forward_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->ip_forward == _ADDRESS_FAMILY_INVALID)
                return false;

        return link->network->ip_forward & ADDRESS_FAMILY_IPV6;
}

static bool link_proxy_arp_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->proxy_arp < 0)
                return false;

        return true;
}

static bool link_ipv6_accept_ra_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (!link_ipv6ll_enabled(link))
                return false;

        /* If unset use system default (enabled if local forwarding is disabled.
         * disabled if local forwarding is enabled).
         * If set, ignore or enforce RA independent of local forwarding state.
         */
        if (link->network->ipv6_accept_ra < 0)
                /* default to accept RA if ip_forward is disabled and ignore RA if ip_forward is enabled */
                return !link_ipv6_forward_enabled(link);
        else if (link->network->ipv6_accept_ra > 0)
                /* accept RA even if ip_forward is enabled */
                return true;
        else
                /* ignore RA */
                return false;
}

static IPv6PrivacyExtensions link_ipv6_privacy_extensions(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return _IPV6_PRIVACY_EXTENSIONS_INVALID;

        if (link->flags & IFF_LOOPBACK)
                return _IPV6_PRIVACY_EXTENSIONS_INVALID;

        if (!link->network)
                return _IPV6_PRIVACY_EXTENSIONS_INVALID;

        return link->network->ipv6_privacy_extensions;
}

static int link_update_ipv6_sysctl(Link *link) {
        bool enabled;
        int r;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        enabled = link_ipv6_enabled(link);
        if (enabled) {
                r = sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "disable_ipv6", false);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Cannot enable IPv6: %m");

                log_link_info(link, "IPv6 successfully enabled");
        }

        return 0;
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
        Iterator i;

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

                SET_FOREACH(slave, link->slaves, i) {
                        link_update_operstate(slave, false);

                        if (slave->carrier_state < LINK_CARRIER_STATE_CARRIER)
                                carrier_state = LINK_CARRIER_STATE_DEGRADED_CARRIER;
                }
        }

        SET_FOREACH(address, link->addresses, i) {
                if (!address_is_ready(address))
                        continue;

                if (address->scope < scope)
                        scope = address->scope;
        }

        /* for operstate we also take foreign addresses into account */
        SET_FOREACH(address, link->addresses_foreign, i) {
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
        uint16_t type;
        const char *ifname, *kind = NULL;
        int r, ifindex;
        unsigned short iftype;

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

        r = sd_netlink_message_read_ether_addr(message, IFLA_ADDRESS, &link->mac);
        if (r < 0)
                log_link_debug_errno(link, r, "MAC address not found for new device, continuing without");

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

static Link *link_free(Link *link) {
        Address *address;

        assert(link);

        link_ntp_settings_clear(link);
        link_dns_settings_clear(link);

        link->routes = set_free_with_destructor(link->routes, route_free);
        link->routes_foreign = set_free_with_destructor(link->routes_foreign, route_free);

        link->neighbors = set_free_with_destructor(link->neighbors, neighbor_free);
        link->neighbors_foreign = set_free_with_destructor(link->neighbors_foreign, neighbor_free);

        link->addresses = set_free_with_destructor(link->addresses, address_free);
        link->addresses_foreign = set_free_with_destructor(link->addresses_foreign, address_free);

        while ((address = link->pool_addresses)) {
                LIST_REMOVE(addresses, link->pool_addresses, address);
                address_free(address);
        }

        sd_dhcp_server_unref(link->dhcp_server);
        sd_dhcp_client_unref(link->dhcp_client);
        sd_dhcp_lease_unref(link->dhcp_lease);
        set_free(link->dhcp_routes);

        link_lldp_emit_stop(link);

        free(link->lease_file);

        sd_lldp_unref(link->lldp);
        free(link->lldp_file);

        ndisc_flush(link);

        sd_ipv4ll_unref(link->ipv4ll);
        sd_dhcp6_client_unref(link->dhcp6_client);
        sd_ndisc_unref(link->ndisc);
        sd_radv_unref(link->radv);

        free(link->ifname);
        free(link->kind);

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
        assert(ifindex);
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

int link_stop_clients(Link *link, bool may_keep_dhcp) {
        int r = 0, k;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        dhcp4_release_old_lease(link);

        if (link->dhcp_client && (!may_keep_dhcp || !link->network ||
                                  !FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP_ON_STOP))) {
                k = sd_dhcp_client_stop(link->dhcp_client);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop DHCPv4 client: %m");
        }

        if (link->ipv4ll) {
                k = sd_ipv4ll_stop(link->ipv4ll);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop IPv4 link-local: %m");
        }

        if (link->dhcp6_client) {
                k = sd_dhcp6_client_stop(link->dhcp6_client);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop DHCPv6 client: %m");
        }

        if (link->ndisc) {
                k = sd_ndisc_stop(link->ndisc);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Discovery: %m");
        }

        if (link->radv) {
                k = sd_radv_stop(link->radv);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Advertisement: %m");
        }

        link_lldp_emit_stop(link);
        return r;
}

void link_enter_failed(Link *link) {
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        log_link_warning(link, "Failed");

        link_set_state(link, LINK_STATE_FAILED);

        link_stop_clients(link, false);

        link_dirty(link);
}

static int link_join_netdevs_after_configured(Link *link) {
        NetDev *netdev;
        Iterator i;
        int r;

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs, i) {
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

        log_link_info(link, "Configured");

        link_set_state(link, LINK_STATE_CONFIGURED);

        (void) link_join_netdevs_after_configured(link);

        link_dirty(link);
}

static int link_request_set_routing_policy_rule(Link *link) {
        RoutingPolicyRule *rule, *rrule = NULL;
        int r;

        assert(link);
        assert(link->network);

        link->routing_policy_rules_configured = false;

        LIST_FOREACH(rules, rule, link->network->rules) {
                r = routing_policy_rule_get(link->manager, rule, &rrule);
                if (r >= 0) {
                        if (r == 0)
                                (void) routing_policy_rule_make_local(link->manager, rrule);
                        continue;
                }

                r = routing_policy_rule_configure(rule, link, NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set routing policy rules: %m");
                if (r > 0)
                        link->routing_policy_rule_messages++;
        }

        routing_policy_rule_purge(link->manager, link);
        if (link->routing_policy_rule_messages == 0) {
                link->routing_policy_rules_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting routing policy rules");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->route_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_CONFIGURING,
                      LINK_STATE_FAILED, LINK_STATE_LINGER));

        link->route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_warning_errno(link, r, "Could not set route: %m");
                link_enter_failed(link);
                return 1;
        }

        if (link->route_messages == 0) {
                log_link_debug(link, "Routes set");
                link->static_routes_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int link_request_set_routes(Link *link) {
        enum {
                PHASE_NON_GATEWAY, /* First phase: Routes without a gateway */
                PHASE_GATEWAY,     /* Second phase: Routes with a gateway */
                _PHASE_MAX
        } phase;
        Route *rt;
        int r;

        assert(link);
        assert(link->network);
        assert(link->addresses_configured);
        assert(link->address_messages == 0);
        assert(link->state != _LINK_STATE_INVALID);

        link->static_routes_configured = false;

        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                /* During configuring addresses, the link lost its carrier. As networkd is dropping
                 * the addresses now, let's not configure the routes either. */
                return 0;

        r = link_request_set_routing_policy_rule(link);
        if (r < 0)
                return r;

        /* First add the routes that enable us to talk to gateways, then add in the others that need a gateway. */
        for (phase = 0; phase < _PHASE_MAX; phase++)
                LIST_FOREACH(routes, rt, link->network->static_routes) {

                        if (in_addr_is_null(rt->family, &rt->gw) != (phase == PHASE_NON_GATEWAY))
                                continue;

                        r = route_configure(rt, link, route_handler);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not set routes: %m");
                        if (r > 0)
                                link->route_messages++;
                }

        if (link->route_messages == 0) {
                link->static_routes_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting routes");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

void link_check_ready(Link *link) {
        Address *a;
        Iterator i;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        if (!link->network)
                return;

        if (!link->addresses_configured)
                return;

        if (!link->neighbors_configured)
                return;

        SET_FOREACH(a, link->addresses, i)
                if (!address_is_ready(a))
                        return;

        if (!link->addresses_ready) {
                link->addresses_ready = true;
                r = link_request_set_routes(link);
                if (r < 0)
                        link_enter_failed(link);
                return;
        }

        if (!link->static_routes_configured)
                return;

        if (!link->routing_policy_rules_configured)
                return;

        if (link_has_carrier(link) || !link->network->configure_without_carrier) {

                if (link_ipv4ll_enabled(link, ADDRESS_FAMILY_IPV4) && !link->ipv4ll_address)
                        return;

                if (link_ipv6ll_enabled(link) &&
                    in_addr_is_null(AF_INET6, (const union in_addr_union*) &link->ipv6ll_address))
                        return;

                if ((link_dhcp4_enabled(link) || link_dhcp6_enabled(link)) &&
                    !link->dhcp4_configured &&
                    !link->dhcp6_configured &&
                    !(link_ipv4ll_enabled(link, ADDRESS_FAMILY_FALLBACK_IPV4) && link->ipv4ll_address))
                        /* When DHCP is enabled, at least one protocol must provide an address, or
                         * an IPv4ll fallback address must be configured. */
                        return;

                if (link_ipv6_accept_ra_enabled(link) && !link->ndisc_configured)
                        return;
        }

        if (link->state != LINK_STATE_CONFIGURED)
                link_enter_configured(link);

        return;
}

static int link_request_set_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->neighbors_configured = false;

        LIST_FOREACH(neighbors, neighbor, link->network->neighbors) {
                r = neighbor_configure(neighbor, link, NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set neighbor: %m");
        }

        if (link->neighbor_messages == 0) {
                link->neighbors_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting neighbors");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->address_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_CONFIGURING,
               LINK_STATE_FAILED, LINK_STATE_LINGER));

        link->address_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_warning_errno(link, r, "could not set address: %m");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->address_messages == 0) {
                log_link_debug(link, "Addresses set");
                link->addresses_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_set_bridge_fdb(Link *link) {
        FdbEntry *fdb_entry;
        int r;

        LIST_FOREACH(static_fdb_entries, fdb_entry, link->network->static_fdb_entries) {
                r = fdb_entry_configure(link, fdb_entry);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to add MAC entry to static MAC table: %m");
        }

        return 0;
}

static int link_request_set_addresses(Link *link) {
        AddressLabel *label;
        Address *ad;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        /* Reset all *_configured flags we are configuring. */
        link->addresses_configured = false;
        link->addresses_ready = false;
        link->neighbors_configured = false;
        link->static_routes_configured = false;
        link->routing_policy_rules_configured = false;

        r = link_set_bridge_fdb(link);
        if (r < 0)
                return r;

        r = link_request_set_neighbors(link);
        if (r < 0)
                return r;

        LIST_FOREACH(addresses, ad, link->network->static_addresses) {
                bool update;

                update = address_get(link, ad->family, &ad->in_addr, ad->prefixlen, NULL) > 0;

                r = address_configure(ad, link, address_handler, update);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set addresses: %m");
                if (r > 0)
                        link->address_messages++;
        }

        LIST_FOREACH(labels, label, link->network->address_labels) {
                r = address_label_configure(label, link, NULL, false);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set address label: %m");

                link->address_label_messages++;
        }

        /* now that we can figure out a default address for the dhcp server,
           start it */
        if (link_dhcp4_server_enabled(link) && (link->flags & IFF_UP)) {
                r = dhcp4_server_configure(link);
                if (r < 0)
                        return r;
                log_link_debug(link, "Offering DHCPv4 leases");
        }

        if (link->address_messages == 0) {
                link->addresses_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting addresses");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int link_set_bridge_vlan(Link *link) {
        int r;

        r = br_vlan_configure(link, link->network->pvid, link->network->br_vid_bitmap, link->network->br_untagged_bitmap);
        if (r < 0)
                log_link_error_errno(link, r, "Failed to assign VLANs to bridge port: %m");

        return r;
}

static int link_set_proxy_arp(Link *link) {
        int r;

        if (!link_proxy_arp_enabled(link))
                return 0;

        r = sysctl_write_ip_property_boolean(AF_INET, link->ifname, "proxy_arp", link->network->proxy_arp > 0);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure proxy ARP for interface: %m");

        return 0;
}

static int link_configure_after_setting_mtu(Link *link);

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
                log_link_warning_errno(link, r, "Could not set MTU, ignoring: %m");
        else
                log_link_debug(link, "Setting MTU done.");

        if (link->state == LINK_STATE_INITIALIZED) {
                r = link_configure_after_setting_mtu(link);
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
                                 "IPv6 is requested and requires a minimum MTU of " STRINGIFY(IPV6_MIN_MTU) " bytes: %m");

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
        Iterator i;

        HASHMAP_FOREACH(dev, link->network->stacked_netdevs, i)
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
                log_link_warning_errno(link, r, "Could not set link flags, ignoring: %m");

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

        if (link_ipv6_accept_ra_enabled(link)) {
                assert(link->ndisc);

                log_link_debug(link, "Discovering IPv6 routers");

                r = sd_ndisc_start(link->ndisc);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not start IPv6 Router Discovery: %m");
        }

        if (link_radv_enabled(link)) {
                assert(link->radv);
                assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

                log_link_debug(link, "Starting IPv6 Router Advertisements");

                r = sd_radv_start(link->radv);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not start IPv6 Router Advertisement: %m");
        }

        (void) dhcp6_request_prefix_delegation(link);

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

        if (link_dhcp4_enabled(link)) {
                assert(link->dhcp_client);

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

        if (link_lldp_emit_enabled(link)) {
                r = link_lldp_emit_start(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start LLDP transmission: %m");
        }

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

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set address genmode for interface, ignoring: %m");

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

        if (!socket_ipv6_is_supported())
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
        else if (sysctl_read_ip_property(AF_INET6, link->ifname, "stable_secret", NULL) < 0)
                /* The file may not exist. And event if it exists, when stable_secret is unset,
                 * reading the file fails with EIO. */
                ipv6ll_mode = IN6_ADDR_GEN_MODE_EUI64;
        else
                ipv6ll_mode = IN6_ADDR_GEN_MODE_STABLE_PRIVACY;

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
                log_link_warning_errno(link, r, "Could not bring up interface: %m");

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

        /* set it free if not enslaved with networkd */
        if (!link->network->bridge && !link->network->bond && !link->network->vrf) {
                r = sd_netlink_message_append_u32(req, IFLA_MASTER, 0);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_MASTER attribute: %m");
        }

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link flags: %m");

        if (link->network->mac) {
                r = sd_netlink_message_append_ether_addr(req, IFLA_ADDRESS, link->network->mac);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set MAC address: %m");
        }

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
                log_link_warning_errno(link, r, "Could not bring down interface: %m");

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

static int link_handle_bound_to_list(Link *link) {
        Link *l;
        Iterator i;
        int r;
        bool required_up = false;
        bool link_is_up = false;

        assert(link);

        if (hashmap_isempty(link->bound_to_links))
                return 0;

        if (link->flags & IFF_UP)
                link_is_up = true;

        HASHMAP_FOREACH (l, link->bound_to_links, i)
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
        Iterator i;
        Link *l;
        int r;

        assert(link);

        if (hashmap_isempty(link->bound_by_links))
                return 0;

        HASHMAP_FOREACH (l, link->bound_by_links, i) {
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
        Iterator i;
        int r;
        bool list_updated = false;

        assert(link);
        assert(link->manager);

        m = link->manager;

        HASHMAP_FOREACH(carrier, m->links, i) {
                if (!carrier->network)
                        continue;

                if (strv_isempty(carrier->network->bind_carrier))
                        continue;

                if (strv_fnmatch(carrier->network->bind_carrier, link->ifname, 0)) {
                        r = link_put_carrier(link, carrier, &link->bound_by_links);
                        if (r < 0)
                                return r;

                        list_updated = true;
                }
        }

        if (list_updated)
                link_dirty(link);

        HASHMAP_FOREACH(carrier, link->bound_by_links, i) {
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
        Iterator i;
        int r;
        bool list_updated = false;

        assert(link);
        assert(link->manager);

        if (!link->network)
                return 0;

        if (strv_isempty(link->network->bind_carrier))
                return 0;

        m = link->manager;

        HASHMAP_FOREACH (carrier, m->links, i) {
                if (strv_fnmatch(link->network->bind_carrier, carrier->ifname, 0)) {
                        r = link_put_carrier(link, carrier, &link->bound_to_links);
                        if (r < 0)
                                return r;

                        list_updated = true;
                }
        }

        if (list_updated)
                link_dirty(link);

        HASHMAP_FOREACH (carrier, link->bound_to_links, i) {
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
        Iterator i;

        HASHMAP_FOREACH (bound_to, link->bound_to_links, i) {
                hashmap_remove(link->bound_to_links, INT_TO_PTR(bound_to->ifindex));

                if (hashmap_remove(bound_to->bound_by_links, INT_TO_PTR(link->ifindex)))
                        link_dirty(bound_to);
        }

        return;
}

static void link_free_bound_by_list(Link *link) {
        Link *bound_by;
        Iterator i;

        HASHMAP_FOREACH (bound_by, link->bound_by_links, i) {
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

        r = set_ensure_allocated(&master->slaves, NULL);
        if (r < 0)
                return r;

        r = set_put(master->slaves, link);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

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

        if (link->network->use_br_vlan &&
            (link->network->bridge || streq_ptr("bridge", link->kind))) {
                r = link_set_bridge_vlan(link);
                if (r < 0)
                        log_link_error_errno(link, r, "Could not set bridge vlan: %m");
        }

        /* Skip setting up addresses until it gets carrier,
           or it would try to set addresses twice,
           which is bad for non-idempotent steps. */
        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                return 0;

        link_set_state(link, LINK_STATE_CONFIGURING);
        return link_request_set_addresses(link);
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
                log_link_error_errno(link, r, "Could not join netdev: %m");
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
        Iterator i;
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

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs, i) {

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

static int link_set_ipv4_forward(Link *link) {
        int r;

        if (!link_ipv4_forward_enabled(link))
                return 0;

        /* We propagate the forwarding flag from one interface to the
         * global setting one way. This means: as long as at least one
         * interface was configured at any time that had IP forwarding
         * enabled the setting will stay on for good. We do this
         * primarily to keep IPv4 and IPv6 packet forwarding behaviour
         * somewhat in sync (see below). */

        r = sysctl_write_ip_property(AF_INET, NULL, "ip_forward", "1");
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot turn on IPv4 packet forwarding, ignoring: %m");

        return 0;
}

static int link_set_ipv6_forward(Link *link) {
        int r;

        if (!link_ipv6_forward_enabled(link))
                return 0;

        /* On Linux, the IPv6 stack does not know a per-interface
         * packet forwarding setting: either packet forwarding is on
         * for all, or off for all. We hence don't bother with a
         * per-interface setting, but simply propagate the interface
         * flag, if it is set, to the global flag, one-way. Note that
         * while IPv4 would allow a per-interface flag, we expose the
         * same behaviour there and also propagate the setting from
         * one to all, to keep things simple (see above). */

        r = sysctl_write_ip_property(AF_INET6, "all", "forwarding", "1");
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 packet forwarding, ignoring: %m");

        return 0;
}

static int link_set_ipv6_privacy_extensions(Link *link) {
        IPv6PrivacyExtensions s;
        int r;

        s = link_ipv6_privacy_extensions(link);
        if (s < 0)
                return 0;

        r = sysctl_write_ip_property_int(AF_INET6, link->ifname, "use_tempaddr", (int) link->network->ipv6_privacy_extensions);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 privacy extension for interface: %m");

        return 0;
}

static int link_set_ipv6_accept_ra(Link *link) {
        int r;

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        r = sysctl_write_ip_property(AF_INET6, link->ifname, "accept_ra", "0");
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot disable kernel IPv6 accept_ra for interface: %m");

        return 0;
}

static int link_set_ipv6_dad_transmits(Link *link) {
        int r;

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_dad_transmits < 0)
                return 0;

        r = sysctl_write_ip_property_int(AF_INET6, link->ifname, "dad_transmits", link->network->ipv6_dad_transmits);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 dad transmits for interface: %m");

        return 0;
}

static int link_set_ipv6_hop_limit(Link *link) {
        int r;

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_hop_limit < 0)
                return 0;

        r = sysctl_write_ip_property_int(AF_INET6, link->ifname, "hop_limit", link->network->ipv6_hop_limit);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 hop limit for interface: %m");

        return 0;
}

static int link_set_ipv6_mtu(Link *link) {
        int r;

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (link->network->ipv6_mtu == 0)
                return 0;

        r = sysctl_write_ip_property_uint32(AF_INET6, link->ifname, "mtu", link->network->ipv6_mtu);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 MTU for interface: %m");

        return 0;
}

static bool link_is_static_address_configured(Link *link, Address *address) {
        Address *net_address;

        assert(link);
        assert(address);

        if (!link->network)
                return false;

        LIST_FOREACH(addresses, net_address, link->network->static_addresses)
                if (address_equal(net_address, address))
                        return true;

        return false;
}

static bool link_is_neighbor_configured(Link *link, Neighbor *neighbor) {
        Neighbor *net_neighbor;

        assert(link);
        assert(neighbor);

        if (!link->network)
                return false;

        LIST_FOREACH(neighbors, net_neighbor, link->network->neighbors)
                if (neighbor_equal(net_neighbor, neighbor))
                        return true;

        return false;
}

static bool link_is_static_route_configured(Link *link, Route *route) {
        Route *net_route;

        assert(link);
        assert(route);

        if (!link->network)
                return false;

        LIST_FOREACH(routes, net_route, link->network->static_routes)
                if (route_equal(net_route, route))
                        return true;

        return false;
}

static bool link_address_is_dynamic(Link *link, Address *address) {
        Route *route;
        Iterator i;

        assert(link);
        assert(address);

        if (address->cinfo.ifa_prefered != CACHE_INFO_INFINITY_LIFE_TIME)
                return true;

        /* Even when the address is leased from a DHCP server, networkd assign the address
         * without lifetime when KeepConfiguration=dhcp. So, let's check that we have
         * corresponding routes with RTPROT_DHCP. */
        SET_FOREACH(route, link->routes_foreign, i) {
                if (route->protocol != RTPROT_DHCP)
                        continue;

                if (address->family != route->family)
                        continue;

                if (in_addr_equal(address->family, &address->in_addr, &route->prefsrc))
                        return true;
        }

        return false;
}

static int link_drop_foreign_config(Link *link) {
        Address *address;
        Neighbor *neighbor;
        Route *route;
        Iterator i;
        int r;

        SET_FOREACH(address, link->addresses_foreign, i) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in_addr_is_link_local(AF_INET6, &address->in_addr) == 1 && link_ipv6ll_enabled(link))
                        continue;

                if (link_address_is_dynamic(link, address)) {
                        if (link->network && FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                                continue;
                } else if (link->network && FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                        continue;

                if (link_is_static_address_configured(link, address)) {
                        r = address_add(link, address->family, &address->in_addr, address->prefixlen, NULL);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to add address: %m");
                } else {
                        r = address_remove(address, link, NULL);
                        if (r < 0)
                                return r;
                }
        }

        SET_FOREACH(neighbor, link->neighbors_foreign, i) {
                if (link_is_neighbor_configured(link, neighbor)) {
                        r = neighbor_add(link, neighbor->family, &neighbor->in_addr, &neighbor->lladdr, neighbor->lladdr_size, NULL);
                        if (r < 0)
                                return r;
                } else {
                        r = neighbor_remove(neighbor, link, NULL);
                        if (r < 0)
                                return r;
                }
        }

        SET_FOREACH(route, link->routes_foreign, i) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                /* do not touch multicast route added by kernel */
                /* FIXME: Why the kernel adds this route with protocol RTPROT_BOOT??? We need to investigate that.
                 * https://tools.ietf.org/html/rfc4862#section-5.4 may explain why. */
                if (route->protocol == RTPROT_BOOT &&
                    route->family == AF_INET6 &&
                    route->dst_prefixlen == 8 &&
                    in_addr_equal(AF_INET6, &route->dst, &(union in_addr_union) { .in6 = {{{ 0xff,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 }}} }))
                        continue;

                if (route->protocol == RTPROT_STATIC && link->network &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                        continue;

                if (route->protocol == RTPROT_DHCP && link->network &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                        continue;

                if (link_is_static_route_configured(link, route)) {
                        r = route_add(link, route, NULL);
                        if (r < 0)
                                return r;
                } else {
                        r = route_remove(route, link, NULL);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int link_drop_config(Link *link) {
        Address *address, *pool_address;
        Neighbor *neighbor;
        Route *route;
        Iterator i;
        int r;

        SET_FOREACH(address, link->addresses, i) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in_addr_is_link_local(AF_INET6, &address->in_addr) == 1 && link_ipv6ll_enabled(link))
                        continue;

                r = address_remove(address, link, NULL);
                if (r < 0)
                        return r;

                /* If this address came from an address pool, clean up the pool */
                LIST_FOREACH(addresses, pool_address, link->pool_addresses) {
                        if (address_equal(address, pool_address)) {
                                LIST_REMOVE(addresses, link->pool_addresses, pool_address);
                                address_free(pool_address);
                                break;
                        }
                }
        }

        SET_FOREACH(neighbor, link->neighbors, i) {
                r = neighbor_remove(neighbor, link, NULL);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(route, link->routes, i) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                r = route_remove(route, link, NULL);
                if (r < 0)
                        return r;
        }

        ndisc_flush(link);

        return 0;
}

static int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        if (link->iftype == ARPHRD_CAN)
                return link_configure_can(link);

        /* Drop foreign config, but ignore loopback or critical devices.
         * We do not want to remove loopback address or addresses used for root NFS. */
        if (!(link->flags & IFF_LOOPBACK) &&
            link->network->keep_configuration != KEEP_CONFIGURATION_YES) {
                r = link_drop_foreign_config(link);
                if (r < 0)
                        return r;
        }

        /* If IPv6 configured that is static IPv6 address and IPv6LL autoconfiguration is enabled
         * for this interface, then enable IPv6 */
        (void) link_update_ipv6_sysctl(link);

        r = link_set_proxy_arp(link);
        if (r < 0)
               return r;

        r = ipv6_proxy_ndp_addresses_configure(link);
        if (r < 0)
                return r;

        r = link_set_ipv4_forward(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_forward(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_privacy_extensions(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_accept_ra(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_dad_transmits(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_hop_limit(link);
        if (r < 0)
                return r;

        r = link_set_flags(link);
        if (r < 0)
                return r;

        r = link_set_ipv6_mtu(link);
        if (r < 0)
                return r;

        if (link_ipv4ll_enabled(link, ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_FALLBACK_IPV4)) {
                r = ipv4ll_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_dhcp4_enabled(link)) {
                r = dhcp4_set_promote_secondaries(link);
                if (r < 0)
                        return r;

                r = dhcp4_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_dhcp4_server_enabled(link)) {
                r = sd_dhcp_server_new(&link->dhcp_server, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_dhcp_server_attach_event(link->dhcp_server, NULL, 0);
                if (r < 0)
                        return r;
        }

        if (link_dhcp6_enabled(link) ||
            link_ipv6_accept_ra_enabled(link)) {
                r = dhcp6_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_ipv6_accept_ra_enabled(link)) {
                r = ndisc_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_radv_enabled(link)) {
                r = radv_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_lldp_rx_enabled(link)) {
                r = link_lldp_rx_configure(link);
                if (r < 0)
                        return r;
        }

        r = link_configure_mtu(link);
        if (r < 0)
                return r;

        r = link_configure_addrgen_mode(link);
        if (r < 0)
                return r;

        return link_configure_after_setting_mtu(link);
}

static int link_configure_after_setting_mtu(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        if (link->setting_mtu)
                return 0;

        if (link_has_carrier(link) || link->network->configure_without_carrier) {
                r = link_acquire_conf(link);
                if (r < 0)
                        return r;
        }

        return link_enter_join_netdev(link);
}

static int duid_set_uuid(DUID *duid, sd_id128_t uuid) {
        assert(duid);

        if (duid->raw_data_len > 0)
                return 0;

        if (duid->type != DUID_TYPE_UUID)
                return -EINVAL;

        memcpy(&duid->raw_data, &uuid, sizeof(sd_id128_t));
        duid->raw_data_len = sizeof(sd_id128_t);

        return 1;
}

int get_product_uuid_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = userdata;
        const sd_bus_error *e;
        const void *a;
        size_t sz;
        DUID *duid;
        Link *link;
        int r;

        assert(m);
        assert(manager);

        e = sd_bus_message_get_error(m);
        if (e) {
                log_error_errno(sd_bus_error_get_errno(e),
                                "Could not get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %s",
                                e->message);
                goto configure;
        }

        r = sd_bus_message_read_array(m, 'y', &a, &sz);
        if (r < 0)
                goto configure;

        if (sz != sizeof(sd_id128_t)) {
                log_error("Invalid product UUID. Falling back to use machine-app-specific ID as DUID-UUID.");
                goto configure;
        }

        memcpy(&manager->product_uuid, a, sz);
        while ((duid = set_steal_first(manager->duids_requesting_uuid)))
                (void) duid_set_uuid(duid, manager->product_uuid);

        manager->duids_requesting_uuid = set_free(manager->duids_requesting_uuid);

configure:
        while ((link = set_steal_first(manager->links_requesting_uuid))) {
                link_unref(link);

                r = link_configure(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        manager->links_requesting_uuid = set_free(manager->links_requesting_uuid);

        /* To avoid calling GetProductUUID() bus method so frequently, set the flag below
         * even if the method fails. */
        manager->has_product_uuid = true;

        return 1;
}

static bool link_requires_uuid(Link *link) {
        const DUID *duid;

        assert(link);
        assert(link->manager);
        assert(link->network);

        duid = link_get_duid(link);
        if (duid->type != DUID_TYPE_UUID || duid->raw_data_len != 0)
                return false;

        if (link_dhcp4_enabled(link) && IN_SET(link->network->dhcp_client_identifier, DHCP_CLIENT_ID_DUID, DHCP_CLIENT_ID_DUID_ONLY))
                return true;

        if (link_dhcp6_enabled(link) || link_ipv6_accept_ra_enabled(link))
                return true;

        return false;
}

static int link_configure_duid(Link *link) {
        Manager *m;
        DUID *duid;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);

        m = link->manager;
        duid = link_get_duid(link);

        if (!link_requires_uuid(link))
                return 1;

        if (m->has_product_uuid) {
                (void) duid_set_uuid(duid, m->product_uuid);
                return 1;
        }

        if (!m->links_requesting_uuid) {
                r = manager_request_product_uuid(m, link);
                if (r < 0) {
                        if (r == -ENOMEM)
                                return r;

                        log_link_warning_errno(link, r,
                                               "Failed to get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %m");
                        return 1;
                }
        } else {
                r = set_put(m->links_requesting_uuid, link);
                if (r < 0)
                        return log_oom();

                r = set_put(m->duids_requesting_uuid, duid);
                if (r < 0)
                        return log_oom();

                link_ref(link);
        }

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
                r = network_get(link->manager, link->sd_device, link->ifname,
                                &link->mac, &network);
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
        int r;

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
        union in_addr_union address;
        const char *p;
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

        if (addresses) {
                p = addresses;

                for (;;) {
                        _cleanup_free_ char *address_str = NULL;
                        char *prefixlen_str;
                        int family;
                        unsigned char prefixlen;

                        r = extract_first_word(&p, &address_str, NULL, 0);
                        if (r < 0) {
                                log_link_debug_errno(link, r, "Failed to extract next address string: %m");
                                continue;
                        }
                        if (r == 0)
                                break;

                        prefixlen_str = strchr(address_str, '/');
                        if (!prefixlen_str) {
                                log_link_debug(link, "Failed to parse address and prefix length %s", address_str);
                                continue;
                        }

                        *prefixlen_str++ = '\0';

                        r = sscanf(prefixlen_str, "%hhu", &prefixlen);
                        if (r != 1) {
                                log_link_error(link, "Failed to parse prefixlen %s", prefixlen_str);
                                continue;
                        }

                        r = in_addr_from_string_auto(address_str, &family, &address);
                        if (r < 0) {
                                log_link_debug_errno(link, r, "Failed to parse address %s: %m", address_str);
                                continue;
                        }

                        r = address_add(link, family, &address, prefixlen, NULL);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to add address: %m");
                }
        }

        if (routes) {
                p = routes;

                for (;;) {
                        _cleanup_(sd_event_source_unrefp) sd_event_source *expire = NULL;
                        _cleanup_(route_freep) Route *tmp = NULL;
                        _cleanup_free_ char *route_str = NULL;
                        char *prefixlen_str;
                        Route *route;

                        r = extract_first_word(&p, &route_str, NULL, 0);
                        if (r < 0) {
                                log_link_debug_errno(link, r, "Failed to extract next route string: %m");
                                continue;
                        }
                        if (r == 0)
                                break;

                        prefixlen_str = strchr(route_str, '/');
                        if (!prefixlen_str) {
                                log_link_debug(link, "Failed to parse route %s", route_str);
                                continue;
                        }

                        *prefixlen_str++ = '\0';

                        r = route_new(&tmp);
                        if (r < 0)
                                return log_oom();

                        r = sscanf(prefixlen_str, "%hhu/%hhu/%"SCNu32"/%"PRIu32"/"USEC_FMT, &tmp->dst_prefixlen, &tmp->tos, &tmp->priority, &tmp->table, &tmp->lifetime);
                        if (r != 5) {
                                log_link_debug(link,
                                               "Failed to parse destination prefix length, tos, priority, table or expiration %s",
                                               prefixlen_str);
                                continue;
                        }

                        r = in_addr_from_string_auto(route_str, &tmp->family, &tmp->dst);
                        if (r < 0) {
                                log_link_debug_errno(link, r, "Failed to parse route destination %s: %m", route_str);
                                continue;
                        }

                        r = route_add(link, tmp, &route);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to add route: %m");

                        if (route->lifetime != USEC_INFINITY && !kernel_route_expiration_supported()) {
                                r = sd_event_add_time(link->manager->event, &expire, clock_boottime_or_monotonic(), route->lifetime,
                                                      0, route_expire_handler, route);
                                if (r < 0)
                                        log_link_warning_errno(link, r, "Could not arm route expiration handler: %m");
                        }

                        sd_event_source_unref(route->expire);
                        route->expire = TAKE_PTR(expire);
                }
        }

        if (dhcp4_address) {
                r = in_addr_from_string(AF_INET, dhcp4_address, &address);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Failed to parse DHCPv4 address %s: %m", dhcp4_address);
                        goto dhcp4_address_fail;
                }

                r = sd_dhcp_client_new(&link->dhcp_client, link->network ? link->network->dhcp_anonymize : 0);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to create DHCPv4 client: %m");

                r = sd_dhcp_client_set_request_address(link->dhcp_client, &address.in);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set initial DHCPv4 address %s: %m", dhcp4_address);
        }

dhcp4_address_fail:

        if (ipv4ll_address) {
                r = in_addr_from_string(AF_INET, ipv4ll_address, &address);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Failed to parse IPv4LL address %s: %m", ipv4ll_address);
                        goto ipv4ll_address_fail;
                }

                r = sd_ipv4ll_new(&link->ipv4ll);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to create IPv4LL client: %m");

                r = sd_ipv4ll_set_address(link->ipv4ll, &address.in);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set initial IPv4LL address %s: %m", ipv4ll_address);
        }

ipv4ll_address_fail:

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

        if (detect_container() <= 0) {
                /* not in a container, udev will be around */
                sprintf(ifindex_str, "n%d", link->ifindex);
                r = sd_device_new_from_device_id(&device, ifindex_str);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not find device, waiting for device initialization: %m");
                        return 0;
                }

                r = sd_device_get_is_initialized(device);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not determine whether the device is initialized or not: %m");
                        goto failed;
                }
                if (r == 0) {
                        /* not yet ready */
                        log_link_debug(link, "link pending udev initialization...");
                        return 0;
                }

                r = device_is_renaming(device);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to determine the device is renamed or not: %m");
                        goto failed;
                }
                if (r > 0) {
                        log_link_debug(link, "Interface is under renaming, pending initialization.");
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

        if (IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED)) {
                r = link_acquire_conf(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }

                link_set_state(link, LINK_STATE_CONFIGURING);
                r = link_request_set_addresses(link);
                if (r < 0)
                        return r;
        }

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

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

        r = link_stop_clients(link, false);
        if (r < 0) {
                link_enter_failed(link);
                return r;
        }

        if (link_dhcp4_server_enabled(link))
                (void) sd_dhcp_server_stop(link->dhcp_server);

        r = link_drop_config(link);
        if (r < 0)
                return r;

        if (!IN_SET(link->state, LINK_STATE_UNMANAGED, LINK_STATE_PENDING)) {
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

int link_update(Link *link, sd_netlink_message *m) {
        struct ether_addr mac;
        const char *ifname;
        uint32_t mtu;
        bool had_carrier, carrier_gained, carrier_lost;
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
        r = sd_netlink_message_read_ether_addr(m, IFLA_ADDRESS, &mac);
        if (r >= 0) {
                if (memcmp(link->mac.ether_addr_octet, mac.ether_addr_octet,
                           ETH_ALEN)) {

                        memcpy(link->mac.ether_addr_octet, mac.ether_addr_octet,
                               ETH_ALEN);

                        log_link_debug(link, "MAC address: "
                                       "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                       mac.ether_addr_octet[0],
                                       mac.ether_addr_octet[1],
                                       mac.ether_addr_octet[2],
                                       mac.ether_addr_octet[3],
                                       mac.ether_addr_octet[4],
                                       mac.ether_addr_octet[5]);

                        if (link->ipv4ll) {
                                r = sd_ipv4ll_set_mac(link->ipv4ll, &link->mac);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC address in IPv4LL client: %m");
                        }

                        if (link->dhcp_client) {
                                r = sd_dhcp_client_set_mac(link->dhcp_client,
                                                           (const uint8_t *) &link->mac,
                                                           sizeof (link->mac),
                                                           ARPHRD_ETHER);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCP client: %m");

                                r = dhcp4_set_client_identifier(link);
                                if (r < 0)
                                        return r;
                        }

                        if (link->dhcp6_client) {
                                const DUID* duid = link_get_duid(link);

                                r = sd_dhcp6_client_set_mac(link->dhcp6_client,
                                                            (const uint8_t *) &link->mac,
                                                            sizeof (link->mac),
                                                            ARPHRD_ETHER);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCPv6 client: %m");

                                if (link->network->iaid_set) {
                                        r = sd_dhcp6_client_set_iaid(link->dhcp6_client,
                                                                     link->network->iaid);
                                        if (r < 0)
                                                return log_link_warning_errno(link, r, "Could not update DHCPv6 IAID: %m");
                                }

                                r = sd_dhcp6_client_set_duid(link->dhcp6_client,
                                                             duid->type,
                                                             duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                             duid->raw_data_len);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update DHCPv6 DUID: %m");
                        }

                        if (link->radv) {
                                r = sd_radv_set_mac(link->radv, &link->mac);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC for Router Advertisement: %m");
                        }

                        if (link->ndisc) {
                                r = sd_ndisc_set_mac(link->ndisc, &link->mac);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC for ndisc: %m");
                        }
                }
        }

        old_master = link->master_ifindex;
        (void) sd_netlink_message_read_u32(m, IFLA_MASTER, (uint32_t *) &link->master_ifindex);

        had_carrier = link_has_carrier(link);

        r = link_update_flags(link, m, old_master != link->master_ifindex);
        if (r < 0)
                return r;

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
        Iterator i;
        Link *link;

        assert(f);
        assert(prefix);

        if (hashmap_isempty(h))
                return;

        fputs(prefix, f);
        HASHMAP_FOREACH(link, h, i) {
                if (space)
                        fputc(' ', f);

                fprintf(f, "%i", link->ifindex);
                space = true;
        }

        fputc('\n', f);
}

static void link_save_dns(FILE *f, struct in_addr_data *dns, unsigned n_dns, bool *space) {
        unsigned j;
        int r;

        for (j = 0; j < n_dns; j++) {
                _cleanup_free_ char *b = NULL;

                r = in_addr_to_string(dns[j].family, &dns[j].address, &b);
                if (r < 0) {
                        log_debug_errno(r, "Failed to format address, ignoring: %m");
                        continue;
                }

                if (*space)
                        fputc(' ', f);
                fputs(b, f);
                *space = true;
        }
}

int link_save(Link *link) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *admin_state, *oper_state, *carrier_state, *address_state;
        Address *a;
        Route *route;
        Iterator i;
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
                sd_dhcp6_lease *dhcp6_lease = NULL;
                bool space;

                fprintf(f, "REQUIRED_FOR_ONLINE=%s\n",
                        yes_no(link->network->required_for_online));

                fprintf(f, "REQUIRED_OPER_STATE_FOR_ONLINE=%s\n",
                        strempty(link_operstate_to_string(link->network->required_operstate_for_online)));

                if (link->dhcp6_client) {
                        r = sd_dhcp6_client_get_lease(link->dhcp6_client, &dhcp6_lease);
                        if (r < 0 && r != -ENOMSG)
                                log_link_debug(link, "No DHCPv6 lease");
                }

                fprintf(f, "NETWORK_FILE=%s\n", link->network->filename);

                fputs("DNS=", f);
                space = false;

                if (link->n_dns != (unsigned) -1)
                        link_save_dns(f, link->dns, link->n_dns, &space);
                else
                        link_save_dns(f, link->network->dns, link->network->n_dns, &space);

                if (link->network->dhcp_use_dns &&
                    link->dhcp_lease) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0)
                                if (serialize_in_addrs(f, addresses, r, space, in4_addr_is_non_local) > 0)
                                        space = true;
                }

                if (link->network->dhcp6_use_dns && dhcp6_lease) {
                        struct in6_addr *in6_addrs;

                        r = sd_dhcp6_lease_get_dns(dhcp6_lease, &in6_addrs);
                        if (r > 0) {
                                if (space)
                                        fputc(' ', f);
                                serialize_in6_addrs(f, in6_addrs, r);
                                space = true;
                        }
                }

                /* Make sure to flush out old entries before we use the NDISC data */
                ndisc_vacuum(link);

                if (link->network->ipv6_accept_ra_use_dns && link->ndisc_rdnss) {
                        NDiscRDNSS *dd;

                        SET_FOREACH(dd, link->ndisc_rdnss, i) {
                                if (space)
                                        fputc(' ', f);

                                serialize_in6_addrs(f, &dd->address, 1);
                                space = true;
                        }
                }

                fputc('\n', f);

                fputs("NTP=", f);
                space = false;
                fputstrv(f, link->ntp ?: link->network->ntp, NULL, &space);

                if (link->network->dhcp_use_ntp &&
                    link->dhcp_lease) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0)
                                if (serialize_in_addrs(f, addresses, r, space, in4_addr_is_non_local) > 0)
                                        space = true;
                }

                if (link->network->dhcp6_use_ntp && dhcp6_lease) {
                        struct in6_addr *in6_addrs;
                        char **hosts;

                        r = sd_dhcp6_lease_get_ntp_addrs(dhcp6_lease,
                                                         &in6_addrs);
                        if (r > 0) {
                                if (space)
                                        fputc(' ', f);
                                serialize_in6_addrs(f, in6_addrs, r);
                                space = true;
                        }

                        r = sd_dhcp6_lease_get_ntp_fqdn(dhcp6_lease, &hosts);
                        if (r > 0)
                                fputstrv(f, hosts, NULL, &space);
                }

                fputc('\n', f);

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        if (link->dhcp_lease) {
                                (void) sd_dhcp_lease_get_domainname(link->dhcp_lease, &dhcp_domainname);
                                (void) sd_dhcp_lease_get_search_domains(link->dhcp_lease, &dhcp_domains);
                        }
                        if (dhcp6_lease)
                                (void) sd_dhcp6_lease_get_domains(dhcp6_lease, &dhcp6_domains);
                }

                fputs("DOMAINS=", f);
                space = false;
                ORDERED_SET_FOREACH(p, link->search_domains ?: link->network->search_domains, i)
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

                        SET_FOREACH(dd, link->ndisc_dnssl, i)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                fputs("ROUTE_DOMAINS=", f);
                space = false;
                ORDERED_SET_FOREACH(p, link->route_domains ?: link->network->route_domains, i)
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

                        SET_FOREACH(dd, link->ndisc_dnssl, i)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                fprintf(f, "LLMNR=%s\n",
                        resolve_support_to_string(link->llmnr >= 0 ? link->llmnr : link->network->llmnr));
                fprintf(f, "MDNS=%s\n",
                        resolve_support_to_string(link->mdns >= 0 ? link->mdns : link->network->mdns));
                if (link->dns_default_route >= 0)
                        fprintf(f, "DNS_DEFAULT_ROUTE=%s\n", yes_no(link->dns_default_route));
                else if (link->network->dns_default_route >= 0)
                        fprintf(f, "DNS_DEFAULT_ROUTE=%s\n", yes_no(link->network->dns_default_route));

                if (link->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                        fprintf(f, "DNS_OVER_TLS=%s\n",
                                dns_over_tls_mode_to_string(link->dns_over_tls_mode));
                else if (link->network->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                        fprintf(f, "DNS_OVER_TLS=%s\n",
                                dns_over_tls_mode_to_string(link->network->dns_over_tls_mode));

                if (link->dnssec_mode != _DNSSEC_MODE_INVALID)
                        fprintf(f, "DNSSEC=%s\n",
                                dnssec_mode_to_string(link->dnssec_mode));
                else if (link->network->dnssec_mode != _DNSSEC_MODE_INVALID)
                        fprintf(f, "DNSSEC=%s\n",
                                dnssec_mode_to_string(link->network->dnssec_mode));

                if (!set_isempty(link->dnssec_negative_trust_anchors)) {
                        const char *n;

                        fputs("DNSSEC_NTA=", f);
                        space = false;
                        SET_FOREACH(n, link->dnssec_negative_trust_anchors, i)
                                fputs_with_space(f, n, NULL, &space);
                        fputc('\n', f);
                } else if (!set_isempty(link->network->dnssec_negative_trust_anchors)) {
                        const char *n;

                        fputs("DNSSEC_NTA=", f);
                        space = false;
                        SET_FOREACH(n, link->network->dnssec_negative_trust_anchors, i)
                                fputs_with_space(f, n, NULL, &space);
                        fputc('\n', f);
                }

                fputs("ADDRESSES=", f);
                space = false;
                SET_FOREACH(a, link->addresses, i) {
                        _cleanup_free_ char *address_str = NULL;

                        r = in_addr_to_string(a->family, &a->in_addr, &address_str);
                        if (r < 0)
                                goto fail;

                        fprintf(f, "%s%s/%u", space ? " " : "", address_str, a->prefixlen);
                        space = true;
                }
                fputc('\n', f);

                fputs("ROUTES=", f);
                space = false;
                SET_FOREACH(route, link->routes, i) {
                        _cleanup_free_ char *route_str = NULL;

                        r = in_addr_to_string(route->family, &route->dst, &route_str);
                        if (r < 0)
                                goto fail;

                        fprintf(f, "%s%s/%hhu/%hhu/%"PRIu32"/%"PRIu32"/"USEC_FMT,
                                space ? " " : "", route_str,
                                route->dst_prefixlen, route->tos, route->priority, route->table, route->lifetime);
                        space = true;
                }

                fputc('\n', f);
        }

        print_link_hashmap(f, "CARRIER_BOUND_TO=", link->bound_to_links);
        print_link_hashmap(f, "CARRIER_BOUND_BY=", link->bound_by_links);

        if (link->dhcp_lease) {
                struct in_addr address;
                const char *tz = NULL;

                assert(link->network);

                r = sd_dhcp_lease_get_timezone(link->dhcp_lease, &tz);
                if (r >= 0)
                        fprintf(f, "TIMEZONE=%s\n", tz);

                r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
                if (r >= 0) {
                        fputs("DHCP4_ADDRESS=", f);
                        serialize_in_addrs(f, &address, 1, false, NULL);
                        fputc('\n', f);
                }

                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        goto fail;

                fprintf(f,
                        "DHCP_LEASE=%s\n",
                        link->lease_file);
        } else
                (void) unlink(link->lease_file);

        if (link->ipv4ll) {
                struct in_addr address;

                r = sd_ipv4ll_get_address(link->ipv4ll, &address);
                if (r >= 0) {
                        fputs("IPV4LL_ADDRESS=", f);
                        serialize_in_addrs(f, &address, 1, false, NULL);
                        fputc('\n', f);
                }
        }

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

        r = set_ensure_allocated(&link->manager->dirty_links, NULL);
        if (r < 0)
                /* allocation errors are ignored */
                return;

        r = set_put(link->manager->dirty_links, link);
        if (r <= 0)
                /* don't take another ref if the link was already dirty */
                return;

        link_ref(link);
}

/* The serialized state in /run is up-to-date */
void link_clean(Link *link) {
        assert(link);
        assert(link->manager);

        link_unref(set_remove(link->manager->dirty_links, link));
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

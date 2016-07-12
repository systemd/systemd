/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/ether.h>
#include <linux/if.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "dhcp-lease-internal.h"
#include "fd-util.h"
#include "fileio.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-lldp-tx.h"
#include "networkd-ndisc.h"
#include "networkd.h"
#include "set.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "udev-util.h"
#include "util.h"
#include "virt.h"

static bool link_dhcp6_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->dhcp & ADDRESS_FAMILY_IPV6;
}

static bool link_dhcp4_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->dhcp & ADDRESS_FAMILY_IPV4;
}

static bool link_dhcp4_server_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->dhcp_server;
}

static bool link_ipv4ll_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->link_local & ADDRESS_FAMILY_IPV4;
}

static bool link_ipv6ll_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->link_local & ADDRESS_FAMILY_IPV6;
}

static bool link_ipv6_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->network->bridge)
                return false;

        /* DHCPv6 client will not be started if no IPv6 link-local address is configured. */
        return link_ipv6ll_enabled(link) || network_has_static_ipv6_addresses(link->network);
}

static bool link_lldp_rx_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        if (link->network->bridge)
                return false;

        return link->network->lldp_mode != LLDP_MODE_NO;
}

static bool link_lldp_emit_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        return link->network->lldp_emit != LLDP_EMIT_NO;
}

static bool link_ipv4_forward_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->ip_forward == _ADDRESS_FAMILY_BOOLEAN_INVALID)
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

        if (link->network->ip_forward == _ADDRESS_FAMILY_BOOLEAN_INVALID)
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

static int link_enable_ipv6(Link *link) {
        const char *p = NULL;
        bool disabled;
        int r;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        disabled = !link_ipv6_enabled(link);

        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/disable_ipv6");

        r = write_string_file(p, one_zero(disabled), WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot %s IPv6 for interface %s: %m", disabled ? "disable" : "enable", link->ifname);
        else {
                if (disabled)
                        log_link_info(link, "IPv6 disabled for interface: %m");
                else
                        log_link_info(link, "IPv6 enabled for interface: %m");
        }

        return 0;
}

void link_update_operstate(Link *link) {
        LinkOperationalState operstate;
        assert(link);

        if (link->kernel_operstate == IF_OPER_DORMANT)
                operstate = LINK_OPERSTATE_DORMANT;
        else if (link_has_carrier(link)) {
                Address *address;
                uint8_t scope = RT_SCOPE_NOWHERE;
                Iterator i;

                /* if we have carrier, check what addresses we have */
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
                        operstate = LINK_OPERSTATE_ROUTABLE;
                else if (scope < RT_SCOPE_HOST)
                        /* only link or site local addresses found */
                        operstate = LINK_OPERSTATE_DEGRADED;
                else
                        /* no useful addresses found */
                        operstate = LINK_OPERSTATE_CARRIER;
        } else if (link->flags & IFF_UP)
                operstate = LINK_OPERSTATE_NO_CARRIER;
        else
                operstate = LINK_OPERSTATE_OFF;

        if (link->operstate != operstate) {
                link->operstate = operstate;
                link_send_changed(link, "OperationalState", NULL);
                link_dirty(link);
        }
}

#define FLAG_STRING(string, flag, old, new) \
        (((old ^ new) & flag) \
                ? ((old & flag) ? (" -" string) : (" +" string)) \
                : "")

static int link_update_flags(Link *link, sd_netlink_message *m) {
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

        if ((link->flags == flags) && (link->kernel_operstate == operstate))
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

        link_update_operstate(link);

        return 0;
}

static int link_new(Manager *manager, sd_netlink_message *message, Link **ret) {
        _cleanup_link_unref_ Link *link = NULL;
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
                (void)sd_netlink_message_read_string(message, IFLA_INFO_KIND, &kind);
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

        link = new0(Link, 1);
        if (!link)
                return -ENOMEM;

        link->n_ref = 1;
        link->manager = manager;
        link->state = LINK_STATE_PENDING;
        link->rtnl_extended_attrs = true;
        link->ifindex = ifindex;
        link->iftype = iftype;
        link->ifname = strdup(ifname);
        if (!link->ifname)
                return -ENOMEM;

        if (kind) {
                link->kind = strdup(kind);
                if (!link->kind)
                        return -ENOMEM;
        }

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

        r = link_update_flags(link, message);
        if (r < 0)
                return r;

        *ret = link;
        link = NULL;

        return 0;
}

static void link_free(Link *link) {
        Address *address;
        Iterator i;
        Link *carrier;

        if (!link)
                return;

        while (!set_isempty(link->addresses))
                address_free(set_first(link->addresses));

        while (!set_isempty(link->addresses_foreign))
                address_free(set_first(link->addresses_foreign));

        link->addresses = set_free(link->addresses);

        link->addresses_foreign = set_free(link->addresses_foreign);

        while ((address = link->pool_addresses)) {
                LIST_REMOVE(addresses, link->pool_addresses, address);
                address_free(address);
        }

        sd_dhcp_server_unref(link->dhcp_server);
        sd_dhcp_client_unref(link->dhcp_client);
        sd_dhcp_lease_unref(link->dhcp_lease);

        link_lldp_emit_stop(link);

        free(link->lease_file);

        sd_lldp_unref(link->lldp);
        free(link->lldp_file);

        sd_ipv4ll_unref(link->ipv4ll);
        sd_dhcp6_client_unref(link->dhcp6_client);
        sd_ndisc_unref(link->ndisc);

        set_free_free(link->ndisc_rdnss);
        set_free_free(link->ndisc_dnssl);

        if (link->manager)
                hashmap_remove(link->manager->links, INT_TO_PTR(link->ifindex));

        free(link->ifname);

        free(link->kind);

        (void)unlink(link->state_file);
        free(link->state_file);

        udev_device_unref(link->udev_device);

        HASHMAP_FOREACH (carrier, link->bound_to_links, i)
                hashmap_remove(link->bound_to_links, INT_TO_PTR(carrier->ifindex));
        hashmap_free(link->bound_to_links);

        HASHMAP_FOREACH (carrier, link->bound_by_links, i)
                hashmap_remove(link->bound_by_links, INT_TO_PTR(carrier->ifindex));
        hashmap_free(link->bound_by_links);

        free(link);
}

Link *link_unref(Link *link) {
        if (!link)
                return NULL;

        assert(link->n_ref > 0);

        link->n_ref--;

        if (link->n_ref > 0)
                return NULL;

        link_free(link);

        return NULL;
}

Link *link_ref(Link *link) {
        if (!link)
                return NULL;

        assert(link->n_ref > 0);

        link->n_ref++;

        return link;
}

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

static void link_set_state(Link *link, LinkState state) {
        assert(link);

        if (link->state == state)
                return;

        link->state = state;

        link_send_changed(link, "AdministrativeState", NULL);
}

static void link_enter_unmanaged(Link *link) {
        assert(link);

        log_link_debug(link, "Unmanaged");

        link_set_state(link, LINK_STATE_UNMANAGED);

        link_dirty(link);
}

static int link_stop_clients(Link *link) {
        int r = 0, k;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        if (link->dhcp_client) {
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

        link_lldp_emit_stop(link);
        return r;
}

void link_enter_failed(Link *link) {
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        log_link_warning(link, "Failed");

        link_set_state(link, LINK_STATE_FAILED);

        link_stop_clients(link);

        link_dirty(link);
}

static Address* link_find_dhcp_server_address(Link *link) {
        Address *address;

        assert(link);
        assert(link->network);

        /* The first statically configured address if there is any */
        LIST_FOREACH(addresses, address, link->network->static_addresses) {

                if (address->family != AF_INET)
                        continue;

                if (in_addr_is_null(address->family, &address->in_addr))
                        continue;

                return address;
        }

        /* If that didn't work, find a suitable address we got from the pool */
        LIST_FOREACH(addresses, address, link->pool_addresses) {
                if (address->family != AF_INET)
                        continue;

                return address;
        }

        return NULL;
}

static int link_enter_configured(Link *link) {
        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_SETTING_ROUTES);

        log_link_info(link, "Configured");

        link_set_state(link, LINK_STATE_CONFIGURED);

        link_dirty(link);

        return 0;
}

void link_check_ready(Link *link) {
        Address *a;
        Iterator i;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        if (!link->network)
                return;

        if (!link->static_configured)
                return;

        if (link_ipv4ll_enabled(link))
                if (!link->ipv4ll_address ||
                    !link->ipv4ll_route)
                        return;

        if (link_ipv6ll_enabled(link))
                if (in_addr_is_null(AF_INET6, (const union in_addr_union*) &link->ipv6ll_address) > 0)
                        return;

        if ((link_dhcp4_enabled(link) && !link_dhcp6_enabled(link) &&
             !link->dhcp4_configured) ||
            (link_dhcp6_enabled(link) && !link_dhcp4_enabled(link) &&
             !link->dhcp6_configured) ||
            (link_dhcp4_enabled(link) && link_dhcp6_enabled(link) &&
             !link->dhcp4_configured && !link->dhcp6_configured))
                return;

        if (link_ipv6_accept_ra_enabled(link) && !link->ndisc_configured)
                return;

        SET_FOREACH(a, link->addresses, i)
                if (!address_is_ready(a))
                        return;

        if (link->state != LINK_STATE_CONFIGURED)
                link_enter_configured(link);

        return;
}

static int route_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link->link_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_SETTING_ADDRESSES,
                      LINK_STATE_SETTING_ROUTES, LINK_STATE_FAILED,
                      LINK_STATE_LINGER));

        link->link_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_link_warning_errno(link, r, "Could not set route: %m");

        if (link->link_messages == 0) {
                log_link_debug(link, "Routes set");
                link->static_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_enter_set_routes(Link *link) {
        Route *rt;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_SETTING_ADDRESSES);

        link_set_state(link, LINK_STATE_SETTING_ROUTES);

        LIST_FOREACH(routes, rt, link->network->static_routes) {
                r = route_configure(rt, link, route_handler);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not set routes: %m");
                        link_enter_failed(link);
                        return r;
                }

                link->link_messages++;
        }

        if (link->link_messages == 0) {
                link->static_configured = true;
                link_check_ready(link);
        } else
                log_link_debug(link, "Setting routes");

        return 0;
}

int link_route_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_warning_errno(link, r, "Could not drop route: %m");

        return 1;
}

static int address_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->link_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_SETTING_ADDRESSES,
               LINK_STATE_FAILED, LINK_STATE_LINGER));

        link->link_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_link_warning_errno(link, r, "could not set address: %m");
        else if (r >= 0)
                manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->link_messages == 0) {
                log_link_debug(link, "Addresses set");
                link_enter_set_routes(link);
        }

        return 1;
}

static int link_push_dns_to_dhcp_server(Link *link, sd_dhcp_server *s) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        char **a;

        log_debug("Copying DNS server information from %s", link->ifname);

        if (!link->network)
                return 0;

        STRV_FOREACH(a, link->network->dns) {
                struct in_addr ia;

                /* Only look for IPv4 addresses */
                if (inet_pton(AF_INET, *a, &ia) <= 0)
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return log_oom();

                addresses[n_addresses++] = ia;
        }

        if (link->network->dhcp_use_dns &&
            link->dhcp_lease) {
                const struct in_addr *da = NULL;
                int n;

                n = sd_dhcp_lease_get_dns(link->dhcp_lease, &da);
                if (n > 0) {

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + n))
                                return log_oom();

                        memcpy(addresses + n_addresses, da, n * sizeof(struct in_addr));
                        n_addresses += n;
                }
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_dns(s, addresses, n_addresses);
}

static int link_push_ntp_to_dhcp_server(Link *link, sd_dhcp_server *s) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        char **a;

        if (!link->network)
                return 0;

        log_debug("Copying NTP server information from %s", link->ifname);

        STRV_FOREACH(a, link->network->ntp) {
                struct in_addr ia;

                /* Only look for IPv4 addresses */
                if (inet_pton(AF_INET, *a, &ia) <= 0)
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return log_oom();

                addresses[n_addresses++] = ia;
        }

        if (link->network->dhcp_use_ntp &&
            link->dhcp_lease) {
                const struct in_addr *da = NULL;
                int n;

                n = sd_dhcp_lease_get_ntp(link->dhcp_lease, &da);
                if (n > 0) {

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + n))
                                return log_oom();

                        memcpy(addresses + n_addresses, da, n * sizeof(struct in_addr));
                        n_addresses += n;
                }
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_ntp(s, addresses, n_addresses);
}

static int link_enter_set_addresses(Link *link) {
        Address *ad;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link_set_state(link, LINK_STATE_SETTING_ADDRESSES);

        LIST_FOREACH(addresses, ad, link->network->static_addresses) {
                r = address_configure(ad, link, address_handler, false);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not set addresses: %m");
                        link_enter_failed(link);
                        return r;
                }

                link->link_messages++;
        }

        /* now that we can figure out a default address for the dhcp server,
           start it */
        if (link_dhcp4_server_enabled(link)) {
                Address *address;
                Link *uplink = NULL;
                bool acquired_uplink = false;

                address = link_find_dhcp_server_address(link);
                if (!address) {
                        log_link_warning(link, "Failed to find suitable address for DHCPv4 server instance.");
                        link_enter_failed(link);
                        return 0;
                }

                /* use the server address' subnet as the pool */
                r = sd_dhcp_server_configure_pool(link->dhcp_server, &address->in_addr.in, address->prefixlen,
                                                  link->network->dhcp_server_pool_offset, link->network->dhcp_server_pool_size);
                if (r < 0)
                        return r;

                /* TODO:
                r = sd_dhcp_server_set_router(link->dhcp_server,
                                              &main_address->in_addr.in);
                if (r < 0)
                        return r;
                */

                if (link->network->dhcp_server_max_lease_time_usec > 0) {
                        r = sd_dhcp_server_set_max_lease_time(
                                        link->dhcp_server,
                                        DIV_ROUND_UP(link->network->dhcp_server_max_lease_time_usec, USEC_PER_SEC));
                        if (r < 0)
                                return r;
                }

                if (link->network->dhcp_server_default_lease_time_usec > 0) {
                        r = sd_dhcp_server_set_default_lease_time(
                                        link->dhcp_server,
                                        DIV_ROUND_UP(link->network->dhcp_server_default_lease_time_usec, USEC_PER_SEC));
                        if (r < 0)
                                return r;
                }

                if (link->network->dhcp_server_emit_dns) {

                        if (link->network->n_dhcp_server_dns > 0)
                                r = sd_dhcp_server_set_dns(link->dhcp_server, link->network->dhcp_server_dns, link->network->n_dhcp_server_dns);
                        else {
                                uplink = manager_find_uplink(link->manager, link);
                                acquired_uplink = true;

                                if (!uplink) {
                                        log_link_debug(link, "Not emitting DNS server information on link, couldn't find suitable uplink.");
                                        r = 0;
                                } else
                                        r = link_push_dns_to_dhcp_server(uplink, link->dhcp_server);
                        }
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to set DNS server for DHCP server, ignoring: %m");
                }


                if (link->network->dhcp_server_emit_ntp) {

                        if (link->network->n_dhcp_server_ntp > 0)
                                r = sd_dhcp_server_set_ntp(link->dhcp_server, link->network->dhcp_server_ntp, link->network->n_dhcp_server_ntp);
                        else {
                                if (!acquired_uplink)
                                        uplink = manager_find_uplink(link->manager, link);

                                if (!uplink) {
                                        log_link_debug(link, "Not emitting NTP server information on link, couldn't find suitable uplink.");
                                        r = 0;
                                } else
                                        r = link_push_ntp_to_dhcp_server(uplink, link->dhcp_server);

                        }
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to set NTP server for DHCP server, ignoring: %m");
                }

                r = sd_dhcp_server_set_emit_router(link->dhcp_server, link->network->dhcp_server_emit_router);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to set router emission for DHCP server: %m");
                        return r;
                }

                if (link->network->dhcp_server_emit_timezone) {
                        _cleanup_free_ char *buffer = NULL;
                        const char *tz = NULL;

                        if (link->network->dhcp_server_timezone)
                                tz = link->network->dhcp_server_timezone;
                        else {
                                r = get_timezone(&buffer);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to determine timezone: %m");
                                else
                                        tz = buffer;
                        }

                        if (tz) {
                                r = sd_dhcp_server_set_timezone(link->dhcp_server, tz);
                                if (r < 0)
                                        return r;
                        }
                }

                r = sd_dhcp_server_start(link->dhcp_server);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not start DHCPv4 server instance: %m");

                        link_enter_failed(link);

                        return 0;
                }

                log_link_debug(link, "Offering DHCPv4 leases");
        }

        if (link->link_messages == 0)
                link_enter_set_routes(link);
        else
                log_link_debug(link, "Setting addresses");

        return 0;
}

int link_address_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_link_warning_errno(link, r, "Could not drop address: %m");

        return 1;
}

static int link_set_bridge_vlan(Link *link) {
        int r = 0;

        r = br_vlan_configure(link, link->network->pvid, link->network->br_vid_bitmap, link->network->br_untagged_bitmap);
        if (r < 0)
                log_link_error_errno(link, r, "Failed to assign VLANs to bridge port: %m");

        return r;
}

static int link_set_bridge_fdb(Link *link) {
        FdbEntry *fdb_entry;
        int r = 0;

        LIST_FOREACH(static_fdb_entries, fdb_entry, link->network->static_fdb_entries) {
                r = fdb_entry_configure(link, fdb_entry);
                if (r < 0) {
                        log_link_error_errno(link, r, "Failed to add MAC entry to static MAC table: %m");
                        break;
                }
        }

        return r;
}

static int link_set_proxy_arp(Link *link) {
        const char *p = NULL;
        int r;

        if (!link_proxy_arp_enabled(link))
                return 0;

        p = strjoina("/proc/sys/net/ipv4/conf/", link->ifname, "/proxy_arp");

        r = write_string_file(p, one_zero(link->network->proxy_arp), WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure proxy ARP for interface: %m");

        return 0;
}

static int link_set_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        log_link_debug(link, "Set link");

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not join netdev: %m");
                link_enter_failed(link);
                return 1;
        }

        return 0;
}

static int set_hostname_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        _cleanup_link_unref_ Link *link = userdata;
        const sd_bus_error *e;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        e = sd_bus_message_get_error(m);
        if (e)
                log_link_warning_errno(link, sd_bus_error_get_errno(e), "Could not set hostname: %s", e->message);

        return 1;
}

int link_set_hostname(Link *link, const char *hostname) {
        int r;

        assert(link);
        assert(link->manager);

        log_link_debug(link, "Setting transient hostname: '%s'", strna(hostname));

        if (!link->manager->bus) {
                /* TODO: replace by assert when we can rely on kdbus */
                log_link_info(link, "Not connected to system bus, ignoring transient hostname.");
                return 0;
        }

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        NULL,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "SetHostname",
                        set_hostname_handler,
                        link,
                        "sb",
                        hostname,
                        false);

        if (r < 0)
                return log_link_error_errno(link, r, "Could not set transient hostname: %m");

        link_ref(link);

        return 0;
}

static int set_timezone_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        _cleanup_link_unref_ Link *link = userdata;
        const sd_bus_error *e;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        e = sd_bus_message_get_error(m);
        if (e)
                log_link_warning_errno(link, sd_bus_error_get_errno(e), "Could not set timezone: %s", e->message);

        return 1;
}

int link_set_timezone(Link *link, const char *tz) {
        int r;

        assert(link);
        assert(link->manager);
        assert(tz);

        log_link_debug(link, "Setting system timezone: '%s'", tz);

        if (!link->manager->bus) {
                log_link_info(link, "Not connected to system bus, ignoring timezone.");
                return 0;
        }

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        NULL,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetTimezone",
                        set_timezone_handler,
                        link,
                        "sb",
                        tz,
                        false);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set timezone: %m");

        link_ref(link);

        return 0;
}

static int set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set MTU: %m");

        return 1;
}

int link_set_mtu(Link *link, uint32_t mtu) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Setting MTU: %" PRIu32, mtu);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_append_u32(req, IFLA_MTU, mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append MTU: %m");

        r = sd_netlink_call_async(link->manager->rtnl, req, set_mtu_handler, link, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_set_bridge(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_family(req, PF_BRIDGE);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set message family: %m");

        r = sd_netlink_message_open_container(req, IFLA_PROTINFO);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_PROTINFO attribute: %m");

        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_GUARD, !link->network->use_bpdu);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_GUARD attribute: %m");

        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MODE, link->network->hairpin);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_MODE attribute: %m");

        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_FAST_LEAVE, link->network->fast_leave);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_FAST_LEAVE attribute: %m");

        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROTECT, !link->network->allow_port_to_be_root);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_PROTECT attribute: %m");

        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_UNICAST_FLOOD, link->network->unicast_flood);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_UNICAST_FLOOD attribute: %m");

        if (link->network->cost != 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BRPORT_COST, link->network->cost);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_BRPORT_COST attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_call_async(link->manager->rtnl, req, link_set_handler, link, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return r;
}

static int link_lldp_save(Link *link) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sd_lldp_neighbor **l = NULL;
        int n = 0, r, i;

        assert(link);
        assert(link->lldp_file);

        if (!link->lldp) {
                (void) unlink(link->lldp_file);
                return 0;
        }

        r = sd_lldp_get_neighbors(link->lldp, &l);
        if (r < 0)
                goto finish;
        if (r == 0) {
                (void) unlink(link->lldp_file);
                goto finish;
        }

        n = r;

        r = fopen_temporary(link->lldp_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        for (i = 0; i < n; i++) {
                const void *p;
                le64_t u;
                size_t sz;

                r = sd_lldp_neighbor_get_raw(l[i], &p, &sz);
                if (r < 0)
                        goto finish;

                u = htole64(sz);
                (void) fwrite(&u, 1, sizeof(u), f);
                (void) fwrite(p, 1, sz, f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        if (rename(temp_path, link->lldp_file) < 0) {
                r = -errno;
                goto finish;
        }

finish:
        if (r < 0) {
                (void) unlink(link->lldp_file);
                if (temp_path)
                        (void) unlink(temp_path);

                log_link_error_errno(link, r, "Failed to save LLDP data to %s: %m", link->lldp_file);
        }

        if (l) {
                for (i = 0; i < n; i++)
                        sd_lldp_neighbor_unref(l[i]);
                free(l);
        }

        return r;
}

static void lldp_handler(sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        (void) link_lldp_save(link);

        if (link_lldp_emit_enabled(link) && event == SD_LLDP_EVENT_ADDED) {
                /* If we received information about a new neighbor, restart the LLDP "fast" logic */

                log_link_debug(link, "Received LLDP datagram from previously unknown neighbor, restarting 'fast' LLDP transmission.");

                r = link_lldp_emit_start(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to restart LLDP transmission: %m");
        }
}

static int link_acquire_ipv6_conf(Link *link) {
        int r;

        assert(link);

        if (link_dhcp6_enabled(link)) {
                assert(link->dhcp6_client);
                assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

                /* start DHCPv6 client in stateless mode */
                r = dhcp6_request_address(link, true);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r,  "Could not acquire DHCPv6 lease: %m");
                else
                        log_link_debug(link, "Acquiring DHCPv6 lease");
        }

        if (link_ipv6_accept_ra_enabled(link)) {
                assert(link->ndisc);

                log_link_debug(link, "Discovering IPv6 routers");

                r = sd_ndisc_start(link->ndisc);
                if (r < 0 && r != -EBUSY)
                        return log_link_warning_errno(link, r, "Could not start IPv6 Router Discovery: %m");
        }

        return 0;
}

static int link_acquire_ipv4_conf(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->event);

        if (link_ipv4ll_enabled(link)) {
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

        if (in_addr_is_null(AF_INET6, (const union in_addr_union*) &link->ipv6ll_address) == 0) {
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
                if ((link->flags & IFF_LOWER_UP) && !(link->flags & IFF_DORMANT))
                        return true;

        return false;
}

static int link_up_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                /* we warn but don't fail the link, as it may be
                   brought up later */
                log_link_warning_errno(link, r, "Could not bring up interface: %m");

        return 1;
}

static int link_up(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        uint8_t ipv6ll_mode;
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

        /* If IPv6 not configured (no static IPv6 address and IPv6LL autoconfiguration is disabled)
           for this interface, or if it is a bridge slave, then disable IPv6 else enable it. */
        (void) link_enable_ipv6(link);

        if (link->network->mtu) {
                /* IPv6 protocol requires a minimum MTU of IPV6_MTU_MIN(1280) bytes
                   on the interface. Bump up MTU bytes to IPV6_MTU_MIN. */
                if (link_ipv6_enabled(link) && link->network->mtu < IPV6_MIN_MTU) {

                        log_link_warning(link, "Bumping MTU to " STRINGIFY(IPV6_MIN_MTU) ", as "
                                         "IPv6 is requested and requires a minimum MTU of " STRINGIFY(IPV6_MIN_MTU) " bytes: %m");

                        link->network->mtu = IPV6_MIN_MTU;
                }

                r = sd_netlink_message_append_u32(req, IFLA_MTU, link->network->mtu);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set MTU: %m");
        }

        r = sd_netlink_message_open_container(req, IFLA_AF_SPEC);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open IFLA_AF_SPEC container: %m");

        if (link_ipv6_enabled(link)) {
                /* if the kernel lacks ipv6 support setting IFF_UP fails if any ipv6 options are passed */
                r = sd_netlink_message_open_container(req, AF_INET6);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not open AF_INET6 container: %m");

                if (!link_ipv6ll_enabled(link))
                        ipv6ll_mode = IN6_ADDR_GEN_MODE_NONE;
                else {
                        const char *p = NULL;
                        _cleanup_free_ char *stable_secret = NULL;

                        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/stable_secret");
                        r = read_one_line_file(p, &stable_secret);

                        if (r < 0)
                                ipv6ll_mode = IN6_ADDR_GEN_MODE_EUI64;
                        else
                                ipv6ll_mode = IN6_ADDR_GEN_MODE_STABLE_PRIVACY;
                }
                r = sd_netlink_message_append_u8(req, IFLA_INET6_ADDR_GEN_MODE, ipv6ll_mode);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_INET6_ADDR_GEN_MODE: %m");

                if (!in_addr_is_null(AF_INET6, &link->network->ipv6_token)) {
                        r = sd_netlink_message_append_in6_addr(req, IFLA_INET6_TOKEN, &link->network->ipv6_token.in6);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append IFLA_INET6_TOKEN: %m");
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not close AF_INET6 container: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close IFLA_AF_SPEC container: %m");

        r = sd_netlink_call_async(link->manager->rtnl, req, link_up_handler, link, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_down_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not bring down interface: %m");

        return 1;
}

static int link_down(Link *link) {
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

        r = sd_netlink_call_async(link->manager->rtnl, req, link_down_handler, link,  0, NULL);
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
                r = link_down(link);
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

void link_drop(Link *link) {
        if (!link || link->state == LINK_STATE_LINGER)
                return;

        link_set_state(link, LINK_STATE_LINGER);

        link_free_carrier_maps(link);

        log_link_debug(link, "Link removed");

        (void)unlink(link->state_file);
        link_unref(link);

        return;
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
        }

        if (link->network->bridge || streq_ptr("bridge", link->kind)) {
                r = link_set_bridge_vlan(link);
                if (r < 0)
                        log_link_error_errno(link, r, "Could not set bridge vlan: %m");
        }

        return link_enter_set_addresses(link);
}

static int netdev_join_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);

        link->enslaving--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not join netdev: %m");
                link_enter_failed(link);
                return 1;
        } else
                log_link_debug(link, "Joined netdev");

        if (link->enslaving <= 0)
                link_joined(link);

        return 1;
}

static int link_enter_join_netdev(Link *link) {
        NetDev *netdev;
        Iterator i;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_PENDING);

        link_set_state(link, LINK_STATE_ENSLAVING);

        link_dirty(link);

        if (!link->network->bridge &&
            !link->network->bond &&
            !link->network->vrf &&
            hashmap_isempty(link->network->stacked_netdevs))
                return link_joined(link);

        if (link->network->bond) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->bond),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->bond->ifname),
                           NULL);

                r = netdev_join(link->network->bond, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->bond),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->bond->ifname),
                                         NULL);

                        link_enter_failed(link);
                        return r;
                }

                link->enslaving++;
        }

        if (link->network->bridge) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->bridge),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->bridge->ifname),
                           NULL);

                r = netdev_join(link->network->bridge, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->bridge),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->bridge->ifname),
                                         NULL),
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving++;
        }

        if (link->network->vrf) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(link->network->vrf),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", link->network->vrf->ifname),
                           NULL);
                r = netdev_join(link->network->vrf, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(link->network->vrf),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", link->network->vrf->ifname),
                                         NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving++;
        }

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs, i) {

                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_NETDEV_INTERFACE(netdev),
                           LOG_LINK_MESSAGE(link, "Enslaving by '%s'", netdev->ifname),
                           NULL);

                r = netdev_join(netdev, link, netdev_join_handler);
                if (r < 0) {
                        log_struct_errno(LOG_WARNING, r,
                                         LOG_LINK_INTERFACE(link),
                                         LOG_NETDEV_INTERFACE(netdev),
                                         LOG_LINK_MESSAGE(link, "Could not join netdev '%s': %m", netdev->ifname),
                                         NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving++;
        }

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

        r = write_string_file("/proc/sys/net/ipv4/ip_forward", "1", WRITE_STRING_FILE_VERIFY_ON_FAILURE);
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

        r = write_string_file("/proc/sys/net/ipv6/conf/all/forwarding", "1", WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 packet forwarding, ignoring: %m");

        return 0;
}

static int link_set_ipv6_privacy_extensions(Link *link) {
        char buf[DECIMAL_STR_MAX(unsigned) + 1];
        IPv6PrivacyExtensions s;
        const char *p = NULL;
        int r;

        s = link_ipv6_privacy_extensions(link);
        if (s < 0)
                return 0;

        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/use_tempaddr");
        xsprintf(buf, "%u", (unsigned) link->network->ipv6_privacy_extensions);

        r = write_string_file(p, buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 privacy extension for interface: %m");

        return 0;
}

static int link_set_ipv6_accept_ra(Link *link) {
        const char *p = NULL;
        int r;

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/accept_ra");

        /* We handle router advertisements ourselves, tell the kernel to GTFO */
        r = write_string_file(p, "0", WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot disable kernel IPv6 accept_ra for interface: %m");

        return 0;
}

static int link_set_ipv6_dad_transmits(Link *link) {
        char buf[DECIMAL_STR_MAX(int) + 1];
        const char *p = NULL;
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

        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/dad_transmits");
        xsprintf(buf, "%i", link->network->ipv6_dad_transmits);

        r = write_string_file(p, buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 dad transmits for interface: %m");

        return 0;
}

static int link_set_ipv6_hop_limit(Link *link) {
        char buf[DECIMAL_STR_MAX(int) + 1];
        const char *p = NULL;
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

        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/hop_limit");
        xsprintf(buf, "%i", link->network->ipv6_hop_limit);

        r = write_string_file(p, buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 hop limit for interface: %m");

        return 0;
}

static int link_drop_foreign_config(Link *link) {
        Address *address;
        Route *route;
        Iterator i;
        int r;

        SET_FOREACH(address, link->addresses_foreign, i) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in_addr_is_link_local(AF_INET6, &address->in_addr) == 1)
                        continue;

                r = address_remove(address, link, link_address_remove_handler);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(route, link->routes_foreign, i) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                r = route_remove(route, link, link_route_remove_handler);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_update_lldp(Link *link) {
        int r;

        assert(link);

        if (!link->lldp)
                return 0;

        if (link->flags & IFF_UP) {
                r = sd_lldp_start(link->lldp);
                if (r > 0)
                        log_link_debug(link, "Started LLDP.");
        } else {
                r = sd_lldp_stop(link->lldp);
                if (r > 0)
                        log_link_debug(link, "Stopped LLDP.");
        }

        return r;
}

static int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_PENDING);

        /* Drop foreign config, but ignore loopback or critical devices.
         * We do not want to remove loopback address or addresses used for root NFS. */
        if (!(link->flags & IFF_LOOPBACK) && !(link->network->dhcp_critical)) {
                r = link_drop_foreign_config(link);
                if (r < 0)
                        return r;
        }

        r = link_set_bridge_fdb(link);
        if (r < 0)
                return r;

        r = link_set_proxy_arp(link);
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

        if (link_ipv4ll_enabled(link)) {
                r = ipv4ll_configure(link);
                if (r < 0)
                        return r;
        }

        if (link_dhcp4_enabled(link)) {
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

        if (link_lldp_rx_enabled(link)) {
                r = sd_lldp_new(&link->lldp);
                if (r < 0)
                        return r;

                r = sd_lldp_set_ifindex(link->lldp, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_lldp_match_capabilities(link->lldp,
                                               link->network->lldp_mode == LLDP_MODE_ROUTERS_ONLY ?
                                               SD_LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS :
                                               SD_LLDP_SYSTEM_CAPABILITIES_ALL);
                if (r < 0)
                        return r;

                r = sd_lldp_set_filter_address(link->lldp, &link->mac);
                if (r < 0)
                        return r;

                r = sd_lldp_attach_event(link->lldp, NULL, 0);
                if (r < 0)
                        return r;

                r = sd_lldp_set_callback(link->lldp, lldp_handler, link);
                if (r < 0)
                        return r;

                r = link_update_lldp(link);
                if (r < 0)
                        return r;
        }

        if (link_has_carrier(link)) {
                r = link_acquire_conf(link);
                if (r < 0)
                        return r;
        }

        return link_enter_join_netdev(link);
}

static int link_initialized_and_synced(sd_netlink *rtnl, sd_netlink_message *m,
                                       void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        Network *network;
        int r;

        assert(link);
        assert(link->ifname);
        assert(link->manager);

        if (link->state != LINK_STATE_PENDING)
                return 1;

        log_link_debug(link, "Link state is up-to-date");

        r = link_new_bound_by_list(link);
        if (r < 0)
                return r;

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        if (!link->network) {
                r = network_get(link->manager, link->udev_device, link->ifname,
                                &link->mac, &network);
                if (r == -ENOENT) {
                        link_enter_unmanaged(link);
                        return 1;
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

                r = network_apply(link->manager, network, link);
                if (r < 0)
                        return r;
        }

        r = link_new_bound_to_list(link);
        if (r < 0)
                return r;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 1;
}

int link_initialized(Link *link, struct udev_device *device) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(device);

        if (link->state != LINK_STATE_PENDING)
                return 0;

        if (link->udev_device)
                return 0;

        log_link_debug(link, "udev initialized link");

        link->udev_device = udev_device_ref(device);

        /* udev has initialized the link, but we don't know if we have yet
         * processed the NEWLINK messages with the latest state. Do a GETLINK,
         * when it returns we know that the pending NEWLINKs have already been
         * processed and that we are up-to-date */

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_GETLINK,
                                     link->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_call_async(link->manager->rtnl, req,
                               link_initialized_and_synced, link, 0, NULL);
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
        union in_addr_union route_dst;
        const char *p;
        int r;

        assert(link);

        r = parse_env_file(link->state_file, NEWLINE,
                           "NETWORK_FILE", &network_file,
                           "ADDRESSES", &addresses,
                           "ROUTES", &routes,
                           "DHCP4_ADDRESS", &dhcp4_address,
                           "IPV4LL_ADDRESS", &ipv4ll_address,
                           NULL);
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

                r = network_apply(link->manager, network, link);
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
                        Route *route;
                        _cleanup_free_ char *route_str = NULL;
                        _cleanup_(sd_event_source_unrefp) sd_event_source *expire = NULL;
                        usec_t lifetime;
                        char *prefixlen_str;
                        int family;
                        unsigned char prefixlen, tos, table;
                        uint32_t priority;

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

                        r = sscanf(prefixlen_str, "%hhu/%hhu/%"SCNu32"/%hhu/"USEC_FMT, &prefixlen, &tos, &priority, &table, &lifetime);
                        if (r != 5) {
                                log_link_debug(link,
                                               "Failed to parse destination prefix length, tos, priority, table or expiration %s",
                                               prefixlen_str);
                                continue;
                        }

                        r = in_addr_from_string_auto(route_str, &family, &route_dst);
                        if (r < 0) {
                                log_link_debug_errno(link, r, "Failed to parse route destination %s: %m", route_str);
                                continue;
                        }

                        r = route_add(link, family, &route_dst, prefixlen, tos, priority, table, &route);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to add route: %m");

                        if (lifetime != USEC_INFINITY) {
                                r = sd_event_add_time(link->manager->event, &expire, clock_boottime_or_monotonic(), lifetime,
                                                      0, route_expire_handler, route);
                                if (r < 0)
                                        log_link_warning_errno(link, r, "Could not arm route expiration handler: %m");
                        }

                        route->lifetime = lifetime;
                        sd_event_source_unref(route->expire);
                        route->expire = expire;
                        expire = NULL;
                }
        }

        if (dhcp4_address) {
                r = in_addr_from_string(AF_INET, dhcp4_address, &address);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Falied to parse DHCPv4 address %s: %m", dhcp4_address);
                        goto dhcp4_address_fail;
                }

                r = sd_dhcp_client_new(&link->dhcp_client);
                if (r < 0)
                        return log_link_error_errno(link, r, "Falied to create DHCPv4 client: %m");

                r = sd_dhcp_client_set_request_address(link->dhcp_client, &address.in);
                if (r < 0)
                        return log_link_error_errno(link, r, "Falied to set initial DHCPv4 address %s: %m", dhcp4_address);
        }

dhcp4_address_fail:

        if (ipv4ll_address) {
                r = in_addr_from_string(AF_INET, ipv4ll_address, &address);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Falied to parse IPv4LL address %s: %m", ipv4ll_address);
                        goto ipv4ll_address_fail;
                }

                r = sd_ipv4ll_new(&link->ipv4ll);
                if (r < 0)
                        return log_link_error_errno(link, r, "Falied to create IPv4LL client: %m");

                r = sd_ipv4ll_set_address(link->ipv4ll, &address.in);
                if (r < 0)
                        return log_link_error_errno(link, r, "Falied to set initial IPv4LL address %s: %m", ipv4ll_address);
        }

ipv4ll_address_fail:

        return 0;
}

int link_add(Manager *m, sd_netlink_message *message, Link **ret) {
        Link *link;
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        char ifindex_str[2 + DECIMAL_STR_MAX(int)];
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
                device = udev_device_new_from_device_id(m->udev, ifindex_str);
                if (!device) {
                        r = log_link_warning_errno(link, errno, "Could not find udev device: %m");
                        goto failed;
                }

                if (udev_device_get_is_initialized(device) <= 0) {
                        /* not yet ready */
                        log_link_debug(link, "link pending udev initialization...");
                        return 0;
                }

                r = link_initialized(link, device);
                if (r < 0)
                        goto failed;
        } else {
                /* we are calling a callback directly, so must take a ref */
                link_ref(link);

                r = link_initialized_and_synced(m->rtnl, NULL, link);
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

        if (!IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_UNMANAGED, LINK_STATE_FAILED)) {
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

        if (!IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_UNMANAGED, LINK_STATE_FAILED)) {
                r = link_acquire_conf(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }

                r = link_enter_set_addresses(link);
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

        r = link_stop_clients(link);
        if (r < 0) {
                link_enter_failed(link);
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
        int r;

        assert(link);
        assert(link->ifname);
        assert(m);

        if (link->state == LINK_STATE_LINGER) {
                link_ref(link);
                log_link_info(link, "Link readded");
                link_set_state(link, LINK_STATE_ENSLAVING);

                r = link_new_carrier_maps(link);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r >= 0 && !streq(ifname, link->ifname)) {
                log_link_info(link, "Renamed to %s", ifname);

                link_free_carrier_maps(link);

                r = free_and_strdup(&link->ifname, ifname);
                if (r < 0)
                        return r;

                r = link_new_carrier_maps(link);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_read_u32(m, IFLA_MTU, &mtu);
        if (r >= 0 && mtu > 0) {
                link->mtu = mtu;
                if (!link->original_mtu) {
                        link->original_mtu = mtu;
                        log_link_debug(link, "Saved original MTU: %" PRIu32, link->original_mtu);
                }

                if (link->dhcp_client) {
                        r = sd_dhcp_client_set_mtu(link->dhcp_client,
                                                   link->mtu);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not update MTU in DHCP client: %m");
                                return r;
                        }
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
                                const DUID *duid = link_duid(link);

                                r = sd_dhcp_client_set_mac(link->dhcp_client,
                                                           (const uint8_t *) &link->mac,
                                                           sizeof (link->mac),
                                                           ARPHRD_ETHER);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCP client: %m");

                                r = sd_dhcp_client_set_iaid_duid(link->dhcp_client,
                                                                 link->network->iaid,
                                                                 duid->type,
                                                                 duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                                 duid->raw_data_len);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update DUID/IAID in DHCP client: %m");
                        }

                        if (link->dhcp6_client) {
                                const DUID* duid = link_duid(link);

                                r = sd_dhcp6_client_set_mac(link->dhcp6_client,
                                                            (const uint8_t *) &link->mac,
                                                            sizeof (link->mac),
                                                            ARPHRD_ETHER);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update MAC address in DHCPv6 client: %m");

                                r = sd_dhcp6_client_set_iaid(link->dhcp6_client,
                                                             link->network->iaid);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update DHCPv6 IAID: %m");

                                r = sd_dhcp6_client_set_duid(link->dhcp6_client,
                                                             duid->type,
                                                             duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                             duid->raw_data_len);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not update DHCPv6 DUID: %m");
                        }
                }
        }

        had_carrier = link_has_carrier(link);

        r = link_update_flags(link, m);
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

int link_save(Link *link) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *admin_state, *oper_state;
        Address *a;
        Route *route;
        Iterator i;
        int r;

        assert(link);
        assert(link->state_file);
        assert(link->lease_file);
        assert(link->manager);

        if (link->state == LINK_STATE_LINGER) {
                unlink(link->state_file);
                return 0;
        }

        link_lldp_save(link);

        admin_state = link_state_to_string(link->state);
        assert(admin_state);

        oper_state = link_operstate_to_string(link->operstate);
        assert(oper_state);

        r = fopen_temporary(link->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADMIN_STATE=%s\n"
                "OPER_STATE=%s\n",
                admin_state, oper_state);

        if (link->network) {
                bool space;
                sd_dhcp6_lease *dhcp6_lease = NULL;
                const char *dhcp_domainname = NULL;
                char **dhcp6_domains = NULL;

                if (link->dhcp6_client) {
                        r = sd_dhcp6_client_get_lease(link->dhcp6_client, &dhcp6_lease);
                        if (r < 0 && r != -ENOMSG)
                                log_link_debug(link, "No DHCPv6 lease");
                }

                fprintf(f, "NETWORK_FILE=%s\n", link->network->filename);

                fputs("DNS=", f);
                space = false;
                fputstrv(f, link->network->dns, NULL, &space);

                if (link->network->dhcp_use_dns &&
                    link->dhcp_lease) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                if (space)
                                        fputc(' ', f);
                                serialize_in_addrs(f, addresses, r);
                                space = true;
                        }
                }

                if (link->network->dhcp_use_dns && dhcp6_lease) {
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

                if (link->network->dhcp_use_dns && link->ndisc_rdnss) {
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
                fputstrv(f, link->network->ntp, NULL, &space);

                if (link->network->dhcp_use_ntp &&
                    link->dhcp_lease) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                if (space)
                                        fputc(' ', f);
                                serialize_in_addrs(f, addresses, r);
                                space = true;
                        }
                }

                if (link->network->dhcp_use_ntp && dhcp6_lease) {
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
                        if (link->dhcp_lease)
                                (void) sd_dhcp_lease_get_domainname(link->dhcp_lease, &dhcp_domainname);
                        if (dhcp6_lease)
                                (void) sd_dhcp6_lease_get_domains(dhcp6_lease, &dhcp6_domains);
                }

                fputs("DOMAINS=", f);
                fputstrv(f, link->network->search_domains, NULL, &space);

                if (link->network->dhcp_use_domains == DHCP_USE_DOMAINS_YES) {
                        NDiscDNSSL *dd;

                        if (dhcp_domainname)
                                fputs_with_space(f, dhcp_domainname, NULL, &space);
                        if (dhcp6_domains)
                                fputstrv(f, dhcp6_domains, NULL, &space);

                        SET_FOREACH(dd, link->ndisc_dnssl, i)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                fputs("ROUTE_DOMAINS=", f);
                fputstrv(f, link->network->route_domains, NULL, NULL);

                if (link->network->dhcp_use_domains == DHCP_USE_DOMAINS_ROUTE) {
                        NDiscDNSSL *dd;

                        if (dhcp_domainname)
                                fputs_with_space(f, dhcp_domainname, NULL, &space);
                        if (dhcp6_domains)
                                fputstrv(f, dhcp6_domains, NULL, &space);

                        SET_FOREACH(dd, link->ndisc_dnssl, i)
                                fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
                }

                fputc('\n', f);

                fprintf(f, "LLMNR=%s\n",
                        resolve_support_to_string(link->network->llmnr));
                fprintf(f, "MDNS=%s\n",
                        resolve_support_to_string(link->network->mdns));

                if (link->network->dnssec_mode != _DNSSEC_MODE_INVALID)
                        fprintf(f, "DNSSEC=%s\n",
                                dnssec_mode_to_string(link->network->dnssec_mode));

                if (!set_isempty(link->network->dnssec_negative_trust_anchors)) {
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

                        fprintf(f, "%s%s/%hhu/%hhu/%"PRIu32"/%hhu/"USEC_FMT, space ? " " : "", route_str,
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
                        serialize_in_addrs(f, &address, 1);
                        fputc('\n', f);
                }

                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        goto fail;

                fprintf(f,
                        "DHCP_LEASE=%s\n",
                        link->lease_file);
        } else
                unlink(link->lease_file);

        if (link->ipv4ll) {
                struct in_addr address;

                r = sd_ipv4ll_get_address(link->ipv4ll, &address);
                if (r >= 0) {
                        fputs("IPV4LL_ADDRESS=", f);
                        serialize_in_addrs(f, &address, 1);
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

        set_remove(link->manager->dirty_links, link);
        link_unref(link);
}

static const char* const link_state_table[_LINK_STATE_MAX] = {
        [LINK_STATE_PENDING] = "pending",
        [LINK_STATE_ENSLAVING] = "configuring",
        [LINK_STATE_SETTING_ADDRESSES] = "configuring",
        [LINK_STATE_SETTING_ROUTES] = "configuring",
        [LINK_STATE_CONFIGURED] = "configured",
        [LINK_STATE_UNMANAGED] = "unmanaged",
        [LINK_STATE_FAILED] = "failed",
        [LINK_STATE_LINGER] = "linger",
};

DEFINE_STRING_TABLE_LOOKUP(link_state, LinkState);

static const char* const link_operstate_table[_LINK_OPERSTATE_MAX] = {
        [LINK_OPERSTATE_OFF] = "off",
        [LINK_OPERSTATE_NO_CARRIER] = "no-carrier",
        [LINK_OPERSTATE_DORMANT] = "dormant",
        [LINK_OPERSTATE_CARRIER] = "carrier",
        [LINK_OPERSTATE_DEGRADED] = "degraded",
        [LINK_OPERSTATE_ROUTABLE] = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_operstate, LinkOperationalState);

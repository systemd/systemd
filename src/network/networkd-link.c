/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "networkd.h"
#include "libudev-private.h"
#include "udev-util.h"
#include "util.h"
#include "virt.h"
#include "bus-util.h"
#include "network-internal.h"
#include "conf-parser.h"

#include "network-util.h"
#include "dhcp-lease-internal.h"

static int ipv4ll_address_update(Link *link, bool deprecate);
static bool ipv4ll_is_bound(sd_ipv4ll *ll);

static int link_new(Manager *manager, sd_rtnl_message *message, Link **ret) {
        _cleanup_link_unref_ Link *link = NULL;
        uint16_t type;
        char *ifname;
        int r, ifindex;

        assert(manager);
        assert(manager->links);
        assert(message);
        assert(ret);

        r = sd_rtnl_message_get_type(message, &type);
        if (r < 0)
                return r;
        else if (type != RTM_NEWLINK)
                return -EINVAL;

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return r;
        else if (ifindex <= 0)
                return -EINVAL;

        r = sd_rtnl_message_read_string(message, IFLA_IFNAME, &ifname);
        if (r < 0)
                return r;

        link = new0(Link, 1);
        if (!link)
                return -ENOMEM;

        link->n_ref = 1;
        link->manager = manager;
        link->state = LINK_STATE_INITIALIZING;
        link->ifindex = ifindex;
        link->ifname = strdup(ifname);
        if (!link->ifname)
                return -ENOMEM;

        r = sd_rtnl_message_read_ether_addr(message, IFLA_ADDRESS, &link->mac);
        if (r < 0)
                log_debug_link(link, "MAC address not found for new device, continuing without");

        r = asprintf(&link->state_file, "/run/systemd/netif/links/%"PRIu64,
                     link->ifindex);
        if (r < 0)
                return -ENOMEM;

        r = asprintf(&link->lease_file, "/run/systemd/netif/leases/%"PRIu64,
                     link->ifindex);
        if (r < 0)
                return -ENOMEM;

        r = hashmap_put(manager->links, &link->ifindex, link);
        if (r < 0)
                return r;

        *ret = link;
        link = NULL;

        return 0;
}

static void link_free(Link *link) {
        Address *address;

        if (!link)
                return;

        while ((address = link->addresses)) {
                LIST_REMOVE(addresses, link->addresses, address);
                address_free(address);
        }

        while ((address = link->pool_addresses)) {
                LIST_REMOVE(addresses, link->pool_addresses, address);
                address_free(address);
        }

        sd_dhcp_client_unref(link->dhcp_client);
        sd_dhcp_lease_unref(link->dhcp_lease);

        unlink(link->lease_file);
        free(link->lease_file);

        sd_ipv4ll_unref(link->ipv4ll);
        sd_dhcp6_client_unref(link->dhcp6_client);
        sd_icmp6_nd_unref(link->icmp6_router_discovery);

        if (link->manager)
                hashmap_remove(link->manager->links, &link->ifindex);

        free(link->ifname);

        unlink(link->state_file);
        free(link->state_file);

        udev_device_unref(link->udev_device);

        free(link);
}

Link *link_unref(Link *link) {
        if (link && (-- link->n_ref <= 0))
                link_free(link);

        return NULL;
}

Link *link_ref(Link *link) {
        if (link)
                assert_se(++ link->n_ref >= 2);

        return link;
}

int link_get(Manager *m, int ifindex, Link **ret) {
        Link *link;
        uint64_t ifindex_64;

        assert(m);
        assert(m->links);
        assert(ifindex);
        assert(ret);

        ifindex_64 = ifindex;
        link = hashmap_get(m->links, &ifindex_64);
        if (!link)
                return -ENODEV;

        *ret = link;

        return 0;
}

void link_drop(Link *link) {
        if (!link || link->state == LINK_STATE_LINGER)
                return;

        link->state = LINK_STATE_LINGER;

        log_debug_link(link, "link removed");

        link_unref(link);

        return;
}

static void link_enter_unmanaged(Link *link) {
        assert(link);

        log_debug_link(link, "unmanaged");

        link->state = LINK_STATE_UNMANAGED;

        link_save(link);
}

static int link_stop_clients(Link *link) {
        int r = 0, k;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        if (!link->network)
                return 0;

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V6)) {
                assert(link->dhcp_client);

                k = sd_dhcp_client_stop(link->dhcp_client);
                if (k < 0) {
                        log_warning_link(link, "Could not stop DHCPv4 client: %s", strerror(-r));
                        r = k;
                }
        }

        if (link->network->ipv4ll) {
                assert(link->ipv4ll);

                k = sd_ipv4ll_stop(link->ipv4ll);
                if (k < 0) {
                        log_warning_link(link, "Could not stop IPv4 link-local: %s", strerror(-r));
                        r = k;
                }
        }

        if (link->network->dhcp_server) {
                assert(link->dhcp_server);

                k = sd_dhcp_server_stop(link->dhcp_server);
                if (k < 0) {
                        log_warning_link(link, "Could not stop DHCPv4 server: %s", strerror(-r));
                        r = k;
                }
        }

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V6)) {
                assert(link->icmp6_router_discovery);

                if (link->dhcp6_client) {
                        k = sd_dhcp6_client_stop(link->dhcp6_client);
                        if (k < 0) {
                                log_warning_link(link, "Could not stop DHCPv6 client: %s", strerror(-r));
                                r = k;
                        }
                }

                k = sd_icmp6_nd_stop(link->icmp6_router_discovery);
                if (k < 0) {
                        log_warning_link(link, "Could not stop ICMPv6 router discovery: %s", strerror(-r));
                        r = k;
                }
        }

        return r;
}

static void link_enter_failed(Link *link) {
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        log_warning_link(link, "failed");

        link->state = LINK_STATE_FAILED;

        link_stop_clients(link);

        link_save(link);
}

static Address* link_find_dhcp_server_address(Link *link) {
        Address *address;

        assert(link);
        assert(link->network);

        /* The the first statically configured address if there is any */
        LIST_FOREACH(addresses, address, link->network->static_addresses) {

                if (address->family != AF_INET)
                        continue;

                if (in_addr_null(address->family, &address->in_addr))
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
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_SETTING_ROUTES);

        if (link->network->dhcp_server &&
            !sd_dhcp_server_is_running(link->dhcp_server)) {
                struct in_addr pool_start;
                Address *address;

                address = link_find_dhcp_server_address(link);
                if (!address) {
                        log_warning_link(link, "Failed to find suitable address for DHCPv4 server instance.");
                        link_enter_failed(link);
                        return 0;
                }

                log_debug_link(link, "offering DHCPv4 leases");

                r = sd_dhcp_server_set_address(link->dhcp_server, &address->in_addr.in);
                if (r < 0)
                        return r;

                /* offer 32 addresses starting from the address following the server address */
                pool_start.s_addr = htobe32(be32toh(address->in_addr.in.s_addr) + 1);
                r = sd_dhcp_server_set_lease_pool(link->dhcp_server,
                                                  &pool_start, 32);
                if (r < 0)
                        return r;

                /* TODO:
                r = sd_dhcp_server_set_router(link->dhcp_server,
                                              &main_address->in_addr.in);
                if (r < 0)
                        return r;

                r = sd_dhcp_server_set_prefixlen(link->dhcp_server,
                                                 main_address->prefixlen);
                if (r < 0)
                        return r;
                */

                r = sd_dhcp_server_start(link->dhcp_server);
                if (r < 0) {
                        log_warning_link(link, "could not start DHCPv4 server "
                                         "instance: %s", strerror(-r));

                        link_enter_failed(link);

                        return 0;
                }
        }

        log_info_link(link, "link configured");

        link->state = LINK_STATE_CONFIGURED;

        link_save(link);

        return 0;
}

static int route_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link->route_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_SETTING_ADDRESSES,
                      LINK_STATE_SETTING_ROUTES, LINK_STATE_FAILED,
                      LINK_STATE_LINGER));

        link->route_messages --;

        if (IN_SET(LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not set route: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        /* we might have received an old reply after moving back to SETTING_ADDRESSES,
         * ignore it */
        if (link->route_messages == 0 && link->state == LINK_STATE_SETTING_ROUTES) {
                log_debug_link(link, "routes set");
                link_enter_configured(link);
        }

        return 1;
}

static int link_set_dhcp_routes(Link *link) {
        struct sd_dhcp_route *static_routes;
        size_t static_routes_size;
        int r;
        unsigned i;

        assert(link);

        r = sd_dhcp_lease_get_routes(link->dhcp_lease, &static_routes, &static_routes_size);
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_link(link, "DHCP error: could not get routes: %s", strerror(-r));
                return r;
        }

        for (i = 0; i < static_routes_size; i++) {
                _cleanup_route_free_ Route *route = NULL;

                r = route_new_dynamic(&route);
                if (r < 0) {
                        log_error_link(link, "Could not allocate route: %s",
                                       strerror(-r));
                        return r;
                }

                route->family = AF_INET;
                route->in_addr.in = static_routes[i].gw_addr;
                route->dst_addr.in = static_routes[i].dst_addr;
                route->dst_prefixlen = static_routes[i].dst_prefixlen;
                route->metrics = DHCP_STATIC_ROUTE_METRIC;

                r = route_configure(route, link, &route_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set host route: %s", strerror(-r));
                        return r;
                }

                link->route_messages ++;
        }

        return 0;
}

static int link_enter_set_routes(Link *link) {
        Route *rt;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_SETTING_ADDRESSES);

        link->state = LINK_STATE_SETTING_ROUTES;

        if (!link->network->static_routes && !link->dhcp_lease &&
            (!link->ipv4ll || ipv4ll_is_bound(link->ipv4ll) == false))
                return link_enter_configured(link);

        log_debug_link(link, "setting routes");

        LIST_FOREACH(routes, rt, link->network->static_routes) {
                r = route_configure(rt, link, &route_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set routes: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->route_messages ++;
        }

        if (link->ipv4ll && !link->dhcp_lease) {
                _cleanup_route_free_ Route *route = NULL;
                struct in_addr addr;

                r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
                if (r < 0 && r != -ENOENT) {
                        log_warning_link(link, "IPV4LL error: no address: %s",
                                        strerror(-r));
                        return r;
                }

                if (r != -ENOENT) {
                        r = route_new_dynamic(&route);
                        if (r < 0) {
                                log_error_link(link, "Could not allocate route: %s",
                                               strerror(-r));
                                return r;
                        }

                        route->family = AF_INET;
                        route->scope = RT_SCOPE_LINK;
                        route->metrics = 99;

                        r = route_configure(route, link, &route_handler);
                        if (r < 0) {
                                log_warning_link(link,
                                                 "could not set routes: %s", strerror(-r));
                                link_enter_failed(link);
                                return r;
                        }

                        link->route_messages ++;
                }
        }

        if (link->dhcp_lease) {
                _cleanup_route_free_ Route *route = NULL;
                _cleanup_route_free_ Route *route_gw = NULL;
                struct in_addr gateway;

                r = sd_dhcp_lease_get_router(link->dhcp_lease, &gateway);
                if (r < 0 && r != -ENOENT) {
                        log_warning_link(link, "DHCP error: could not get gateway: %s",
                                         strerror(-r));
                        return r;
                }

                if (r >= 0) {
                        r = route_new_dynamic(&route);
                        if (r < 0) {
                                log_error_link(link, "Could not allocate route: %s",
                                               strerror(-r));
                                return r;
                        }

                        r = route_new_dynamic(&route_gw);
                        if (r < 0) {
                                log_error_link(link, "Could not allocate route: %s",
                                               strerror(-r));
                                return r;
                        }

                        /* The dhcp netmask may mask out the gateway. Add an explicit
                         * route for the gw host so that we can route no matter the
                         * netmask or existing kernel route tables. */
                        route_gw->family = AF_INET;
                        route_gw->dst_addr.in = gateway;
                        route_gw->dst_prefixlen = 32;
                        route_gw->scope = RT_SCOPE_LINK;
                        route_gw->metrics = DHCP_STATIC_ROUTE_METRIC;

                        r = route_configure(route_gw, link, &route_handler);
                        if (r < 0) {
                                log_warning_link(link,
                                                 "could not set host route: %s", strerror(-r));
                                return r;
                        }

                        link->route_messages ++;

                        route->family = AF_INET;
                        route->in_addr.in = gateway;
                        route->metrics = DHCP_STATIC_ROUTE_METRIC;

                        r = route_configure(route, link, &route_handler);
                        if (r < 0) {
                                log_warning_link(link,
                                                 "could not set routes: %s", strerror(-r));
                                link_enter_failed(link);
                                return r;
                        }

                        link->route_messages ++;
                }

                if (link->network->dhcp_routes)
                        link_set_dhcp_routes(link);
        }

        if (link->route_messages == 0) {
                link_enter_configured(link);
        }

        return 0;
}

static int route_drop_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not drop route: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        return 0;
}

static int address_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->addr_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_SETTING_ADDRESSES,
               LINK_STATE_FAILED, LINK_STATE_LINGER));

        link->addr_messages --;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not set address: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        if (link->addr_messages == 0) {
                log_debug_link(link, "addresses set");
                link_enter_set_routes(link);
        }

        return 1;
}

static int link_enter_set_addresses(Link *link) {
        Address *ad;
        int r;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->state = LINK_STATE_SETTING_ADDRESSES;

        if (!link->network->static_addresses && !link->dhcp_lease &&
                (!link->ipv4ll || ipv4ll_is_bound(link->ipv4ll) == false))
                return link_enter_set_routes(link);

        log_debug_link(link, "setting addresses");

        LIST_FOREACH(addresses, ad, link->network->static_addresses) {
                r = address_configure(ad, link, &address_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set addresses: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->addr_messages ++;
        }

        if (link->ipv4ll && !link->dhcp_lease) {
                _cleanup_address_free_ Address *ll_addr = NULL;
                struct in_addr addr;

                r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
                if (r < 0 && r != -ENOENT) {
                        log_warning_link(link, "IPV4LL error: no address: %s",
                                        strerror(-r));
                        return r;
                }

                if (r != -ENOENT) {
                        r = address_new_dynamic(&ll_addr);
                        if (r < 0) {
                                log_error_link(link, "Could not allocate address: %s", strerror(-r));
                                return r;
                        }

                        ll_addr->family = AF_INET;
                        ll_addr->in_addr.in = addr;
                        ll_addr->prefixlen = 16;
                        ll_addr->broadcast.s_addr = ll_addr->in_addr.in.s_addr | htonl(0xfffffffflu >> ll_addr->prefixlen);
                        ll_addr->scope = RT_SCOPE_LINK;

                        r = address_configure(ll_addr, link, &address_handler);
                        if (r < 0) {
                                log_warning_link(link,
                                         "could not set addresses: %s", strerror(-r));
                                link_enter_failed(link);
                                return r;
                        }

                        link->addr_messages ++;
                }
        }

        if (link->dhcp_lease) {
                _cleanup_address_free_ Address *address = NULL;
                struct in_addr addr;
                struct in_addr netmask;
                unsigned prefixlen;

                r = sd_dhcp_lease_get_address(link->dhcp_lease, &addr);
                if (r < 0) {
                        log_warning_link(link, "DHCP error: no address: %s",
                                         strerror(-r));
                        return r;
                }

                if (!link->network->dhcp_critical) {
                        r = sd_dhcp_lease_get_lifetime(link->dhcp_lease,
                                                       &lifetime);
                        if (r < 0) {
                                log_warning_link(link, "DHCP error: no lifetime: %s",
                                                 strerror(-r));
                                return r;
                        }
                }

                r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
                if (r < 0) {
                        log_warning_link(link, "DHCP error: no netmask: %s",
                                         strerror(-r));
                        return r;
                }

                prefixlen = net_netmask_to_prefixlen(&netmask);

                r = address_new_dynamic(&address);
                if (r < 0) {
                        log_error_link(link, "Could not allocate address: %s",
                                       strerror(-r));
                        return r;
                }

                address->family = AF_INET;
                address->in_addr.in = addr;
                address->cinfo.ifa_prefered = lifetime;
                address->cinfo.ifa_valid = lifetime;
                address->prefixlen = prefixlen;
                address->broadcast.s_addr = addr.s_addr | ~netmask.s_addr;

                /* use update rather than configure so that we will update the lifetime
                   of an existing address if it has already been configured */
                r = address_update(address, link, &address_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set addresses: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->addr_messages ++;
        }

        return 0;
}

static int address_update_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not update address: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        return 0;
}

static int address_drop_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not drop address: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        return 0;
}

static int set_hostname_handler(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_bus_message_get_errno(m);
        if (r < 0)
                log_warning_link(link, "Could not set hostname: %s", strerror(-r));

        return 1;
}

static int link_set_hostname(Link *link, const char *hostname) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r = 0;

        assert(link);
        assert(link->manager);
        assert(hostname);

        log_debug_link(link, "Setting transient hostname: '%s'", hostname);

        if (!link->manager->bus) { /* TODO: replace by assert when we can rely on kdbus */
                log_info_link(link, "Not connected to system bus, ignoring transient hostname.");
                return 0;
        }

        r = sd_bus_message_new_method_call(
                        link->manager->bus,
                        &m,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "SetHostname");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "sb", hostname, false);
        if (r < 0)
                return r;

        r = sd_bus_call_async(link->manager->bus, NULL, m, set_hostname_handler, link, 0);
        if (r < 0) {
                log_error_link(link, "Could not set transient hostname: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        return 0;
}

static int set_mtu_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not set MTU: %s",
                                IFNAMSIZ, link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        return 1;
}

static int link_set_mtu(Link *link, uint32_t mtu) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_debug_link(link, "setting MTU: %" PRIu32, mtu);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req,
                                     RTM_SETLINK, link->ifindex);
        if (r < 0) {
                log_error_link(link, "Could not allocate RTM_SETLINK message");
                return r;
        }

        r = sd_rtnl_message_append_u32(req, IFLA_MTU, mtu);
        if (r < 0) {
                log_error_link(link, "Could not append MTU: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, set_mtu_handler, link, 0, NULL);
        if (r < 0) {
                log_error_link(link,
                               "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        return 0;
}

static int dhcp_lease_lost(Link *link) {
        _cleanup_address_free_ Address *address = NULL;
        struct in_addr addr;
        struct in_addr netmask;
        struct in_addr gateway;
        unsigned prefixlen;
        unsigned i;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        log_warning_link(link, "DHCP lease lost");

        if (link->network->dhcp_routes) {
                struct sd_dhcp_route *routes;
                size_t routes_size;

                r = sd_dhcp_lease_get_routes(link->dhcp_lease, &routes, &routes_size);
                if (r >= 0) {
                        for (i = 0; i < routes_size; i++) {
                                _cleanup_route_free_ Route *route = NULL;

                                r = route_new_dynamic(&route);
                                if (r >= 0) {
                                        route->family = AF_INET;
                                        route->in_addr.in = routes[i].gw_addr;
                                        route->dst_addr.in = routes[i].dst_addr;
                                        route->dst_prefixlen = routes[i].dst_prefixlen;

                                        route_drop(route, link, &route_drop_handler);
                                }
                        }
                }
        }

        r = address_new_dynamic(&address);
        if (r >= 0) {
                r = sd_dhcp_lease_get_router(link->dhcp_lease, &gateway);
                if (r >= 0) {
                        _cleanup_route_free_ Route *route_gw = NULL;
                        _cleanup_route_free_ Route *route = NULL;

                        r = route_new_dynamic(&route_gw);
                        if (r >= 0) {
                                route_gw->family = AF_INET;
                                route_gw->dst_addr.in = gateway;
                                route_gw->dst_prefixlen = 32;
                                route_gw->scope = RT_SCOPE_LINK;

                                route_drop(route_gw, link, &route_drop_handler);
                        }

                        r = route_new_dynamic(&route);
                        if (r >= 0) {
                                route->family = AF_INET;
                                route->in_addr.in = gateway;

                                route_drop(route, link, &route_drop_handler);
                        }
                }

                sd_dhcp_lease_get_address(link->dhcp_lease, &addr);
                sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
                prefixlen = net_netmask_to_prefixlen(&netmask);

                address->family = AF_INET;
                address->in_addr.in = addr;
                address->prefixlen = prefixlen;

                address_drop(address, link, &address_drop_handler);
        }

        if (link->network->dhcp_mtu) {
                uint16_t mtu;

                r = sd_dhcp_lease_get_mtu(link->dhcp_lease, &mtu);
                if (r >= 0 && link->original_mtu != mtu) {
                        r = link_set_mtu(link, link->original_mtu);
                        if (r < 0) {
                                log_warning_link(link, "DHCP error: could not reset MTU");
                                link_enter_failed(link);
                                return r;
                        }
                }
        }

        if (link->network->dhcp_hostname) {
                const char *hostname = NULL;

                r = sd_dhcp_lease_get_hostname(link->dhcp_lease, &hostname);
                if (r >= 0 && hostname) {
                        r = link_set_hostname(link, "");
                        if (r < 0)
                                log_error_link(link, "Failed to reset transient hostname");
                }
        }

        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);

        return 0;
}

static int dhcp_lease_renew(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        int r;

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0) {
                log_warning_link(link, "DHCP error: no lease %s",
                                 strerror(-r));
                return r;
        }

        sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp_lease = lease;

        link_enter_set_addresses(link);

        return 0;
}

static int dhcp_lease_acquired(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        struct in_addr gateway;
        unsigned prefixlen;
        int r;

        assert(client);
        assert(link);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0) {
                log_warning_link(link, "DHCP error: no lease: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0) {
                log_warning_link(link, "DHCP error: no address: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0) {
                log_warning_link(link, "DHCP error: no netmask: %s",
                                 strerror(-r));
                return r;
        }

        prefixlen = net_netmask_to_prefixlen(&netmask);

        r = sd_dhcp_lease_get_router(lease, &gateway);
        if (r < 0 && r != -ENOENT) {
                log_warning_link(link, "DHCP error: could not get gateway: %s",
                                 strerror(-r));
                return r;
        }

        if (r >= 0)
                log_struct_link(LOG_INFO, link,
                                "MESSAGE=%-*s: DHCPv4 address %u.%u.%u.%u/%u via %u.%u.%u.%u",
                                 IFNAMSIZ,
                                 link->ifname,
                                 ADDRESS_FMT_VAL(address),
                                 prefixlen,
                                 ADDRESS_FMT_VAL(gateway),
                                 "ADDRESS=%u.%u.%u.%u",
                                 ADDRESS_FMT_VAL(address),
                                 "PREFIXLEN=%u",
                                 prefixlen,
                                 "GATEWAY=%u.%u.%u.%u",
                                 ADDRESS_FMT_VAL(gateway),
                                 NULL);
        else
                log_struct_link(LOG_INFO, link,
                                "MESSAGE=%-*s: DHCPv4 address %u.%u.%u.%u/%u",
                                 IFNAMSIZ,
                                 link->ifname,
                                 ADDRESS_FMT_VAL(address),
                                 prefixlen,
                                 "ADDRESS=%u.%u.%u.%u",
                                 ADDRESS_FMT_VAL(address),
                                 "PREFIXLEN=%u",
                                 prefixlen,
                                 NULL);

        link->dhcp_lease = lease;

        if (link->network->dhcp_mtu) {
                uint16_t mtu;

                r = sd_dhcp_lease_get_mtu(lease, &mtu);
                if (r >= 0) {
                        r = link_set_mtu(link, mtu);
                        if (r < 0)
                                log_error_link(link, "Failed to set MTU "
                                               "to %" PRIu16, mtu);
                }
        }

        if (link->network->dhcp_hostname) {
                const char *hostname;

                r = sd_dhcp_lease_get_hostname(lease, &hostname);
                if (r >= 0) {
                        r = link_set_hostname(link, hostname);
                        if (r < 0)
                                log_error_link(link, "Failed to set transient hostname "
                                          "to '%s'", hostname);
                }
        }

        link_enter_set_addresses(link);

        return 0;
}

static void dhcp_handler(sd_dhcp_client *client, int event, void *userdata) {
        Link *link = userdata;
        int r = 0;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
                case DHCP_EVENT_NO_LEASE:
                        log_debug_link(link, "IP address in use.");
                        break;
                case DHCP_EVENT_EXPIRED:
                case DHCP_EVENT_STOP:
                case DHCP_EVENT_IP_CHANGE:
                        if (link->network->dhcp_critical) {
                                log_error_link(link, "DHCPv4 connection considered system critical, "
                                               "ignoring request to reconfigure it.");
                                return;
                        }

                        if (link->dhcp_lease) {
                                r = dhcp_lease_lost(link);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return;
                                }
                        }

                        if (event == DHCP_EVENT_IP_CHANGE) {
                                r = dhcp_lease_acquired(client, link);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return;
                                }
                        }

                        if (event == DHCP_EVENT_EXPIRED && link->network->ipv4ll) {
                                if (!sd_ipv4ll_is_running(link->ipv4ll))
                                        r = sd_ipv4ll_start(link->ipv4ll);
                                else if (ipv4ll_is_bound(link->ipv4ll))
                                        r = ipv4ll_address_update(link, false);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return;
                                }
                        }

                        break;
                case DHCP_EVENT_RENEW:
                        r = dhcp_lease_renew(client, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        break;
                case DHCP_EVENT_IP_ACQUIRE:
                        r = dhcp_lease_acquired(client, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        if (link->ipv4ll) {
                                if (ipv4ll_is_bound(link->ipv4ll))
                                        r = ipv4ll_address_update(link, true);
                                else
                                        r = sd_ipv4ll_stop(link->ipv4ll);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return;
                                }
                        }
                        break;
                default:
                        if (event < 0)
                                log_warning_link(link, "DHCP error: client failed: %s", strerror(-event));
                        else
                                log_warning_link(link, "DHCP unknown event: %d", event);
                        break;
        }

        return;
}

static int ipv4ll_address_update(Link *link, bool deprecate) {
        int r;
        struct in_addr addr;

        assert(link);

        r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
        if (r >= 0) {
                _cleanup_address_free_ Address *address = NULL;

                log_debug_link(link, "IPv4 link-local %s %u.%u.%u.%u",
                               deprecate ? "deprecate" : "approve",
                               ADDRESS_FMT_VAL(addr));

                r = address_new_dynamic(&address);
                if (r < 0) {
                        log_error_link(link, "Could not allocate address: %s", strerror(-r));
                        return r;
                }

                address->family = AF_INET;
                address->in_addr.in = addr;
                address->prefixlen = 16;
                address->scope = RT_SCOPE_LINK;
                address->cinfo.ifa_prefered = deprecate ? 0 : CACHE_INFO_INFINITY_LIFE_TIME;
                address->broadcast.s_addr = address->in_addr.in.s_addr | htonl(0xfffffffflu >> address->prefixlen);

                address_update(address, link, &address_update_handler);
        }

        return 0;

}

static int ipv4ll_address_lost(Link *link) {
        int r;
        struct in_addr addr;

        assert(link);

        r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
        if (r >= 0) {
                _cleanup_address_free_ Address *address = NULL;
                _cleanup_route_free_ Route *route = NULL;

                log_debug_link(link, "IPv4 link-local release %u.%u.%u.%u",
                                ADDRESS_FMT_VAL(addr));

                r = address_new_dynamic(&address);
                if (r < 0) {
                        log_error_link(link, "Could not allocate address: %s", strerror(-r));
                        return r;
                }

                address->family = AF_INET;
                address->in_addr.in = addr;
                address->prefixlen = 16;
                address->scope = RT_SCOPE_LINK;

                address_drop(address, link, &address_drop_handler);

                r = route_new_dynamic(&route);
                if (r < 0) {
                        log_error_link(link, "Could not allocate route: %s",
                                       strerror(-r));
                        return r;
                }

                route->family = AF_INET;
                route->scope = RT_SCOPE_LINK;
                route->metrics = 99;

                route_drop(route, link, &route_drop_handler);
        }

        return 0;
}

static bool ipv4ll_is_bound(sd_ipv4ll *ll) {
        int r;
        struct in_addr addr;

        assert(ll);

        r = sd_ipv4ll_get_address(ll, &addr);
        if (r < 0)
                return false;
        return true;
}

static int ipv4ll_address_claimed(sd_ipv4ll *ll, Link *link) {
        struct in_addr address;
        int r;

        assert(ll);
        assert(link);

        r = sd_ipv4ll_get_address(ll, &address);
        if (r < 0)
                return r;

        log_struct_link(LOG_INFO, link,
                        "MESSAGE=%-*s: IPv4 link-local address %u.%u.%u.%u",
                        IFNAMSIZ,
                        link->ifname,
                        ADDRESS_FMT_VAL(address),
                        NULL);

       link_enter_set_addresses(link);

       return 0;
}

static void ipv4ll_handler(sd_ipv4ll *ll, int event, void *userdata){
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
                case IPV4LL_EVENT_STOP:
                case IPV4LL_EVENT_CONFLICT:
                        r = ipv4ll_address_lost(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        break;
                case IPV4LL_EVENT_BIND:
                        r = ipv4ll_address_claimed(ll, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        break;
                default:
                        if (event < 0)
                                log_warning_link(link, "IPv4 link-local error: %s", strerror(-event));
                        else
                                log_warning_link(link, "IPv4 link-local unknown event: %d", event);
                        break;
        }
}

static void dhcp6_handler(sd_dhcp6_client *client, int event, void *userdata) {
        Link *link = userdata;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
        case DHCP6_EVENT_STOP:
        case DHCP6_EVENT_RESEND_EXPIRE:
        case DHCP6_EVENT_RETRANS_MAX:
        case DHCP6_EVENT_IP_ACQUIRE:
                log_debug_link(link, "DHCPv6 event %d", event);

                break;

        default:
                if (event < 0)
                        log_warning_link(link, "DHCPv6 error: %s",
                                         strerror(-event));
                else
                        log_warning_link(link, "DHCPv6 unknown event: %d",
                                         event);
                return;
        }
}

static void icmp6_router_handler(sd_icmp6_nd *nd, int event, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
        case ICMP6_EVENT_ROUTER_ADVERTISMENT_NONE:
        case ICMP6_EVENT_ROUTER_ADVERTISMENT_OTHER:
                return;

        case ICMP6_EVENT_ROUTER_ADVERTISMENT_TIMEOUT:
        case ICMP6_EVENT_ROUTER_ADVERTISMENT_MANAGED:
                break;

        default:
                if (event < 0)
                        log_warning_link(link, "ICMPv6 error: %s",
                                         strerror(-event));
                else
                        log_warning_link(link, "ICMPv6 unknown event: %d",
                                         event);

                return;
        }

        if (link->dhcp6_client)
                return;

        r = sd_dhcp6_client_new(&link->dhcp6_client);
        if (r < 0)
                return;

        r = sd_dhcp6_client_attach_event(link->dhcp6_client, NULL, 0);
        if (r < 0) {
                link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
                return;
        }

        r = sd_dhcp6_client_set_mac(link->dhcp6_client, &link->mac);
        if (r < 0) {
                link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
                return;
        }

        r = sd_dhcp6_client_set_index(link->dhcp6_client, link->ifindex);
        if (r < 0) {
                link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
                return;
        }

        r = sd_dhcp6_client_set_callback(link->dhcp6_client, dhcp6_handler,
                                         link);
        if (r < 0) {
                link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
                return;
        }

        r = sd_dhcp6_client_start(link->dhcp6_client);
        if (r < 0)
                link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
}

static int link_acquire_conf(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->event);

        if (link->network->ipv4ll) {
                assert(link->ipv4ll);

                log_debug_link(link, "acquiring IPv4 link-local address");

                r = sd_ipv4ll_start(link->ipv4ll);
                if (r < 0) {
                        log_warning_link(link, "could not acquire IPv4 "
                                         "link-local address");
                        return r;
                }
        }

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V4)) {
                assert(link->dhcp_client);

                log_debug_link(link, "acquiring DHCPv4 lease");

                r = sd_dhcp_client_start(link->dhcp_client);
                if (r < 0) {
                        log_warning_link(link, "could not acquire DHCPv4 "
                                         "lease");
                        return r;
                }
        }

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V6)) {
                assert(link->icmp6_router_discovery);

                log_debug_link(link, "discovering IPv6 routers");

                r = sd_icmp6_router_solicitation_start(link->icmp6_router_discovery);
                if (r < 0) {
                        log_warning_link(link, "could not start IPv6 router discovery");
                        return r;
                }
        }

        return 0;
}

bool link_has_carrier(unsigned flags, uint8_t operstate) {
        /* see Documentation/networking/operstates.txt in the kernel sources */

        if (operstate == IF_OPER_UP)
                return true;

        if (operstate == IF_OPER_UNKNOWN)
                /* operstate may not be implemented, so fall back to flags */
                if ((flags & IFF_LOWER_UP) && !(flags & IFF_DORMANT))
                        return true;

        return false;
}

#define FLAG_STRING(string, flag, old, new) \
        (((old ^ new) & flag) \
                ? ((old & flag) ? (" -" string) : (" +" string)) \
                : "")

static int link_update_flags(Link *link, sd_rtnl_message *m) {
        unsigned flags, unknown_flags_added, unknown_flags_removed, unknown_flags;
        uint8_t operstate;
        bool carrier_gained = false, carrier_lost = false;
        int r;

        assert(link);

        r = sd_rtnl_message_link_get_flags(m, &flags);
        if (r < 0) {
                log_warning_link(link, "Could not get link flags");
                return r;
        }

        r = sd_rtnl_message_read_u8(m, IFLA_OPERSTATE, &operstate);
        if (r < 0)
                /* if we got a message without operstate, take it to mean
                   the state was unchanged */
                operstate = link->kernel_operstate;

        if ((link->flags == flags) && (link->kernel_operstate == operstate))
                return 0;

        if (link->flags != flags) {
                log_debug_link(link, "flags change:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
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

                /* link flags are currently at most 18 bits, let's align to printing 20 */
                if (unknown_flags_added)
                        log_debug_link(link, "unknown link flags gained: %#.5x (ignoring)",
                                       unknown_flags_added);

                if (unknown_flags_removed)
                        log_debug_link(link, "unknown link flags lost: %#.5x (ignoring)",
                                       unknown_flags_removed);
        }

        carrier_gained = !link_has_carrier(link->flags, link->kernel_operstate) &&
                       link_has_carrier(flags, operstate);
        carrier_lost = link_has_carrier(link->flags, link->kernel_operstate) &&
                         !link_has_carrier(flags, operstate);

        link->flags = flags;
        link->kernel_operstate = operstate;

        link_save(link);

        if (link->state == LINK_STATE_FAILED ||
            link->state == LINK_STATE_UNMANAGED)
                return 0;

        if (carrier_gained) {
                log_info_link(link, "gained carrier");

                if (link->network) {
                        r = link_acquire_conf(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                }
        } else if (carrier_lost) {
                log_info_link(link, "lost carrier");

                r = link_stop_clients(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        return 0;
}

static int link_up_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                /* we warn but don't fail the link, as it may
                   be brought up later */
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%-*s: could not bring up interface: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);
        }

        return 1;
}

static int link_up(Link *link) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_debug_link(link, "bringing link up");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req,
                                     RTM_SETLINK, link->ifindex);
        if (r < 0) {
                log_error_link(link, "Could not allocate RTM_SETLINK message");
                return r;
        }

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0) {
                log_error_link(link, "Could not set link flags: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, link_up_handler, link, 0, NULL);
        if (r < 0) {
                log_error_link(link,
                               "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        return 0;
}

static int link_enslaved(Link *link) {
        int r;

        assert(link);
        assert(link->state == LINK_STATE_ENSLAVING);
        assert(link->network);

        log_debug_link(link, "enslaved");

        if (!(link->flags & IFF_UP)) {
                r = link_up(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        return link_enter_set_addresses(link);
}

static int enslave_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(IN_SET(link->state, LINK_STATE_ENSLAVING, LINK_STATE_FAILED,
                      LINK_STATE_LINGER));
        assert(link->network);

        link->enslaving --;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_struct_link(LOG_ERR, link,
                                "MESSAGE=%-*s: could not enslave: %s",
                                IFNAMSIZ,
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);
                link_enter_failed(link);
                return 1;
        }

        if (link->enslaving <= 0)
                link_enslaved(link);

        return 1;
}

static int link_enter_enslave(Link *link) {
        NetDev *vlan, *macvlan, *vxlan;
        Iterator i;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZING);

        link->state = LINK_STATE_ENSLAVING;

        link_save(link);

        if (!link->network->bridge &&
            !link->network->bond &&
            !link->network->tunnel &&
            hashmap_isempty(link->network->vlans) &&
            hashmap_isempty(link->network->macvlans) &&
            hashmap_isempty(link->network->vxlans))
                return link_enslaved(link);

        if (link->network->bond) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%-*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, link->network->bond->ifname,
                                NETDEV(link->network->bond),
                                NULL);

                r = netdev_enslave(link->network->bond, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%-*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, link->network->bond->ifname, strerror(-r),
                                        NETDEV(link->network->bond),
                                        NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        if (link->network->bridge) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%-*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, link->network->bridge->ifname,
                                NETDEV(link->network->bridge),
                                NULL);

                r = netdev_enslave(link->network->bridge, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%-*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, link->network->bridge->ifname, strerror(-r),
                                        NETDEV(link->network->bridge),
                                        NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        if (link->network->tunnel) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%-*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, link->network->tunnel->ifname,
                                NETDEV(link->network->tunnel),
                                NULL);

                r = netdev_enslave(link->network->tunnel, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%-*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, link->network->tunnel->ifname, strerror(-r),
                                        NETDEV(link->network->tunnel),
                                        NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        HASHMAP_FOREACH(vlan, link->network->vlans, i) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%-*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, vlan->ifname, NETDEV(vlan), NULL);

                r = netdev_enslave(vlan, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%-*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, vlan->ifname, strerror(-r),
                                        NETDEV(vlan), NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        HASHMAP_FOREACH(macvlan, link->network->macvlans, i) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%-*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, macvlan->ifname, NETDEV(macvlan), NULL);

                r = netdev_enslave(macvlan, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%-*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, macvlan->ifname, strerror(-r),
                                        NETDEV(macvlan), NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        HASHMAP_FOREACH(vxlan, link->network->vxlans, i) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%*s: enslaving by '%s'",
                                IFNAMSIZ,
                                link->ifname, vxlan->ifname, NETDEV(vxlan), NULL);

                r = netdev_enslave(vxlan, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%*s: could not enslave by '%s': %s",
                                        IFNAMSIZ,
                                        link->ifname, vxlan->ifname, strerror(-r),
                                        NETDEV(vxlan), NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        return 0;
}

static int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->state == LINK_STATE_INITIALIZING);

        if (link->network->ipv4ll) {
                uint8_t seed[8];

                r = sd_ipv4ll_new(&link->ipv4ll);
                if (r < 0)
                        return r;

                if (link->udev_device) {
                        r = net_get_unique_predictable_data(link->udev_device, seed);
                        if (r >= 0) {
                                r = sd_ipv4ll_set_address_seed(link->ipv4ll, seed);
                                if (r < 0)
                                        return r;
                        }
                }

                r = sd_ipv4ll_attach_event(link->ipv4ll, NULL, 0);
                if (r < 0)
                        return r;

                r = sd_ipv4ll_set_mac(link->ipv4ll, &link->mac);
                if (r < 0)
                        return r;

                r = sd_ipv4ll_set_index(link->ipv4ll, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_ipv4ll_set_callback(link->ipv4ll, ipv4ll_handler, link);
                if (r < 0)
                        return r;
        }

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V4)) {
                r = sd_dhcp_client_new(&link->dhcp_client);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_attach_event(link->dhcp_client, NULL, 0);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_set_mac(link->dhcp_client, &link->mac);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_set_index(link->dhcp_client, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_set_callback(link->dhcp_client, dhcp_handler, link);
                if (r < 0)
                        return r;

                if (link->network->dhcp_mtu) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, 26);
                        if (r < 0)
                                return r;
                }

                if (link->network->dhcp_routes) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, DHCP_OPTION_STATIC_ROUTE);
                        if (r < 0)
                                return r;
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, DHCP_OPTION_CLASSLESS_STATIC_ROUTE);
                        if (r < 0)
                                return r;
                }

                if (link->network->dhcp_sendhost) {
                        _cleanup_free_ char *hostname = gethostname_malloc();
                        if (!hostname)
                                return -ENOMEM;

                        if (!is_localhost(hostname)) {
                                r = sd_dhcp_client_set_hostname(link->dhcp_client, hostname);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (link->network->dhcp_server) {
                r = sd_dhcp_server_new(&link->dhcp_server, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_dhcp_server_attach_event(link->dhcp_server, NULL, 0);
                if (r < 0)
                        return r;
        }

        if (IN_SET(link->network->dhcp, DHCP_SUPPORT_BOTH, DHCP_SUPPORT_V6)) {
                r = sd_icmp6_nd_new(&link->icmp6_router_discovery);
                if (r < 0)
                        return r;

                r = sd_icmp6_nd_attach_event(link->icmp6_router_discovery,
                                             NULL, 0);
                if (r < 0)
                        return r;

                r = sd_icmp6_nd_set_mac(link->icmp6_router_discovery,
                                        &link->mac);
                if (r < 0)
                        return r;

                r = sd_icmp6_nd_set_index(link->icmp6_router_discovery,
                                          link->ifindex);
                if (r < 0)
                        return r;

                r = sd_icmp6_nd_set_callback(link->icmp6_router_discovery,
                                             icmp6_router_handler, link);
                if (r < 0)
                        return r;
        }

        if (link_has_carrier(link->flags, link->kernel_operstate)) {
                r = link_acquire_conf(link);
                if (r < 0)
                        return r;
        }

        return link_enter_enslave(link);
}

static int link_initialized_and_synced(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        Network *network;
        int r;

        assert(link);
        assert(link->ifname);
        assert(link->manager);

        if (link->state != LINK_STATE_INITIALIZING)
                return 1;

        log_debug_link(link, "link state is up-to-date");

        r = network_get(link->manager, link->udev_device, link->ifname, &link->mac, &network);
        if (r == -ENOENT) {
                link_enter_unmanaged(link);
                return 1;
        } else if (r < 0)
                return r;

        r = network_apply(link->manager, network, link);
        if (r < 0)
                return r;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 1;
}

int link_initialized(Link *link, struct udev_device *device) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(device);

        if (link->state != LINK_STATE_INITIALIZING)
                return 0;

        log_debug_link(link, "udev initialized link");

        link->udev_device = udev_device_ref(device);

        /* udev has initialized the link, but we don't know if we have yet processed
           the NEWLINK messages with the latest state. Do a GETLINK, when it returns
           we know that the pending NEWLINKs have already been processed and that we
           are up-to-date */

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_GETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sd_rtnl_call_async(link->manager->rtnl, req, link_initialized_and_synced, link, 0, NULL);
        if (r < 0)
                return r;

        link_ref(link);

        return 0;
}

int link_rtnl_process_address(sd_rtnl *rtnl, sd_rtnl_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        uint16_t type;
        _cleanup_address_free_ Address *address = NULL;
        Address *ad;
        char buf[INET6_ADDRSTRLEN];
        bool address_dropped = false;
        int r, ifindex;

        assert(rtnl);
        assert(message);
        assert(m);

        r = sd_rtnl_message_get_type(message, &type);
        if (r < 0) {
                log_warning("rtnl: could not get message type");
                return 0;
        }

        r = sd_rtnl_message_addr_get_ifindex(message, &ifindex);
        if (r < 0 || ifindex <= 0) {
                log_warning("rtnl: received address message without valid ifindex, ignoring");
                return 0;
        } else {
                r = link_get(m, ifindex, &link);
                if (r < 0 || !link) {
                        log_warning("rtnl: received address for a nonexistent link, ignoring");
                        return 0;
                }
        }

        r = address_new_dynamic(&address);
        if (r < 0)
                return 0;

        r = sd_rtnl_message_addr_get_family(message, &address->family);
        if (r < 0 || !IN_SET(address->family, AF_INET, AF_INET6)) {
                log_warning_link(link, "rtnl: received address with invalid family, ignoring");
                return 0;
        }

        r = sd_rtnl_message_addr_get_prefixlen(message, &address->prefixlen);
        if (r < 0) {
                log_warning_link(link, "rtnl: received address with invalid prefixlen, ignoring");
                return 0;
        }

        r = sd_rtnl_message_addr_get_scope(message, &address->scope);
        if (r < 0) {
                log_warning_link(link, "rtnl: received address with invalid scope, ignoring");
                return 0;
        }

        switch (address->family) {
        case AF_INET:
                r = sd_rtnl_message_read_in_addr(message, IFA_LOCAL, &address->in_addr.in);
                if (r < 0) {
                        log_warning_link(link, "rtnl: received address without valid address, ignoring");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_rtnl_message_read_in6_addr(message, IFA_ADDRESS, &address->in_addr.in6);
                if (r < 0) {
                        log_warning_link(link, "rtnl: received address without valid address, ignoring");
                        return 0;
                }

                break;

        default:
                assert_not_reached("invalid address family");
        }

        if (!inet_ntop(address->family, &address->in_addr, buf, INET6_ADDRSTRLEN)) {
                log_warning_link(link, "could not print address");
                return 0;
        }

        LIST_FOREACH(addresses, ad, link->addresses) {
                if (address_equal(ad, address)) {
                        LIST_REMOVE(addresses, link->addresses, ad);

                        address_free(ad);

                        address_dropped = true;

                        break;
                }
        }

        switch (type) {
        case RTM_NEWADDR:
                if (!address_dropped)
                        log_debug_link(link, "added address: %s/%u", buf,
                                      address->prefixlen);

                LIST_PREPEND(addresses, link->addresses, address);
                address = NULL;

                link_save(link);

                break;
        case RTM_DELADDR:
                if (address_dropped) {
                        log_debug_link(link, "removed address: %s/%u", buf,
                                      address->prefixlen);

                        link_save(link);
                }

                break;
        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static int link_get_address_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->manager);

        for (; m; m = sd_rtnl_message_next(m)) {
                r = sd_rtnl_message_get_errno(m);
                if (r < 0) {
                        log_debug_link(link, "getting address failed: %s", strerror(-r));
                        continue;
                }

                r = link_rtnl_process_address(rtnl, m, link->manager);
                if (r < 0)
                        log_warning_link(link, "could not process address: %s", strerror(-r));
        }

        return 1;
}

int link_add(Manager *m, sd_rtnl_message *message, Link **ret) {
        Link *link;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
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

        log_debug_link(link, "link %"PRIu64" added", link->ifindex);

        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, link->ifindex, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_call_async(m->rtnl, req, link_get_address_handler, link, 0, NULL);
        if (r < 0)
                return r;

        link_ref(link);

        if (detect_container(NULL) <= 0) {
                /* not in a container, udev will be around */
                sprintf(ifindex_str, "n%"PRIu64, link->ifindex);
                device = udev_device_new_from_device_id(m->udev, ifindex_str);
                if (!device) {
                        log_warning_link(link, "could not find udev device");
                        return -errno;
                }

                if (udev_device_get_is_initialized(device) <= 0) {
                        /* not yet ready */
                        log_debug_link(link, "udev initializing link...");
                        return 0;
                }

                r = link_initialized(link, device);
                if (r < 0)
                        return r;
        } else {
                /* we are calling a callback directly, so must take a ref */
                link_ref(link);

                r = link_initialized_and_synced(m->rtnl, NULL, link);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_update(Link *link, sd_rtnl_message *m) {
        struct ether_addr mac;
        char *ifname;
        int r;

        assert(link);
        assert(link->ifname);
        assert(m);

        if (link->state == LINK_STATE_LINGER) {
                link_ref(link);
                log_info_link(link, "link readded");
                link->state = LINK_STATE_ENSLAVING;
        }

        r = sd_rtnl_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r >= 0 && !streq(ifname, link->ifname)) {
                log_info_link(link, "renamed to %s", ifname);

                free(link->ifname);
                link->ifname = strdup(ifname);
                if (!link->ifname)
                        return -ENOMEM;
        }

        if (!link->original_mtu) {
                r = sd_rtnl_message_read_u16(m, IFLA_MTU, &link->original_mtu);
                if (r >= 0)
                        log_debug_link(link, "saved original MTU: %"
                                       PRIu16, link->original_mtu);
        }

        /* The kernel may broadcast NEWLINK messages without the MAC address
           set, simply ignore them. */
        r = sd_rtnl_message_read_ether_addr(m, IFLA_ADDRESS, &mac);
        if (r >= 0) {
                if (memcmp(link->mac.ether_addr_octet, mac.ether_addr_octet, ETH_ALEN)) {

                        memcpy(link->mac.ether_addr_octet, mac.ether_addr_octet, ETH_ALEN);

                        log_debug_link(link, "MAC address: "
                                       "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                       mac.ether_addr_octet[0],
                                       mac.ether_addr_octet[1],
                                       mac.ether_addr_octet[2],
                                       mac.ether_addr_octet[3],
                                       mac.ether_addr_octet[4],
                                       mac.ether_addr_octet[5]);

                        if (link->ipv4ll) {
                                r = sd_ipv4ll_set_mac(link->ipv4ll, &link->mac);
                                if (r < 0) {
                                        log_warning_link(link, "Could not update MAC "
                                                         "address in IPv4LL client: %s",
                                                         strerror(-r));
                                        return r;
                                }
                        }

                        if (link->dhcp_client) {
                                r = sd_dhcp_client_set_mac(link->dhcp_client, &link->mac);
                                if (r < 0) {
                                        log_warning_link(link, "Could not update MAC "
                                                         "address in DHCP client: %s",
                                                         strerror(-r));
                                        return r;
                                }
                        }

                        if (link->dhcp6_client) {
                                r = sd_dhcp6_client_set_mac(link->dhcp6_client,
                                                            &link->mac);
                                if (r < 0) {
                                        log_warning_link(link, "Could not update MAC address in DHCPv6 client: %s",
                                                         strerror(-r));
                                        return r;
                                }
                        }
                }
        }

        return link_update_flags(link, m);
}

static void serialize_addresses(FILE *f, const char *key, Address *address) {
        Address *ad;

        assert(f);
        assert(key);

        if (!address)
                return;

        fprintf(f, "%s=", key);

        LIST_FOREACH(addresses, ad, address) {
                char buf[INET6_ADDRSTRLEN];

                if (inet_ntop(ad->family, &ad->in_addr, buf, INET6_ADDRSTRLEN))
                        fprintf(f, "%s%s", buf, (ad->addresses_next) ? " ": "");
        }

        fputs("\n", f);
}

static void link_update_operstate(Link *link) {

        assert(link);

        if (link->kernel_operstate == IF_OPER_DORMANT)
                link->operstate = LINK_OPERSTATE_DORMANT;
        else if (link_has_carrier(link->flags, link->kernel_operstate)) {
                Address *address;
                uint8_t scope = RT_SCOPE_NOWHERE;

                /* if we have carrier, check what addresses we have */
                LIST_FOREACH(addresses, address, link->addresses) {
                        if (address->scope < scope)
                                scope = address->scope;
                }

                if (scope < RT_SCOPE_SITE)
                        /* universally accessible addresses found */
                        link->operstate = LINK_OPERSTATE_ROUTABLE;
                else if (scope < RT_SCOPE_HOST)
                        /* only link or site local addresses found */
                        link->operstate = LINK_OPERSTATE_DEGRADED;
                else
                        /* no useful addresses found */
                        link->operstate = LINK_OPERSTATE_CARRIER;
        } else
                link->operstate = LINK_OPERSTATE_UNKNOWN;
}

int link_save(Link *link) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *admin_state, *oper_state;
        int r;

        assert(link);
        assert(link->state_file);
        assert(link->lease_file);
        assert(link->manager);

        link_update_operstate(link);

        r = manager_save(link->manager);
        if (r < 0)
                return r;

        if (link->state == LINK_STATE_LINGER) {
                unlink(link->state_file);
                return 0;
        }

        admin_state = link_state_to_string(link->state);
        assert(admin_state);

        oper_state = link_operstate_to_string(link->operstate);
        assert(oper_state);

        r = fopen_temporary(link->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADMIN_STATE=%s\n"
                "OPER_STATE=%s\n"
                "FLAGS=%u\n",
                admin_state, oper_state, link->flags);

        if (link->network) {
                serialize_addresses(f, "DNS", link->network->dns);
                serialize_addresses(f, "NTP", link->network->ntp);
        }

        if (link->dhcp_lease) {
                assert(link->network);

                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        goto finish;

                fprintf(f,
                        "DHCP_LEASE=%s\n"
                        "DHCP_USE_DNS=%s\n"
                        "DHCP_USE_NTP=%s\n",
                        link->lease_file,
                        yes_no(link->network->dhcp_dns),
                        yes_no(link->network->dhcp_ntp));
        } else
                unlink(link->lease_file);

        fflush(f);

        if (ferror(f) || rename(temp_path, link->state_file) < 0) {
                r = -errno;
                unlink(link->state_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error_link(link, "Failed to save link data to %s: %s", link->state_file, strerror(-r));

        return r;
}

static const char* const link_state_table[_LINK_STATE_MAX] = {
        [LINK_STATE_INITIALIZING] = "initializing",
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
        [LINK_OPERSTATE_UNKNOWN] = "unknown",
        [LINK_OPERSTATE_DORMANT] = "dormant",
        [LINK_OPERSTATE_CARRIER] = "carrier",
        [LINK_OPERSTATE_DEGRADED] = "degraded",
        [LINK_OPERSTATE_ROUTABLE] = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_operstate, LinkOperationalState);

static const char* const dhcp_support_table[_DHCP_SUPPORT_MAX] = {
        [DHCP_SUPPORT_NONE] = "none",
        [DHCP_SUPPORT_BOTH] = "both",
        [DHCP_SUPPORT_V4] = "v4",
        [DHCP_SUPPORT_V6] = "v6",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp_support, DHCPSupport);

int config_parse_dhcp(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        DHCPSupport *dhcp = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                *dhcp = DHCP_SUPPORT_BOTH;
        else if (k == 0)
                *dhcp = DHCP_SUPPORT_NONE;
        else {
                DHCPSupport s;

                s = dhcp_support_from_string(rvalue);
                if (s < 0){
                        log_syntax(unit, LOG_ERR, filename, line, -s, "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }

                *dhcp = s;
        }

        return 0;
}

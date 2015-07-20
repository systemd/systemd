/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013-2014 Tom Gundersen <teg@jklm.no>

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

#include "hostname-util.h"
#include "networkd-link.h"
#include "network-internal.h"
#include "dhcp-lease-internal.h"

static int dhcp4_route_handler(sd_netlink *rtnl, sd_netlink_message *m,
                               void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(link->dhcp4_messages);

        link->dhcp4_messages --;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error(link, "could not set DHCPv4 route: %s",
                               strerror(-r));
                link_enter_failed(link);
        }

        if (!link->dhcp4_messages) {
                link->dhcp4_configured = true;
                link_client_handler(link);
        }

        return 1;
}

static int link_set_dhcp_routes(Link *link) {
        struct in_addr gateway;
        struct sd_dhcp_route *static_routes;
        int r, n, i;

        assert(link);
        assert(link->dhcp_lease);

        r = sd_dhcp_lease_get_router(link->dhcp_lease, &gateway);
        if (r < 0 && r != -ENOENT) {
                log_link_warning(link,
                                 "DHCP error: could not get gateway: %s",
                                 strerror(-r));
                return r;
        }
        if (r >= 0) {
                struct in_addr address;
                _cleanup_route_free_ Route *route = NULL;
                _cleanup_route_free_ Route *route_gw = NULL;

                r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
                if (r < 0) {
                        log_link_warning(link,
                                         "DHCP error: could not get address: %s",
                                         strerror(-r));
                        return r;
                }

                r = route_new_dynamic(&route, RTPROT_DHCP);
                if (r < 0) {
                        log_link_error(link,
                                       "Could not allocate route: %s",
                                       strerror(-r));
                        return r;
                }

                r = route_new_dynamic(&route_gw, RTPROT_DHCP);
                if (r < 0) {
                log_link_error(link,
                               "Could not allocate route: %s",
                               strerror(-r));
                               return r;
                }

                /* The dhcp netmask may mask out the gateway. Add an explicit
                 * route for the gw host so that we can route no matter the
                 * netmask or existing kernel route tables. */
                route_gw->family = AF_INET;
                route_gw->dst_addr.in = gateway;
                route_gw->dst_prefixlen = 32;
                route_gw->prefsrc_addr.in = address;
                route_gw->scope = RT_SCOPE_LINK;
                route_gw->metrics = link->network->dhcp_route_metric;

                r = route_configure(route_gw, link, &dhcp4_route_handler);
                if (r < 0) {
                        log_link_warning(link,
                                         "could not set host route: %s",
                                         strerror(-r));
                        return r;
                }

                link->dhcp4_messages ++;

                route->family = AF_INET;
                route->in_addr.in = gateway;
                route->prefsrc_addr.in = address;
                route->metrics = link->network->dhcp_route_metric;

                r = route_configure(route, link, &dhcp4_route_handler);
                if (r < 0) {
                        log_link_warning(link,
                                         "could not set routes: %s",
                                         strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->dhcp4_messages ++;
        }

        n = sd_dhcp_lease_get_routes(link->dhcp_lease, &static_routes);
        if (n == -ENOENT)
                return 0;
        if (n < 0) {
                log_link_warning(link,
                                 "DHCP error: could not get routes: %s",
                                 strerror(-n));

                return n;
        }

        for (i = 0; i < n; i++) {
                _cleanup_route_free_ Route *route = NULL;

                r = route_new_dynamic(&route, RTPROT_DHCP);
                if (r < 0) {
                        log_link_error(link, "Could not allocate route: %s",
                                       strerror(-r));
                        return r;
                }

                route->family = AF_INET;
                route->in_addr.in = static_routes[i].gw_addr;
                route->dst_addr.in = static_routes[i].dst_addr;
                route->dst_prefixlen = static_routes[i].dst_prefixlen;
                route->metrics = link->network->dhcp_route_metric;

                r = route_configure(route, link, &dhcp4_route_handler);
                if (r < 0) {
                        log_link_warning(link,
                                         "could not set host route: %s",
                                         strerror(-r));
                        return r;
                }

                link->dhcp4_messages ++;
        }

        return 0;
}

static int dhcp_lease_lost(Link *link) {
        _cleanup_address_free_ Address *address = NULL;
        struct in_addr addr;
        struct in_addr netmask;
        struct in_addr gateway;
        unsigned prefixlen = 0;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        log_link_warning(link, "DHCP lease lost");

        if (link->network->dhcp_routes) {
                struct sd_dhcp_route *routes;
                int n, i;

                n = sd_dhcp_lease_get_routes(link->dhcp_lease, &routes);
                if (n >= 0) {
                        for (i = 0; i < n; i++) {
                                _cleanup_route_free_ Route *route = NULL;

                                r = route_new_dynamic(&route, RTPROT_UNSPEC);
                                if (r >= 0) {
                                        route->family = AF_INET;
                                        route->in_addr.in = routes[i].gw_addr;
                                        route->dst_addr.in = routes[i].dst_addr;
                                        route->dst_prefixlen = routes[i].dst_prefixlen;

                                        route_drop(route, link,
                                                   &link_route_drop_handler);
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

                        r = route_new_dynamic(&route_gw, RTPROT_UNSPEC);
                        if (r >= 0) {
                                route_gw->family = AF_INET;
                                route_gw->dst_addr.in = gateway;
                                route_gw->dst_prefixlen = 32;
                                route_gw->scope = RT_SCOPE_LINK;

                                route_drop(route_gw, link,
                                           &link_route_drop_handler);
                        }

                        r = route_new_dynamic(&route, RTPROT_UNSPEC);
                        if (r >= 0) {
                                route->family = AF_INET;
                                route->in_addr.in = gateway;

                                route_drop(route, link,
                                           &link_route_drop_handler);
                        }
                }

                r = sd_dhcp_lease_get_address(link->dhcp_lease, &addr);
                if (r >= 0) {
                        r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
                        if (r >= 0)
                                prefixlen = in_addr_netmask_to_prefixlen(&netmask);

                        address->family = AF_INET;
                        address->in_addr.in = addr;
                        address->prefixlen = prefixlen;

                       address_drop(address, link, &link_address_drop_handler);
                }
        }

        if (link->network->dhcp_mtu) {
                uint16_t mtu;

                r = sd_dhcp_lease_get_mtu(link->dhcp_lease, &mtu);
                if (r >= 0 && link->original_mtu != mtu) {
                        r = link_set_mtu(link, link->original_mtu);
                        if (r < 0) {
                                log_link_warning(link,
                                                 "DHCP error: could not reset MTU");
                                link_enter_failed(link);
                                return r;
                        }
                }
        }

        if (link->network->dhcp_hostname) {
                const char *hostname = NULL;

                if (!link->network->hostname)
                        r = sd_dhcp_lease_get_hostname(link->dhcp_lease, &hostname);
                else
                        hostname = link->network->hostname;

                if (r >= 0 || hostname) {
                        r = link_set_hostname(link, hostname);
                        if (r < 0)
                                log_link_error_errno(link, r,
                                                     "Failed to set transient hostname to '%s': %m",
                                                     hostname);

                }
        }

        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp4_configured = false;

        return 0;
}

static int dhcp4_address_handler(sd_netlink *rtnl, sd_netlink_message *m,
                                 void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error(link, "could not set DHCPv4 address: %s",
                               strerror(-r));
                link_enter_failed(link);
        } else if (r >= 0)
                link_rtnl_process_address(rtnl, m, link->manager);

        link_set_dhcp_routes(link);

        return 1;
}

static int dhcp4_update_address(Link *link,
                                struct in_addr *address,
                                struct in_addr *netmask,
                                uint32_t lifetime) {
        _cleanup_address_free_ Address *addr = NULL;
        unsigned prefixlen;
        int r;

        assert(address);
        assert(netmask);
        assert(lifetime);

        prefixlen = in_addr_netmask_to_prefixlen(netmask);

        r = address_new_dynamic(&addr);
        if (r < 0)
                return r;

        addr->family = AF_INET;
        addr->in_addr.in.s_addr = address->s_addr;
        addr->cinfo.ifa_prefered = lifetime;
        addr->cinfo.ifa_valid = lifetime;
        addr->prefixlen = prefixlen;
        addr->broadcast.s_addr = address->s_addr | ~netmask->s_addr;

        /* use update rather than configure so that we will update the
         * lifetime of an existing address if it has already been configured */
        r = address_update(addr, link, &dhcp4_address_handler);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp_lease_renew(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;
        int r;

        assert(link);
        assert(client);
        assert(link->network);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0) {
                log_link_warning(link, "DHCP error: no lease %s",
                                 strerror(-r));
                return r;
        }

        sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp4_configured = false;
        link->dhcp_lease = lease;

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0) {
                log_link_warning(link, "DHCP error: no address: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0) {
                log_link_warning(link, "DHCP error: no netmask: %s",
                                 strerror(-r));
                return r;
        }

        if (!link->network->dhcp_critical) {
                r = sd_dhcp_lease_get_lifetime(link->dhcp_lease,
                                               &lifetime);
                if (r < 0) {
                        log_link_warning(link,
                                         "DHCP error: no lifetime: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = dhcp4_update_address(link, &address, &netmask, lifetime);
        if (r < 0) {
                log_link_warning(link, "could not update IP address: %s",
                                 strerror(-r));
                link_enter_failed(link);
                return r;
        }

        return 0;
}

static int dhcp_lease_acquired(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        struct in_addr gateway;
        unsigned prefixlen;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;
        int r;

        assert(client);
        assert(link);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: no lease: %m");

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: no address: %m");

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: no netmask: %m");

        prefixlen = in_addr_netmask_to_prefixlen(&netmask);

        r = sd_dhcp_lease_get_router(lease, &gateway);
        if (r < 0 && r != -ENOENT)
                return log_link_error_errno(link, r, "DHCP error: could not get gateway: %m");

        if (r >= 0)
                log_struct(LOG_INFO,
                           LOG_LINK_INTERFACE(link),
                           LOG_LINK_MESSAGE(link, "DHCPv4 address %u.%u.%u.%u/%u via %u.%u.%u.%u",
                                            ADDRESS_FMT_VAL(address),
                                            prefixlen,
                                            ADDRESS_FMT_VAL(gateway)),
                           "ADDRESS=%u.%u.%u.%u", ADDRESS_FMT_VAL(address),
                           "PREFIXLEN=%u", prefixlen,
                           "GATEWAY=%u.%u.%u.%u", ADDRESS_FMT_VAL(gateway),
                           NULL);
        else
                log_struct(LOG_INFO,
                           LOG_LINK_INTERFACE(link),
                           LOG_LINK_MESSAGE(link, "DHCPv4 address %u.%u.%u.%u/%u",
                                            ADDRESS_FMT_VAL(address),
                                            prefixlen),
                           "ADDRESS=%u.%u.%u.%u", ADDRESS_FMT_VAL(address),
                           "PREFIXLEN=%u", prefixlen,
                           NULL);

        link->dhcp_lease = lease;

        if (link->network->dhcp_mtu) {
                uint16_t mtu;

                r = sd_dhcp_lease_get_mtu(lease, &mtu);
                if (r >= 0) {
                        r = link_set_mtu(link, mtu);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set MTU to %" PRIu16 ": %m", mtu);
                }
        }

        if (link->network->dhcp_hostname) {
                const char *hostname;

                if (!link->network->hostname)
                        r = sd_dhcp_lease_get_hostname(lease, &hostname);
                else
                        hostname = link->network->hostname;

                if (r >= 0 || hostname) {
                        r = link_set_hostname(link, hostname);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set transient hostname to '%s': %m", hostname);
                }
        }

        if (!link->network->dhcp_critical) {
                r = sd_dhcp_lease_get_lifetime(link->dhcp_lease, &lifetime);
                if (r < 0) {
                        log_link_warning_errno(link, r, "DHCP error: no lifetime: %m");
                        return r;
                }
        }

        r = dhcp4_update_address(link, &address, &netmask, lifetime);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not update IP address: %m");
                link_enter_failed(link);
                return r;
        }

        return 0;
}
static void dhcp4_handler(sd_dhcp_client *client, int event, void *userdata) {
        Link *link = userdata;
        int r = 0;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
                case DHCP_EVENT_EXPIRED:
                case DHCP_EVENT_STOP:
                case DHCP_EVENT_IP_CHANGE:
                        if (link->network->dhcp_critical) {
                                log_link_error(link,
                                               "DHCPv4 connection considered system critical, ignoring request to reconfigure it.");
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
                        break;
                default:
                        if (event < 0)
                                log_link_warning(link,
                                                 "DHCP error: client failed: %s",
                                                 strerror(-event));
                        else
                                log_link_warning(link,
                                                 "DHCP unknown event: %d",
                                                 event);
                        break;
        }

        return;
}

int dhcp4_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->dhcp & ADDRESS_FAMILY_IPV4);

        r = sd_dhcp_client_new(&link->dhcp_client);
        if (r < 0)
                return r;

        r = sd_dhcp_client_attach_event(link->dhcp_client, NULL, 0);
        if (r < 0)
                return r;

        r = sd_dhcp_client_set_mac(link->dhcp_client,
                                   (const uint8_t *) &link->mac,
                                   sizeof (link->mac), ARPHRD_ETHER);
        if (r < 0)
                return r;

        r = sd_dhcp_client_set_index(link->dhcp_client, link->ifindex);
        if (r < 0)
                return r;

        r = sd_dhcp_client_set_callback(link->dhcp_client, dhcp4_handler, link);
        if (r < 0)
                return r;

        r = sd_dhcp_client_set_request_broadcast(link->dhcp_client,
                                                 link->network->dhcp_broadcast);
        if (r < 0)
                return r;

        if (link->mtu) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return r;
        }

        if (link->network->dhcp_mtu) {
             r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                   DHCP_OPTION_INTERFACE_MTU);
             if (r < 0)
                return r;
        }

        if (link->network->dhcp_routes) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                      DHCP_OPTION_STATIC_ROUTE);
                if (r < 0)
                        return r;
                r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                      DHCP_OPTION_CLASSLESS_STATIC_ROUTE);
                        if (r < 0)
                                return r;
        }

        if (link->network->dhcp_sendhost) {
                _cleanup_free_ char *hostname = NULL;
                const char *hn = NULL;

                if (!link->network->hostname)  {
                        hostname = gethostname_malloc();
                        if (!hostname)
                                return -ENOMEM;

                        hn = hostname;
                } else
                        hn = link->network->hostname;

                if (!is_localhost(hn)) {
                        r = sd_dhcp_client_set_hostname(link->dhcp_client, hn);
                        if (r < 0)
                                return r;
                }
        }

        if (link->network->dhcp_vendor_class_identifier) {
                r = sd_dhcp_client_set_vendor_class_identifier(link->dhcp_client,
                                                               link->network->dhcp_vendor_class_identifier);
                if (r < 0)
                        return r;
        }

        switch (link->network->dhcp_client_identifier) {
        case DHCP_CLIENT_ID_DUID:
                /* Library defaults to this. */
                break;
        case DHCP_CLIENT_ID_MAC:
                r = sd_dhcp_client_set_client_id(link->dhcp_client,
                                                 ARPHRD_ETHER,
                                                 (const uint8_t *) &link->mac,
                                                 sizeof (link->mac));
                if (r < 0)
                        return r;
                break;
        default:
                assert_not_reached("Unknown client identifier type.");
        }

        return 0;
}

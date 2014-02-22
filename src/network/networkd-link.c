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

#include "networkd.h"
#include "libudev-private.h"
#include "util.h"
#include "bus-util.h"
#include "net-util.h"

int link_new(Manager *manager, struct udev_device *device, Link **ret) {
        _cleanup_link_free_ Link *link = NULL;
        const char *mac;
        struct ether_addr *mac_addr;
        const char *ifname;
        int r;

        assert(manager);
        assert(manager->links);
        assert(device);
        assert(ret);

        link = new0(Link, 1);
        if (!link)
                return -ENOMEM;

        link->manager = manager;
        link->state = _LINK_STATE_INVALID;

        link->ifindex = udev_device_get_ifindex(device);
        if (link->ifindex <= 0)
                return -EINVAL;

        mac = udev_device_get_sysattr_value(device, "address");
        if (mac) {
                mac_addr = ether_aton(mac);
                if (mac_addr)
                        memcpy(&link->mac, mac_addr, sizeof(struct ether_addr));
        }

        ifname = udev_device_get_sysname(device);
        link->ifname = strdup(ifname);

        r = hashmap_put(manager->links, &link->ifindex, link);
        if (r < 0)
                return r;

        *ret = link;
        link = NULL;

        return 0;
}

void link_free(Link *link) {
        if (!link)
                return;

        assert(link->manager);

        sd_dhcp_client_free(link->dhcp_client);
        sd_dhcp_lease_unref(link->dhcp_lease);

        hashmap_remove(link->manager->links, &link->ifindex);

        free(link->ifname);

        free(link);
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

int link_add(Manager *m, struct udev_device *device, Link **ret) {
        Link *link = NULL;
        Network *network;
        int r;

        assert(m);
        assert(device);

        r = link_new(m, device, &link);
        if (r < 0)
                return r;

        *ret = link;

        r = network_get(m, device, &network);
        if (r < 0)
                return r == -ENOENT ? 0 : r;

        r = network_apply(m, network, link);
        if (r < 0)
                return r;

        return 0;
}

static int link_enter_configured(Link *link) {
        assert(link);
        assert(link->state == LINK_STATE_SETTING_ROUTES);

        log_info_link(link, "link configured");

        link->state = LINK_STATE_CONFIGURED;

        return 0;
}

static void link_enter_failed(Link *link) {
        assert(link);

        log_warning_link(link, "failed");

        link->state = LINK_STATE_FAILED;
}

static int route_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link->route_messages > 0);
        assert(link->state == LINK_STATE_SETTING_ADDRESSES ||
               link->state == LINK_STATE_SETTING_ROUTES ||
               link->state == LINK_STATE_FAILED);

        link->route_messages --;

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%s: could not set route: %s",
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

static int link_enter_set_routes(Link *link) {
        Route *rt;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_SETTING_ADDRESSES);

        link->state = LINK_STATE_SETTING_ROUTES;

        if (!link->network->static_routes && !link->dhcp_lease)
                return link_enter_configured(link);

        log_debug_link(link, "setting routes");

        LIST_FOREACH(static_routes, rt, link->network->static_routes) {
                r = route_configure(rt, link, &route_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set routes: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->route_messages ++;
        }

        if (link->dhcp_lease) {
                _cleanup_route_free_ Route *route = NULL;
                struct in_addr gateway;

                r = sd_dhcp_lease_get_router(link->dhcp_lease, &gateway);
                if (r < 0) {
                        log_warning_link(link, "DHCP error: no router: %s",
                                         strerror(-r));
                        return r;
                }

                r = route_new_dynamic(&route);
                if (r < 0) {
                        log_error_link(link, "Could not allocate route: %s",
                                       strerror(-r));
                        return r;
                }

                route->family = AF_INET;
                route->in_addr.in = gateway;

                r = route_configure(route, link, &route_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set routes: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->route_messages ++;
        }

        return 0;
}

static int address_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->addr_messages > 0);
        assert(link->state == LINK_STATE_SETTING_ADDRESSES || link->state == LINK_STATE_FAILED);

        link->addr_messages --;

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%s: could not set address: %s",
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

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->state = LINK_STATE_SETTING_ADDRESSES;

        if (!link->network->static_addresses && !link->dhcp_lease)
                return link_enter_set_routes(link);

        log_debug_link(link, "setting addresses");

        LIST_FOREACH(static_addresses, ad, link->network->static_addresses) {
                r = address_configure(ad, link, &address_handler);
                if (r < 0) {
                        log_warning_link(link,
                                         "could not set addresses: %s", strerror(-r));
                        link_enter_failed(link);
                        return r;
                }

                link->addr_messages ++;
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
                address->prefixlen = prefixlen;
                address->broadcast.s_addr = addr.s_addr | ~netmask.s_addr;

                r = address_configure(address, link, &address_handler);
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

static int address_drop_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%s: could not drop address: %s",
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);

        return 1;
}

static int set_hostname_handler(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        int r;

        r = sd_bus_message_get_errno(m);
        if (r < 0)
                log_warning("Could not set hostname: %s", strerror(-r));

        return 1;
}

static int set_hostname(sd_bus *bus, const char *hostname) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r = 0;

        assert(hostname);

        log_debug("Setting transient hostname: '%s'", hostname);

        if (!bus) { /* TODO: replace by assert when we can rely on kdbus */
                log_info("Not connected to system bus, ignoring transient hostname.");
                return 0;
        }

        r = sd_bus_message_new_method_call(
                        bus,
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

        r = sd_bus_call_async(bus, m, set_hostname_handler, NULL, 0, NULL);
        if (r < 0)
                log_error("Could not set transient hostname: %s", strerror(-r));

        return r;
}

static int set_mtu_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0)
                log_struct_link(LOG_WARNING, link,
                                "MESSAGE=%s: could not set MTU: %s",
                                link->ifname, strerror(-r),
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

        return 0;
}

static int dhcp_lease_lost(Link *link) {
        _cleanup_address_free_ Address *address = NULL;
        struct in_addr addr;
        struct in_addr netmask;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        log_warning_link(link, "DHCP lease lost");

        r = address_new_dynamic(&address);
        if (r >= 0) {
                sd_dhcp_lease_get_address(link->dhcp_lease, &addr);
                sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
                prefixlen = net_netmask_to_prefixlen(&netmask);

                address->family = AF_INET;
                address->in_addr.in = addr;
                address->prefixlen = prefixlen;

                address_drop(address, link, address_drop_handler);
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
                        r = set_hostname(link->manager->bus, "");
                        if (r < 0)
                                log_error("Failed to reset transient hostname");
                }
        }

        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);

        return 0;
}

static int dhcp_lease_acquired(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        struct in_addr gateway;
        unsigned prefixlen;
        struct in_addr *nameservers;
        size_t nameservers_size;
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
        if (r < 0) {
                log_warning_link(link, "DHCP error: no router: %s",
                                 strerror(-r));
                return r;
        }

        log_struct_link(LOG_INFO, link,
                        "MESSAGE=%s: DHCPv4 address %u.%u.%u.%u/%u via %u.%u.%u.%u",
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

        link->dhcp_lease = lease;

        if (link->network->dhcp_dns) {
                r = sd_dhcp_lease_get_dns(lease, &nameservers, &nameservers_size);
                if (r >= 0) {
                        r = manager_update_resolv_conf(link->manager);
                        if (r < 0)
                                log_error("Failed to update resolv.conf");
                }
        }

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
                        r = set_hostname(link->manager->bus, hostname);
                        if (r < 0)
                                log_error("Failed to set transient hostname "
                                          "to '%s'", hostname);
                }
        }

        link_enter_set_addresses(link);

        return 0;
}

static void dhcp_handler(sd_dhcp_client *client, int event, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (link->state == LINK_STATE_FAILED)
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
                                log_warning_link(link, "DHCP error: %s", strerror(-event));
                        else
                                log_warning_link(link, "DHCP unknown event: %d", event);
                        break;
        }

        return;
}

static int link_acquire_conf(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->dhcp);
        assert(link->manager);
        assert(link->manager->event);

        if (!link->dhcp_client) {
                r = sd_dhcp_client_new(&link->dhcp_client);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_attach_event(link->dhcp_client, NULL, 0);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_set_index(link->dhcp_client, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_dhcp_client_set_mac(link->dhcp_client, &link->mac);
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
        }

        log_debug_link(link, "acquiring DHCPv4 lease");

        r = sd_dhcp_client_start(link->dhcp_client);
        if (r < 0)
                return r;

        return 0;
}

static int link_update_flags(Link *link, unsigned flags) {
        int r;

        assert(link);
        assert(link->network);

        if (link->state == LINK_STATE_FAILED)
                return 0;

        if (link->flags == flags) {
                log_debug_link(link, "link status unchanged: %#.8x", flags);
                return 0;
        }

        if ((link->flags & IFF_UP) != (flags & IFF_UP))
                log_info_link(link,
                              "link is %s", flags & IFF_UP ? "up": "down");

        if ((link->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
                if (flags & IFF_LOWER_UP) {
                        log_info_link(link, "carrier on");

                        if (link->network->dhcp) {
                                r = link_acquire_conf(link);
                                if (r < 0) {
                                        log_warning_link(link, "Could not acquire DHCPv4 lease: %s", strerror(-r));
                                        link_enter_failed(link);
                                        return r;
                                }
                        }
                } else {
                        log_info_link(link, "carrier off");

                        if (link->network->dhcp) {
                                r = sd_dhcp_client_stop(link->dhcp_client);
                                if (r < 0) {
                                        log_warning_link(link, "Could not stop DHCPv4 client: %s", strerror(-r));
                                        link_enter_failed(link);
                                        return r;
                                }
                        }
                }
        }

        log_debug_link(link,
                       "link status updated: %#.8x -> %#.8x", link->flags, flags);

        link->flags = flags;

        return 0;
}

static int link_up_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                log_struct_link(LOG_ERR, link,
                                "MESSAGE=%s: could not bring up interface: %s",
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);
                link_enter_failed(link);
                return 1;
        }

        link_update_flags(link, link->flags | IFF_UP);

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

        return 0;
}

static int link_enslaved(Link *link) {
        int r;

        assert(link);
        assert(link->state == LINK_STATE_ENSLAVING);
        assert(link->network);

        r = link_up(link);
        if (r < 0) {
                link_enter_failed(link);
                return r;
        }

        if (!link->network->dhcp)
                return link_enter_set_addresses(link);

        return 0;
}

static int enslave_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->state == LINK_STATE_ENSLAVING || link->state == LINK_STATE_FAILED);
        assert(link->network);

        link->enslaving --;

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                log_struct_link(LOG_ERR, link,
                                "MESSAGE=%s: could not enslave: %s",
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);
                link_enter_failed(link);
                return 1;
        }

        log_debug_link(link, "enslaved");

        if (link->enslaving == 0)
                link_enslaved(link);

        return 1;
}

static int link_enter_enslave(Link *link) {
        NetDev *vlan;
        Iterator i;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == _LINK_STATE_INVALID);

        link->state = LINK_STATE_ENSLAVING;

        if (!link->network->bridge && !link->network->bond &&
            hashmap_isempty(link->network->vlans))
                return link_enslaved(link);

        if (link->network->bridge) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%s: enslaving by '%s'",
                                link->ifname, link->network->bridge->name,
                                NETDEV(link->network->bridge),
                                NULL);

                r = netdev_enslave(link->network->bridge, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%s: could not enslave by '%s': %s",
                                        link->ifname, link->network->bridge->name, strerror(-r),
                                        NETDEV(link->network->bridge),
                                        NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        HASHMAP_FOREACH(vlan, link->network->vlans, i) {
                log_struct_link(LOG_DEBUG, link,
                                "MESSAGE=%s: enslaving by '%s'",
                                link->ifname, vlan->name, NETDEV(vlan), NULL);

                r = netdev_enslave(vlan, link, &enslave_handler);
                if (r < 0) {
                        log_struct_link(LOG_WARNING, link,
                                        "MESSAGE=%s: could not enslave by '%s': %s",
                                        link->ifname, vlan->name, strerror(-r),
                                        NETDEV(vlan), NULL);
                        link_enter_failed(link);
                        return r;
                }

                link->enslaving ++;
        }

        return 0;
}

static int link_getlink_handler(sd_rtnl *rtnl, sd_rtnl_message *m,
                                void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        if (link->state == LINK_STATE_FAILED)
                return 1;

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                log_struct_link(LOG_ERR, link,
                                "MESSAGE=%s: could not get state: %s",
                                link->ifname, strerror(-r),
                                "ERRNO=%d", -r,
                                NULL);
                link_enter_failed(link);
                return 1;
        }

        log_debug_link(link, "got link state");

        link_update(link, m);

        return 1;
}

static int link_getlink(Link *link) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_debug_link(link, "requesting link status");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req,
                                     RTM_GETLINK, link->ifindex);
        if (r < 0) {
                log_error_link(link, "Could not allocate RTM_GETLINK message");
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, link_getlink_handler,
                               link, 0, NULL);
        if (r < 0) {
                log_error_link(link,
                               "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == _LINK_STATE_INVALID);

        r = link_getlink(link);
        if (r < 0) {
                link_enter_failed(link);
                return r;
        }

        return link_enter_enslave(link);
}

int link_update(Link *link, sd_rtnl_message *m) {
        unsigned flags;
        void *data;
        uint16_t type;
        int r;

        assert(link);
        assert(m);

        if (link->state == LINK_STATE_FAILED)
                return 0;

        r = sd_rtnl_message_link_get_flags(m, &flags);
        if (r < 0) {
                log_warning_link(link, "Could not get link flags");
                return r;
        }

        while (sd_rtnl_message_read(m, &type, &data) > 0) {
                if (type == IFLA_MTU && link->network->dhcp &&
                    link->network->dhcp_mtu && !link->original_mtu) {
                        link->original_mtu = *(uint16_t *) data;
                        log_debug_link(link, "saved original MTU: %" PRIu16,
                                       link->original_mtu);
                }
        }

        return link_update_flags(link, flags);
}

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

#include <sys/socket.h>
#include <linux/if.h>

#include "sd-daemon.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "bus-util.h"
#include "conf-parser.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "libudev-private.h"
#include "local-addresses.h"
#include "netlink-util.h"
#include "networkd.h"
#include "path-util.h"
#include "set.h"
#include "udev-util.h"
#include "virt.h"

/* use 8 MB for receive socket kernel queue. */
#define RCVBUF_SIZE    (8*1024*1024)

const char* const network_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
#ifdef HAVE_SPLIT_USR
        "/lib/systemd/network",
#endif
        NULL};

static int setup_default_address_pool(Manager *m) {
        AddressPool *p;
        int r;

        assert(m);

        /* Add in the well-known private address ranges. */

        r = address_pool_new_from_string(m, &p, AF_INET6, "fc00::", 7);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "192.168.0.0", 16);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "172.16.0.0", 12);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "10.0.0.0", 8);
        if (r < 0)
                return r;

        return 0;
}

static int on_bus_retry(sd_event_source *s, usec_t usec, void *userdata) {
        Manager *m = userdata;

        assert(s);
        assert(m);

        m->bus_retry_event_source = sd_event_source_unref(m->bus_retry_event_source);

        manager_connect_bus(m);

        return 0;
}

static int manager_reset_all(Manager *m) {
        Link *link;
        Iterator i;
        int r;

        assert(m);

        HASHMAP_FOREACH(link, m->links, i) {
                r = link_carrier_reset(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Could not reset carrier: %m");
        }

        return 0;
}

static int match_prepare_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = userdata;
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse PrepareForSleep signal: %m");
                return 0;
        }

        if (b)
                return 0;

        log_debug("Coming back from suspend, resetting all connections...");

        manager_reset_all(m);

        return 0;
}

int manager_connect_bus(Manager *m) {
        int r;

        assert(m);

        r = sd_bus_default_system(&m->bus);
        if (r == -ENOENT) {
                /* We failed to connect? Yuck, we must be in early
                 * boot. Let's try in 5s again. As soon as we have
                 * kdbus we can stop doing this... */

                log_debug_errno(r, "Failed to connect to bus, trying again in 5s: %m");

                r = sd_event_add_time(m->event, &m->bus_retry_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + 5*USEC_PER_SEC, 0, on_bus_retry, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to install bus reconnect time event: %m");

                return 0;
        }

        if (r < 0)
                return r;

        r = sd_bus_add_match(m->bus, &m->prepare_for_sleep_slot,
                             "type='signal',"
                             "sender='org.freedesktop.login1',"
                             "interface='org.freedesktop.login1.Manager',"
                             "member='PrepareForSleep',"
                             "path='/org/freedesktop/login1'",
                             match_prepare_for_sleep,
                             m);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for PrepareForSleep: %m");

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/network1", "org.freedesktop.network1.Manager", manager_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add manager object vtable: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/network1/link", "org.freedesktop.network1.Link", link_vtable, link_object_find, m);
        if (r < 0)
               return log_error_errno(r, "Failed to add link object vtable: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/network1/link", link_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add link enumerator: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/network1/network", "org.freedesktop.network1.Network", network_vtable, network_object_find, m);
        if (r < 0)
               return log_error_errno(r, "Failed to add network object vtable: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/network1/network", network_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add network enumerator: %m");

        r = sd_bus_request_name(m->bus, "org.freedesktop.network1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to register name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static int manager_udev_process_link(Manager *m, struct udev_device *device) {
        Link *link = NULL;
        int r, ifindex;

        assert(m);
        assert(device);

        if (!streq_ptr(udev_device_get_action(device), "add"))
                return 0;

        ifindex = udev_device_get_ifindex(device);
        if (ifindex <= 0) {
                log_debug("Ignoring udev ADD event for device with invalid ifindex");
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r == -ENODEV)
                return 0;
        else if (r < 0)
                return r;

        r = link_initialized(link, device);
        if (r < 0)
                return r;

        return 0;
}

static int manager_dispatch_link_udev(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        struct udev_monitor *monitor = m->udev_monitor;
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;

        device = udev_monitor_receive_device(monitor);
        if (!device)
                return -ENOMEM;

        manager_udev_process_link(m, device);
        return 0;
}

static int manager_connect_udev(Manager *m) {
        int r;

        /* udev does not initialize devices inside containers,
         * so we rely on them being already initialized before
         * entering the container */
        if (detect_container() > 0)
                return 0;

        m->udev = udev_new();
        if (!m->udev)
                return -ENOMEM;

        m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_monitor)
                return -ENOMEM;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_monitor, "net", NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add udev monitor filter: %m");

        r = udev_monitor_enable_receiving(m->udev_monitor);
        if (r < 0) {
                log_error("Could not enable udev monitor");
                return r;
        }

        r = sd_event_add_io(m->event,
                        &m->udev_event_source,
                        udev_monitor_get_fd(m->udev_monitor),
                        EPOLLIN, manager_dispatch_link_udev,
                        m);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(m->udev_event_source, "networkd-udev");
        if (r < 0)
                return r;

        return 0;
}

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        uint16_t type;
        uint32_t ifindex, priority = 0;
        unsigned char protocol, scope, tos, table;
        int family;
        unsigned char dst_prefixlen, src_prefixlen;
        union in_addr_union dst = {}, gw = {}, src = {}, prefsrc = {};
        Route *route = NULL;
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive route: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type: %m");
                return 0;
        } else if (type != RTM_NEWROUTE && type != RTM_DELROUTE) {
                log_warning("rtnl: received unexpected message type when processing route");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_OIF, &ifindex);
        if (r == -ENODATA) {
                log_debug("rtnl: received route without ifindex, ignoring");
                return 0;
        } else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from route, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received route message with invalid ifindex, ignoring: %d", ifindex);
                return 0;
        } else {
                r = link_get(m, ifindex, &link);
                if (r < 0 || !link) {
                        /* when enumerating we might be out of sync, but we will
                         * get the route again, so just ignore it */
                        if (!m->enumerating)
                                log_warning("rtnl: received route for nonexistent link (%d), ignoring", ifindex);
                        return 0;
                }
        }

        r = sd_rtnl_message_route_get_family(message, &family);
        if (r < 0 || !IN_SET(family, AF_INET, AF_INET6)) {
                log_link_warning(link, "rtnl: received address with invalid family, ignoring.");
                return 0;
        }

        r = sd_rtnl_message_route_get_protocol(message, &protocol);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get route protocol: %m");
                return 0;
        }

        switch (family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, RTA_DST, &dst.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_GATEWAY, &gw.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid gateway, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_SRC, &src.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_PREFSRC, &prefsrc.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, RTA_DST, &dst.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_GATEWAY, &gw.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid gateway, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_SRC, &src.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_PREFSRC, &prefsrc.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route with invalid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        default:
                log_link_debug(link, "rtnl: ignoring unsupported address family: %d", family);
                return 0;
        }

        r = sd_rtnl_message_route_get_dst_prefixlen(message, &dst_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid destination prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_src_prefixlen(message, &src_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid source prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_scope(message, &scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_tos(message, &tos);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid tos, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_table(message, &table);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid table, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_PRIORITY, &priority);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route with invalid priority, ignoring: %m");
                return 0;
        }

        route_get(link, family, &dst, dst_prefixlen, tos, priority, table, &route);

        switch (type) {
        case RTM_NEWROUTE:
                if (!route) {
                        /* A route appeared that we did not request */
                        r = route_add_foreign(link, family, &dst, dst_prefixlen, tos, priority, table, &route);
                        if (r < 0)
                                return 0;
                }

                route_update(route, &src, src_prefixlen, &gw, &prefsrc, scope, protocol);

                break;

        case RTM_DELROUTE:

                if (route)
                        route_drop(route);

                break;
        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

int manager_rtnl_process_address(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        uint16_t type;
        unsigned char flags;
        int family;
        unsigned char prefixlen;
        unsigned char scope;
        union in_addr_union in_addr;
        struct ifa_cacheinfo cinfo;
        Address *address = NULL;
        char buf[INET6_ADDRSTRLEN], valid_buf[FORMAT_TIMESPAN_MAX];
        const char *valid_str = NULL;
        int r, ifindex;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive address: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type: %m");
                return 0;
        } else if (type != RTM_NEWADDR && type != RTM_DELADDR) {
                log_warning("rtnl: received unexpected message type when processing address");
                return 0;
        }

        r = sd_rtnl_message_addr_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from address: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received address message with invalid ifindex: %d", ifindex);
                return 0;
        } else {
                r = link_get(m, ifindex, &link);
                if (r < 0 || !link) {
                        /* when enumerating we might be out of sync, but we will
                         * get the address again, so just ignore it */
                        if (!m->enumerating)
                                log_warning("rtnl: received address for nonexistent link (%d), ignoring", ifindex);
                        return 0;
                }
        }

        r = sd_rtnl_message_addr_get_family(message, &family);
        if (r < 0 || !IN_SET(family, AF_INET, AF_INET6)) {
                log_link_warning(link, "rtnl: received address with invalid family, ignoring.");
                return 0;
        }

        r = sd_rtnl_message_addr_get_prefixlen(message, &prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address with invalid prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_scope(message, &scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_flags(message, &flags);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address with invalid flags, ignoring: %m");
                return 0;
        }

        switch (family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, IFA_LOCAL, &in_addr.in);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address without valid address, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, IFA_ADDRESS, &in_addr.in6);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address without valid address, ignoring: %m");
                        return 0;
                }

                break;

        default:
                log_link_debug(link, "rtnl: ignoring unsupported address family: %d", family);
        }

        if (!inet_ntop(family, &in_addr, buf, INET6_ADDRSTRLEN)) {
                log_link_warning(link, "Could not print address");
                return 0;
        }

        r = sd_netlink_message_read_cache_info(message, IFA_CACHEINFO, &cinfo);
        if (r >= 0) {
                if (cinfo.ifa_valid != CACHE_INFO_INFINITY_LIFE_TIME)
                        valid_str = format_timespan(valid_buf, FORMAT_TIMESPAN_MAX,
                                                    cinfo.ifa_valid * USEC_PER_SEC,
                                                    USEC_PER_SEC);
        }

        address_get(link, family, &in_addr, prefixlen, &address);

        switch (type) {
        case RTM_NEWADDR:
                if (address)
                        log_link_debug(link, "Updating address: %s/%u (valid %s%s)", buf, prefixlen,
                                       valid_str ? "for " : "forever", valid_str ?: "");
                else {
                        /* An address appeared that we did not request */
                        r = address_add_foreign(link, family, &in_addr, prefixlen, &address);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to add address %s/%u: %m", buf, prefixlen);
                                return 0;
                        } else
                                log_link_debug(link, "Adding address: %s/%u (valid %s%s)", buf, prefixlen,
                                               valid_str ? "for " : "forever", valid_str ?: "");
                }

                address_update(address, flags, scope, &cinfo);

                break;

        case RTM_DELADDR:

                if (address) {
                        log_link_debug(link, "Removing address: %s/%u (valid %s%s)", buf, prefixlen,
                                       valid_str ? "for " : "forever", valid_str ?: "");
                        address_drop(address);
                } else
                        log_link_warning(link, "Removing non-existent address: %s/%u (valid %s%s)", buf, prefixlen,
                                         valid_str ? "for " : "forever", valid_str ?: "");

                break;
        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static int manager_rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        NetDev *netdev = NULL;
        uint16_t type;
        const char *name;
        int r, ifindex;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: Could not receive link: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type: %m");
                return 0;
        } else if (type != RTM_NEWLINK && type != RTM_DELLINK) {
                log_warning("rtnl: Received unexpected message type when processing link");
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex: %d", ifindex);
                return 0;
        } else
                link_get(m, ifindex, &link);

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &name);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Received link message without ifname: %m");
                return 0;
        } else
                netdev_get(m, name, &netdev);

        switch (type) {
        case RTM_NEWLINK:
                if (!link) {
                        /* link is new, so add it */
                        r = link_add(m, message, &link);
                        if (r < 0) {
                                log_warning_errno(r, "Could not add new link: %m");
                                return 0;
                        }
                }

                if (netdev) {
                        /* netdev exists, so make sure the ifindex matches */
                        r = netdev_set_ifindex(netdev, message);
                        if (r < 0) {
                                log_warning_errno(r, "Could not set ifindex on netdev: %m");
                                return 0;
                        }
                }

                r = link_update(link, message);
                if (r < 0)
                        return 0;

                break;

        case RTM_DELLINK:
                link_drop(link);
                netdev_drop(netdev);

                break;

        default:
                assert_not_reached("Received invalid RTNL message type.");
        }

        return 1;
}

static int systemd_netlink_fd(void) {
        int n, fd, rtnl_fd = -EINVAL;

        n = sd_listen_fds(true);
        if (n <= 0)
                return -EINVAL;

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd ++) {
                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {
                        if (rtnl_fd >= 0)
                                return -EINVAL;

                        rtnl_fd = fd;
                }
        }

        return rtnl_fd;
}

static int manager_connect_rtnl(Manager *m) {
        int fd, r;

        assert(m);

        fd = systemd_netlink_fd();
        if (fd < 0)
                r = sd_netlink_open(&m->rtnl);
        else
                r = sd_netlink_open_fd(&m->rtnl, fd);
        if (r < 0)
                return r;

        r = sd_netlink_inc_rcvbuf(m->rtnl, RCVBUF_SIZE);
        if (r < 0)
                return r;

        r = sd_netlink_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_NEWLINK, &manager_rtnl_process_link, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELLINK, &manager_rtnl_process_link, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_NEWADDR, &manager_rtnl_process_address, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELADDR, &manager_rtnl_process_address, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_NEWROUTE, &manager_rtnl_process_route, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELROUTE, &manager_rtnl_process_route, m);
        if (r < 0)
                return r;

        return 0;
}

static int set_put_in_addr(Set *s, const struct in_addr *address) {
        char *p;
        int r;

        assert(s);

        r = in_addr_to_string(AF_INET, (const union in_addr_union*) address, &p);
        if (r < 0)
                return r;

        r = set_consume(s, p);
        if (r == -EEXIST)
                return 0;

        return r;
}

static int set_put_in_addrv(Set *s, const struct in_addr *addresses, int n) {
        int r, i, c = 0;

        assert(s);
        assert(n <= 0 || addresses);

        for (i = 0; i < n; i++) {
                r = set_put_in_addr(s, addresses+i);
                if (r < 0)
                        return r;

                c += r;
        }

        return c;
}

static void print_string_set(FILE *f, const char *field, Set *s) {
        bool space = false;
        Iterator i;
        char *p;

        if (set_isempty(s))
                return;

        fputs(field, f);

        SET_FOREACH(p, s, i) {
                if (space)
                        fputc(' ', f);
                fputs(p, f);
                space = true;
        }
        fputc('\n', f);
}

static int manager_save(Manager *m) {
        _cleanup_set_free_free_ Set *dns = NULL, *ntp = NULL, *domains = NULL;
        Link *link;
        Iterator i;
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        LinkOperationalState operstate = LINK_OPERSTATE_OFF;
        const char *operstate_str;
        int r;

        assert(m);
        assert(m->state_file);

        /* We add all NTP and DNS server to a set, to filter out duplicates */
        dns = set_new(&string_hash_ops);
        if (!dns)
                return -ENOMEM;

        ntp = set_new(&string_hash_ops);
        if (!ntp)
                return -ENOMEM;

        domains = set_new(&string_hash_ops);
        if (!domains)
                return -ENOMEM;

        HASHMAP_FOREACH(link, m->links, i) {
                if (link->flags & IFF_LOOPBACK)
                        continue;

                if (link->operstate > operstate)
                        operstate = link->operstate;

                if (!link->network)
                        continue;

                /* First add the static configured entries */
                r = set_put_strdupv(dns, link->network->dns);
                if (r < 0)
                        return r;

                r = set_put_strdupv(ntp, link->network->ntp);
                if (r < 0)
                        return r;

                r = set_put_strdupv(domains, link->network->domains);
                if (r < 0)
                        return r;

                if (!link->dhcp_lease)
                        continue;

                /* Secondly, add the entries acquired via DHCP */
                if (link->network->dhcp_dns) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = set_put_in_addrv(dns, addresses, r);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_ntp) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = set_put_in_addrv(ntp, addresses, r);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_domains) {
                        const char *domainname;

                        r = sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname);
                        if (r >= 0) {
                                r = set_put_strdup(domains, domainname);
                                if (r < 0)
                                        return r;
                        } else if (r != -ENODATA)
                                return r;
                }
        }

        operstate_str = link_operstate_to_string(operstate);
        assert(operstate_str);

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "OPER_STATE=%s\n", operstate_str);

        print_string_set(f, "DNS=", dns);
        print_string_set(f, "NTP=", ntp);
        print_string_set(f, "DOMAINS=", domains);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, m->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        if (m->operational_state != operstate) {
                m->operational_state = operstate;
                r = manager_send_changed(m, "OperationalState", NULL);
                if (r < 0)
                        log_error_errno(r, "Could not emit changed OperationalState: %m");
        }

        m->dirty = false;

        return 0;

fail:
        (void) unlink(m->state_file);
        (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save network state to %s: %m", m->state_file);
}

static int manager_dirty_handler(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Link *link;
        Iterator i;
        int r;

        assert(m);

        if (m->dirty)
                manager_save(m);

        SET_FOREACH(link, m->dirty_links, i) {
                r = link_save(link);
                if (r >= 0)
                        link_clean(link);
        }

        return 1;
}

int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->state_file = strdup("/run/systemd/netif/state");
        if (!m->state_file)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_set_watchdog(m->event, true);

        sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        r = sd_event_add_post(m->event, NULL, manager_dirty_handler, m);
        if (r < 0)
                return r;

        r = manager_connect_rtnl(m);
        if (r < 0)
                return r;

        r = manager_connect_udev(m);
        if (r < 0)
                return r;

        m->netdevs = hashmap_new(&string_hash_ops);
        if (!m->netdevs)
                return -ENOMEM;

        LIST_HEAD_INIT(m->networks);

        r = setup_default_address_pool(m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

void manager_free(Manager *m) {
        Network *network;
        NetDev *netdev;
        Link *link;
        AddressPool *pool;

        if (!m)
                return;

        free(m->state_file);

        while ((link = hashmap_first(m->links)))
                link_unref(link);
        hashmap_free(m->links);

        while ((network = m->networks))
                network_free(network);

        hashmap_free(m->networks_by_name);

        while ((netdev = hashmap_first(m->netdevs)))
                netdev_unref(netdev);
        hashmap_free(m->netdevs);

        while ((pool = m->address_pools))
                address_pool_free(pool);

        sd_netlink_unref(m->rtnl);
        sd_event_unref(m->event);

        sd_event_source_unref(m->udev_event_source);
        udev_monitor_unref(m->udev_monitor);
        udev_unref(m->udev);

        sd_bus_unref(m->bus);
        sd_bus_slot_unref(m->prepare_for_sleep_slot);
        sd_event_source_unref(m->bus_retry_event_source);

        free(m);
}

static bool manager_check_idle(void *userdata) {
        Manager *m = userdata;
        Link *link;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(link, m->links, i) {
                /* we are not woken on udev activity, so let's just wait for the
                 * pending udev event */
                if (link->state == LINK_STATE_PENDING)
                        return false;

                if (!link->network)
                        continue;

                /* we are not woken on netork activity, so let's stay around */
                if (link_lldp_enabled(link) ||
                    link_ipv4ll_enabled(link) ||
                    link_dhcp4_server_enabled(link) ||
                    link_dhcp4_enabled(link) ||
                    link_dhcp6_enabled(link) ||
                    link_ipv6_accept_ra_enabled(link))
                        return false;
        }

        return true;
}

int manager_run(Manager *m) {
        Link *link;
        Iterator i;

        assert(m);

        /* The dirty handler will deal with future serialization, but the first one
           must be done explicitly. */

        manager_save(m);

        HASHMAP_FOREACH(link, m->links, i)
                link_save(link);

        if (m->bus)
                return bus_event_loop_with_idle(
                                m->event,
                                m->bus,
                                "org.freedesktop.network1",
                                DEFAULT_EXIT_USEC,
                                manager_check_idle,
                                m);
        else
                /* failed to connect to the bus, so we lose exit-on-idle logic,
                   this should not happen except if dbus is not around at all */
                return sd_event_loop(m->event);
}

int manager_load_config(Manager *m) {
        int r;

        /* update timestamp */
        paths_check_timestamp(network_dirs, &m->network_dirs_ts_usec, true);

        r = netdev_load(m);
        if (r < 0)
                return r;

        r = network_load(m);
        if (r < 0)
                return r;

        return 0;
}

bool manager_should_reload(Manager *m) {
        return paths_check_timestamp(network_dirs, &m->network_dirs_ts_usec, false);
}

int manager_rtnl_enumerate_links(Manager *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *link;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (link = reply; link; link = sd_netlink_message_next(link)) {
                int k;

                m->enumerating = true;

                k = manager_rtnl_process_link(m->rtnl, link, m);
                if (k < 0)
                        r = k;

                m->enumerating = false;
        }

        return r;
}

int manager_rtnl_enumerate_addresses(Manager *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *addr;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, 0, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (addr = reply; addr; addr = sd_netlink_message_next(addr)) {
                int k;

                m->enumerating = true;

                k = manager_rtnl_process_address(m->rtnl, addr, m);
                if (k < 0)
                        r = k;

                m->enumerating = false;
        }

        return r;
}

int manager_rtnl_enumerate_routes(Manager *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *route;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_route(m->rtnl, &req, RTM_GETROUTE, 0, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (route = reply; route; route = sd_netlink_message_next(route)) {
                int k;

                m->enumerating = true;

                k = manager_rtnl_process_route(m->rtnl, route, m);
                if (k < 0)
                        r = k;

                m->enumerating = false;
        }

        return r;
}

int manager_address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found) {
        AddressPool *p;
        int r;

        assert(m);
        assert(prefixlen > 0);
        assert(found);

        LIST_FOREACH(address_pools, p, m->address_pools) {
                if (p->family != family)
                        continue;

                r = address_pool_acquire(p, prefixlen, found);
                if (r != 0)
                        return r;
        }

        return 0;
}

Link* manager_find_uplink(Manager *m, Link *exclude) {
        _cleanup_free_ struct local_address *gateways = NULL;
        int n, i;

        assert(m);

        /* Looks for a suitable "uplink", via black magic: an
         * interface that is up and where the default route with the
         * highest priority points to. */

        n = local_gateways(m->rtnl, 0, AF_UNSPEC, &gateways);
        if (n < 0) {
                log_warning_errno(n, "Failed to determine list of default gateways: %m");
                return NULL;
        }

        for (i = 0; i < n; i++) {
                Link *link;

                link = hashmap_get(m->links, INT_TO_PTR(gateways[i].ifindex));
                if (!link) {
                        log_debug("Weird, found a gateway for a link we don't know. Ignoring.");
                        continue;
                }

                if (link == exclude)
                        continue;

                if (link->operstate < LINK_OPERSTATE_ROUTABLE)
                        continue;

                return link;
        }

        return NULL;
}

void manager_dirty(Manager *manager) {
        assert(manager);

        /* the serialized state in /run is no longer up-to-date */
        manager->dirty = true;
}

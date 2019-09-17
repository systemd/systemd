/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/fib_rules.h>

#include "sd-daemon.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "bus-util.h"
#include "conf-parser.h"
#include "def.h"
#include "device-private.h"
#include "device-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "local-addresses.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-dhcp6.h"
#include "networkd-link-bus.h"
#include "networkd-manager-bus.h"
#include "networkd-manager.h"
#include "networkd-network-bus.h"
#include "networkd-speed-meter.h"
#include "ordered-set.h"
#include "path-util.h"
#include "set.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "virt.h"

/* use 8 MB for receive socket kernel queue. */
#define RCVBUF_SIZE    (8*1024*1024)

static int setup_default_address_pool(Manager *m) {
        AddressPool *p;
        int r;

        assert(m);

        /* Add in the well-known private address ranges. */

        r = address_pool_new_from_string(m, &p, AF_INET6, "fd00::", 8);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "10.0.0.0", 8);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "172.16.0.0", 12);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "192.168.0.0", 16);
        if (r < 0)
                return r;

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
        assert(m);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse PrepareForSleep signal: %m");
                return 0;
        }

        if (b)
                return 0;

        log_debug("Coming back from suspend, resetting all connections...");

        (void) manager_reset_all(m);

        return 0;
}

static int on_connected(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = userdata;

        assert(message);
        assert(m);

        /* Did we get a timezone or transient hostname from DHCP while D-Bus wasn't up yet? */
        if (m->dynamic_hostname)
                (void) manager_set_hostname(m, m->dynamic_hostname);
        if (m->dynamic_timezone)
                (void) manager_set_timezone(m, m->dynamic_timezone);
        if (m->links_requesting_uuid)
                (void) manager_request_product_uuid(m, NULL);

        return 0;
}

int manager_connect_bus(Manager *m) {
        int r;

        assert(m);

        if (m->bus)
                return 0;

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-network");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus: %m");

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

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.network1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.DBus.Local",
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "Connected",
                        on_connected, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match on Connected signal: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "PrepareForSleep",
                        match_prepare_for_sleep, NULL, m);
        if (r < 0)
                log_warning_errno(r, "Failed to request match for PrepareForSleep, ignoring: %m");

        return 0;
}

static int manager_udev_process_link(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = userdata;
        DeviceAction action;
        Link *link = NULL;
        int r, ifindex;

        assert(m);
        assert(device);

        r = device_get_action(device, &action);
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to get udev action, ignoring device: %m");
                return 0;
        }

        if (!IN_SET(action, DEVICE_ACTION_ADD, DEVICE_ACTION_CHANGE, DEVICE_ACTION_MOVE)) {
                log_device_debug(device, "Ignoring udev %s event for device.", device_action_to_string(action));
                return 0;
        }

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0) {
                log_device_debug_errno(device, r, "Ignoring udev ADD event for device without ifindex or with invalid ifindex: %m");
                return 0;
        }

        r = device_is_renaming(device);
        if (r < 0) {
                log_device_error_errno(device, r, "Failed to determine the device is renamed or not, ignoring '%s' uevent: %m",
                                       device_action_to_string(action));
                return 0;
        }
        if (r > 0) {
                log_device_debug(device, "Interface is under renaming, wait for the interface to be renamed: %m");
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0) {
                if (r != -ENODEV)
                        log_debug_errno(r, "Failed to get link from ifindex %i, ignoring: %m", ifindex);
                return 0;
        }

        (void) link_initialized(link, device);

        return 0;
}

static int manager_connect_udev(Manager *m) {
        int r;

        /* udev does not initialize devices inside containers,
         * so we rely on them being already initialized before
         * entering the container */
        if (detect_container() > 0)
                return 0;

        r = sd_device_monitor_new(&m->device_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, "net", NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add device monitor filter: %m");

        r = sd_device_monitor_attach_event(m->device_monitor, m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(m->device_monitor, manager_udev_process_link, m);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        return 0;
}

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        _cleanup_(route_freep) Route *tmp = NULL;
        Route *route = NULL;
        Manager *m = userdata;
        Link *link = NULL;
        uint32_t ifindex;
        uint16_t type;
        unsigned char table;
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive route message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE)) {
                log_warning("rtnl: received unexpected message type %u when processing route, ignoring.", type);
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_OIF, &ifindex);
        if (r == -ENODATA) {
                log_debug("rtnl: received route message without ifindex, ignoring");
                return 0;
        } else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from route message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received route message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will
                 * get the route again, so just ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received route message for link (%d) we do not know about, ignoring", ifindex);
                return 0;
        }

        r = route_new(&tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_route_get_family(message, &tmp->family);
        if (r < 0 || !IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_link_warning(link, "rtnl: received route message with invalid family, ignoring");
                return 0;
        }

        r = sd_rtnl_message_route_get_protocol(message, &tmp->protocol);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid route protocol: %m");
                return 0;
        }

        switch (tmp->family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, RTA_DST, &tmp->dst.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_GATEWAY, &tmp->gw.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_SRC, &tmp->src.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_PREFSRC, &tmp->prefsrc.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, RTA_DST, &tmp->dst.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_GATEWAY, &tmp->gw.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_SRC, &tmp->src.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_PREFSRC, &tmp->prefsrc.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        default:
                assert_not_reached("Received route message with unsupported address family");
                return 0;
        }

        r = sd_rtnl_message_route_get_dst_prefixlen(message, &tmp->dst_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid destination prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_src_prefixlen(message, &tmp->src_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid source prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_scope(message, &tmp->scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_tos(message, &tmp->tos);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid tos, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_type(message, &tmp->type);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_table(message, &table);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid table, ignoring: %m");
                return 0;
        }
        tmp->table = table;

        r = sd_netlink_message_read_u32(message, RTA_PRIORITY, &tmp->priority);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid priority, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_enter_container(message, RTA_METRICS);
        if (r < 0 && r != -ENODATA) {
                log_link_error_errno(link, r, "rtnl: Could not enter RTA_METRICS container: %m");
                return 0;
        }
        if (r >= 0) {
                r = sd_netlink_message_read_u32(message, RTAX_INITCWND, &tmp->initcwnd);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message with invalid initcwnd, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_u32(message, RTAX_INITRWND, &tmp->initrwnd);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message with invalid initrwnd, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_exit_container(message);
                if (r < 0) {
                        log_link_error_errno(link, r, "rtnl: Could not exit from RTA_METRICS container: %m");
                        return 0;
                }
        }

        (void) route_get(link, tmp, &route);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *buf_dst = NULL, *buf_dst_prefixlen = NULL,
                        *buf_src = NULL, *buf_gw = NULL, *buf_prefsrc = NULL;
                char buf_scope[ROUTE_SCOPE_STR_MAX], buf_table[ROUTE_TABLE_STR_MAX],
                        buf_protocol[ROUTE_PROTOCOL_STR_MAX];

                if (!in_addr_is_null(tmp->family, &tmp->dst)) {
                        (void) in_addr_to_string(tmp->family, &tmp->dst, &buf_dst);
                        (void) asprintf(&buf_dst_prefixlen, "/%u", tmp->dst_prefixlen);
                }
                if (!in_addr_is_null(tmp->family, &tmp->src))
                        (void) in_addr_to_string(tmp->family, &tmp->src, &buf_src);
                if (!in_addr_is_null(tmp->family, &tmp->gw))
                        (void) in_addr_to_string(tmp->family, &tmp->gw, &buf_gw);
                if (!in_addr_is_null(tmp->family, &tmp->prefsrc))
                        (void) in_addr_to_string(tmp->family, &tmp->prefsrc, &buf_prefsrc);

                log_link_debug(link,
                               "%s route: dst: %s%s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s",
                               type == RTM_DELROUTE ? "Forgetting" : route ? "Received remembered" : "Remembering",
                               strna(buf_dst), strempty(buf_dst_prefixlen),
                               strna(buf_src), strna(buf_gw), strna(buf_prefsrc),
                               format_route_scope(tmp->scope, buf_scope, sizeof buf_scope),
                               format_route_table(tmp->table, buf_table, sizeof buf_table),
                               format_route_protocol(tmp->protocol, buf_protocol, sizeof buf_protocol),
                               strna(route_type_to_string(tmp->type)));
        }

        switch (type) {
        case RTM_NEWROUTE:
                if (!route) {
                        /* A route appeared that we did not request */
                        r = route_add_foreign(link, tmp, &route);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign route, ignoring: %m");
                                return 0;
                        }
                }

                break;

        case RTM_DELROUTE:
                route_free(route);
                break;

        default:
                assert_not_reached("Received route message with invalid RTNL message type");
        }

        return 1;
}

static int manager_rtnl_process_neighbor_lladdr(sd_netlink_message *message, union lladdr_union *lladdr, size_t *size, char **str) {
        int r;

        assert(message);
        assert(lladdr);
        assert(size);
        assert(str);

        *str = NULL;

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->ip.in6), &lladdr->ip.in6);
        if (r >= 0) {
                *size = sizeof(lladdr->ip.in6);
                if (in_addr_to_string(AF_INET6, &lladdr->ip, str) < 0)
                        log_warning_errno(r, "Could not print lower address: %m");
                return r;
        }

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->mac), &lladdr->mac);
        if (r >= 0) {
                *size = sizeof(lladdr->mac);
                *str = new(char, ETHER_ADDR_TO_STRING_MAX);
                if (!*str) {
                        log_oom();
                        return r;
                }
                ether_addr_to_string(&lladdr->mac, *str);
                return r;
        }

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->ip.in), &lladdr->ip.in);
        if (r >= 0) {
                *size = sizeof(lladdr->ip.in);
                if (in_addr_to_string(AF_INET, &lladdr->ip, str) < 0)
                        log_warning_errno(r, "Could not print lower address: %m");
                return r;
        }

        return r;
}

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        Neighbor *neighbor = NULL;
        int ifindex, family, r;
        uint16_t type, state;
        union in_addr_union in_addr = IN_ADDR_NULL;
        _cleanup_free_ char *addr_str = NULL;
        union lladdr_union lladdr;
        size_t lladdr_size = 0;
        _cleanup_free_ char *lladdr_str = NULL;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive neighbor message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEIGH, RTM_DELNEIGH)) {
                log_warning("rtnl: received unexpected message type %u when processing neighbor, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_neigh_get_state(message, &state);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message with invalid state, ignoring: %m");
                return 0;
        } else if (!FLAGS_SET(state, NUD_PERMANENT)) {
                log_debug("rtnl: received non-static neighbor, ignoring.");
                return 0;
        }

        r = sd_rtnl_message_neigh_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received neighbor message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will get the neighbor again, so just
                 * ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received neighbor for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = sd_rtnl_message_neigh_get_family(message, &family);
        if (r < 0 || !IN_SET(family, AF_INET, AF_INET6)) {
                log_link_warning(link, "rtnl: received neighbor message with invalid family, ignoring.");
                return 0;
        }

        switch (family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, NDA_DST, &in_addr.in);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, NDA_DST, &in_addr.in6);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                        return 0;
                }

                break;

        default:
                assert_not_reached("Received unsupported address family");
        }

        if (in_addr_to_string(family, &in_addr, &addr_str) < 0)
                log_link_warning_errno(link, r, "Could not print address: %m");

        r = manager_rtnl_process_neighbor_lladdr(message, &lladdr, &lladdr_size, &lladdr_str);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message with invalid lladdr, ignoring: %m");
                return 0;
        }

        (void) neighbor_get(link, family, &in_addr, &lladdr, lladdr_size, &neighbor);

        switch (type) {
        case RTM_NEWNEIGH:
                if (neighbor)
                        log_link_debug(link, "Remembering neighbor: %s->%s",
                                       strnull(addr_str), strnull(lladdr_str));
                else {
                        /* A neighbor appeared that we did not request */
                        r = neighbor_add_foreign(link, family, &in_addr, &lladdr, lladdr_size, &neighbor);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign neighbor %s->%s, ignoring: %m",
                                                       strnull(addr_str), strnull(lladdr_str));
                                return 0;
                        } else
                                log_link_debug(link, "Remembering foreign neighbor: %s->%s",
                                               strnull(addr_str), strnull(lladdr_str));
                }

                break;

        case RTM_DELNEIGH:
                if (neighbor) {
                        log_link_debug(link, "Forgetting neighbor: %s->%s",
                                       strnull(addr_str), strnull(lladdr_str));
                        (void) neighbor_free(neighbor);
                } else
                        log_link_info(link, "Kernel removed a neighbor we don't remember: %s->%s, ignoring.",
                                      strnull(addr_str), strnull(lladdr_str));

                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

int manager_rtnl_process_address(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        _cleanup_free_ char *buf = NULL;
        Manager *m = userdata;
        Link *link = NULL;
        uint16_t type;
        unsigned char flags, prefixlen, scope;
        union in_addr_union in_addr = IN_ADDR_NULL;
        struct ifa_cacheinfo cinfo;
        Address *address = NULL;
        char valid_buf[FORMAT_TIMESPAN_MAX];
        const char *valid_str = NULL;
        int ifindex, family, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive address message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWADDR, RTM_DELADDR)) {
                log_warning("rtnl: received unexpected message type %u when processing address, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_addr_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received address message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will get the address again, so just
                 * ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received address for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = sd_rtnl_message_addr_get_family(message, &family);
        if (r < 0 || !IN_SET(family, AF_INET, AF_INET6)) {
                log_link_warning(link, "rtnl: received address message with invalid family, ignoring.");
                return 0;
        }

        r = sd_rtnl_message_addr_get_prefixlen(message, &prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message with invalid prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_scope(message, &scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_flags(message, &flags);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message with invalid flags, ignoring: %m");
                return 0;
        }

        switch (family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, IFA_LOCAL, &in_addr.in);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address message without valid address, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, IFA_ADDRESS, &in_addr.in6);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address message without valid address, ignoring: %m");
                        return 0;
                }

                break;

        default:
                assert_not_reached("Received unsupported address family");
        }

        r = in_addr_to_string(family, &in_addr, &buf);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not print address: %m");

        r = sd_netlink_message_read_cache_info(message, IFA_CACHEINFO, &cinfo);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: cannot get IFA_CACHEINFO attribute, ignoring: %m");
                return 0;
        } else if (r >= 0 && cinfo.ifa_valid != CACHE_INFO_INFINITY_LIFE_TIME)
                valid_str = format_timespan(valid_buf, FORMAT_TIMESPAN_MAX,
                                            cinfo.ifa_valid * USEC_PER_SEC,
                                            USEC_PER_SEC);

        (void) address_get(link, family, &in_addr, prefixlen, &address);

        switch (type) {
        case RTM_NEWADDR:
                if (address)
                        log_link_debug(link, "Remembering updated address: %s/%u (valid %s%s)",
                                       strnull(buf), prefixlen,
                                       valid_str ? "for " : "forever", strempty(valid_str));
                else {
                        /* An address appeared that we did not request */
                        r = address_add_foreign(link, family, &in_addr, prefixlen, &address);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign address %s/%u, ignoring: %m",
                                                       strnull(buf), prefixlen);
                                return 0;
                        } else
                                log_link_debug(link, "Remembering foreign address: %s/%u (valid %s%s)",
                                               strnull(buf), prefixlen,
                                               valid_str ? "for " : "forever", strempty(valid_str));
                }

                /* address_update() logs internally, so we don't need to. */
                (void) address_update(address, flags, scope, &cinfo);

                break;

        case RTM_DELADDR:
                if (address) {
                        log_link_debug(link, "Forgetting address: %s/%u (valid %s%s)",
                                       strnull(buf), prefixlen,
                                       valid_str ? "for " : "forever", strempty(valid_str));
                        (void) address_drop(address);
                } else
                        log_link_info(link, "Kernel removed an address we don't remember: %s/%u (valid %s%s), ignoring.",
                                      strnull(buf), prefixlen,
                                      valid_str ? "for " : "forever", strempty(valid_str));

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
                        log_warning_errno(r, "rtnl: Could not receive link message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWLINK, RTM_DELLINK)) {
                log_warning("rtnl: Received unexpected message type %u when processing link, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &name);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Received link message without ifname, ignoring: %m");
                return 0;
        }

        (void) link_get(m, ifindex, &link);
        (void) netdev_get(m, name, &netdev);

        switch (type) {
        case RTM_NEWLINK:
                if (!link) {
                        /* link is new, so add it */
                        r = link_add(m, message, &link);
                        if (r < 0) {
                                log_warning_errno(r, "Could not process new link message, ignoring: %m");
                                return 0;
                        }
                }

                if (netdev) {
                        /* netdev exists, so make sure the ifindex matches */
                        r = netdev_set_ifindex(netdev, message);
                        if (r < 0) {
                                log_warning_errno(r, "Could not process new link message for netdev, ignoring: %m");
                                return 0;
                        }
                }

                r = link_update(link, message);
                if (r < 0) {
                        log_warning_errno(r, "Could not process link message, ignoring: %m");
                        return 0;
                }

                break;

        case RTM_DELLINK:
                link_drop(link);
                netdev_drop(netdev);

                break;

        default:
                assert_not_reached("Received link message with invalid RTNL message type.");
        }

        return 1;
}

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, void *userdata) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *tmp = NULL;
        _cleanup_free_ char *from = NULL, *to = NULL;
        RoutingPolicyRule *rule = NULL;
        const char *iif = NULL, *oif = NULL;
        Manager *m = userdata;
        unsigned flags;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: failed to receive rule message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWRULE, RTM_DELRULE)) {
                log_warning("rtnl: received unexpected message type %u when processing rule, ignoring.", type);
                return 0;
        }

        r = routing_policy_rule_new(&tmp);
        if (r < 0) {
                log_oom();
                return 0;
        }

        r = sd_rtnl_message_get_family(message, &tmp->family);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get rule family, ignoring: %m");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_debug("rtnl: received rule message with invalid family %d, ignoring.", tmp->family);
                return 0;
        }

        switch (tmp->family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, FRA_SRC, &tmp->from.in);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_src_prefixlen(message, &tmp->from_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                                return 0;
                        }
                }

                r = sd_netlink_message_read_in_addr(message, FRA_DST, &tmp->to.in);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_dst_prefixlen(message, &tmp->to_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                                return 0;
                        }
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, FRA_SRC, &tmp->from.in6);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_src_prefixlen(message, &tmp->from_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                                return 0;
                        }
                }

                r = sd_netlink_message_read_in6_addr(message, FRA_DST, &tmp->to.in6);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_dst_prefixlen(message, &tmp->to_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                                return 0;
                        }
                }

                break;

        default:
                assert_not_reached("Received rule message with unsupported address family");
        }

        if (tmp->from_prefixlen == 0 && tmp->to_prefixlen == 0)
                return 0;

        r = sd_rtnl_message_routing_policy_rule_get_flags(message, &flags);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received rule message without valid flag, ignoring: %m");
                return 0;
        }
        tmp->invert_rule = flags & FIB_RULE_INVERT;

        r = sd_netlink_message_read_u32(message, FRA_FWMARK, &tmp->fwmark);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_FWMARK attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, FRA_FWMASK, &tmp->fwmask);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_FWMASK attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, FRA_PRIORITY, &tmp->priority);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_PRIORITY attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, FRA_TABLE, &tmp->table);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_TABLE attribute, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_routing_policy_rule_get_tos(message, &tmp->tos);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get ip rule TOS, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string(message, FRA_IIFNAME, &iif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IIFNAME attribute, ignoring: %m");
                return 0;
        }
        r = free_and_strdup(&tmp->iif, iif);
        if (r < 0)
                return log_oom();

        r = sd_netlink_message_read_string(message, FRA_OIFNAME, &oif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_OIFNAME attribute, ignoring: %m");
                return 0;
        }
        r = free_and_strdup(&tmp->oif, oif);
        if (r < 0)
                return log_oom();

        r = sd_netlink_message_read_u8(message, FRA_IP_PROTO, &tmp->protocol);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IP_PROTO attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read(message, FRA_SPORT_RANGE, sizeof(tmp->sport), &tmp->sport);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SPORT_RANGE attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read(message, FRA_DPORT_RANGE, sizeof(tmp->dport), &tmp->dport);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_DPORT_RANGE attribute, ignoring: %m");
                return 0;
        }

        (void) routing_policy_rule_get(m, tmp, &rule);

        if (DEBUG_LOGGING) {
                (void) in_addr_to_string(tmp->family, &tmp->from, &from);
                (void) in_addr_to_string(tmp->family, &tmp->to, &to);
        }

        switch (type) {
        case RTM_NEWRULE:
                if (!rule) {
                        log_debug("Remembering foreign routing policy rule: %s/%u -> %s/%u, iif: %s, oif: %s, table: %u",
                                  from, tmp->from_prefixlen, to, tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                        r = routing_policy_rule_add_foreign(m, tmp, &rule);
                        if (r < 0) {
                                log_warning_errno(r, "Could not remember foreign rule, ignoring: %m");
                                return 0;
                        }
                }
                break;
        case RTM_DELRULE:
                log_debug("Forgetting routing policy rule: %s/%u -> %s/%u, iif: %s, oif: %s, table: %u",
                          from, tmp->from_prefixlen, to, tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                routing_policy_rule_free(rule);

                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
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

static int manager_connect_genl(Manager *m) {
        int r;

        assert(m);

        r = sd_genl_socket_open(&m->genl);
        if (r < 0)
                return r;

        r = sd_netlink_inc_rcvbuf(m->genl, RCVBUF_SIZE);
        if (r < 0)
                return r;

        r = sd_netlink_attach_event(m->genl, m->event, 0);
        if (r < 0)
                return r;

        return 0;
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

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, &manager_rtnl_process_link, NULL, m, "network-rtnl_process_link");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELLINK, &manager_rtnl_process_link, NULL, m, "network-rtnl_process_link");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWADDR, &manager_rtnl_process_address, NULL, m, "network-rtnl_process_address");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELADDR, &manager_rtnl_process_address, NULL, m, "network-rtnl_process_address");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWNEIGH, &manager_rtnl_process_neighbor, NULL, m, "network-rtnl_process_neighbor");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELNEIGH, &manager_rtnl_process_neighbor, NULL, m, "network-rtnl_process_neighbor");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWROUTE, &manager_rtnl_process_route, NULL, m, "network-rtnl_process_route");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELROUTE, &manager_rtnl_process_route, NULL, m, "network-rtnl_process_route");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWRULE, &manager_rtnl_process_rule, NULL, m, "network-rtnl_process_rule");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELRULE, &manager_rtnl_process_rule, NULL, m, "network-rtnl_process_rule");
        if (r < 0)
                return r;

        return 0;
}

static int ordered_set_put_in_addr_data(OrderedSet *s, const struct in_addr_data *address) {
        char *p;
        int r;

        assert(s);
        assert(address);

        r = in_addr_to_string(address->family, &address->address, &p);
        if (r < 0)
                return r;

        r = ordered_set_consume(s, p);
        if (r == -EEXIST)
                return 0;

        return r;
}

static int ordered_set_put_in_addr_datav(OrderedSet *s, const struct in_addr_data *addresses, unsigned n) {
        int r, c = 0;
        unsigned i;

        assert(s);
        assert(addresses || n == 0);

        for (i = 0; i < n; i++) {
                r = ordered_set_put_in_addr_data(s, addresses+i);
                if (r < 0)
                        return r;

                c += r;
        }

        return c;
}

static int ordered_set_put_in4_addr(OrderedSet *s, const struct in_addr *address) {
        char *p;
        int r;

        assert(s);
        assert(address);

        r = in_addr_to_string(AF_INET, (const union in_addr_union*) address, &p);
        if (r < 0)
                return r;

        r = ordered_set_consume(s, p);
        if (r == -EEXIST)
                return 0;

        return r;
}

static int ordered_set_put_in4_addrv(OrderedSet *s,
                                     const struct in_addr *addresses,
                                     size_t n,
                                     bool (*predicate)(const struct in_addr *addr)) {
        int r, c = 0;
        size_t i;

        assert(s);
        assert(n == 0 || addresses);

        for (i = 0; i < n; i++) {
                if (predicate && !predicate(&addresses[i]))
                        continue;
                r = ordered_set_put_in4_addr(s, addresses+i);
                if (r < 0)
                        return r;

                c += r;
        }

        return c;
}

static int manager_save(Manager *m) {
        _cleanup_ordered_set_free_free_ OrderedSet *dns = NULL, *ntp = NULL, *search_domains = NULL, *route_domains = NULL;
        Link *link;
        Iterator i;
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_strv_free_ char **p = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        LinkOperationalState operstate = LINK_OPERSTATE_OFF;
        LinkCarrierState carrier_state = LINK_CARRIER_STATE_OFF;
        LinkAddressState address_state = LINK_ADDRESS_STATE_OFF;
        const char *operstate_str, *carrier_state_str, *address_state_str;
        int r;

        assert(m);
        assert(m->state_file);

        /* We add all NTP and DNS server to a set, to filter out duplicates */
        dns = ordered_set_new(&string_hash_ops);
        if (!dns)
                return -ENOMEM;

        ntp = ordered_set_new(&string_hash_ops);
        if (!ntp)
                return -ENOMEM;

        search_domains = ordered_set_new(&dns_name_hash_ops);
        if (!search_domains)
                return -ENOMEM;

        route_domains = ordered_set_new(&dns_name_hash_ops);
        if (!route_domains)
                return -ENOMEM;

        HASHMAP_FOREACH(link, m->links, i) {
                if (link->flags & IFF_LOOPBACK)
                        continue;

                if (link->operstate > operstate)
                        operstate = link->operstate;

                if (link->carrier_state > carrier_state)
                        carrier_state = link->carrier_state;

                if (link->address_state > address_state)
                        address_state = link->address_state;

                if (!link->network)
                        continue;

                /* First add the static configured entries */
                r = ordered_set_put_in_addr_datav(dns, link->network->dns, link->network->n_dns);
                if (r < 0)
                        return r;

                r = ordered_set_put_strdupv(ntp, link->ntp ?: link->network->ntp);
                if (r < 0)
                        return r;

                r = ordered_set_put_string_set(search_domains, link->search_domains ?: link->network->search_domains);
                if (r < 0)
                        return r;

                r = ordered_set_put_string_set(route_domains, link->route_domains ?: link->network->route_domains);
                if (r < 0)
                        return r;

                if (!link->dhcp_lease)
                        continue;

                /* Secondly, add the entries acquired via DHCP */
                if (link->network->dhcp_use_dns) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(dns, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_ntp) {
                        const struct in_addr *addresses;

                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(ntp, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        const char *domainname;
                        char **domains = NULL;

                        OrderedSet *target_domains = (link->network->dhcp_use_domains == DHCP_USE_DOMAINS_YES) ? search_domains : route_domains;
                        r = sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname);
                        if (r >= 0) {
                                r = ordered_set_put_strdup(target_domains, domainname);
                                if (r < 0)
                                        return r;
                        } else if (r != -ENODATA)
                                return r;

                        r = sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains);
                        if (r >= 0) {
                                r = ordered_set_put_strdupv(target_domains, domains);
                                if (r < 0)
                                        return r;
                        } else if (r != -ENODATA)
                                return r;
                }
        }

        if (carrier_state >= LINK_CARRIER_STATE_ENSLAVED)
                carrier_state = LINK_CARRIER_STATE_CARRIER;

        operstate_str = link_operstate_to_string(operstate);
        assert(operstate_str);

        carrier_state_str = link_carrier_state_to_string(carrier_state);
        assert(carrier_state_str);

        address_state_str = link_address_state_to_string(address_state);
        assert(address_state_str);

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "OPER_STATE=%s\n"
                "CARRIER_STATE=%s\n"
                "ADDRESS_STATE=%s\n",
                operstate_str, carrier_state_str, address_state_str);

        ordered_set_print(f, "DNS=", dns);
        ordered_set_print(f, "NTP=", ntp);
        ordered_set_print(f, "DOMAINS=", search_domains);
        ordered_set_print(f, "ROUTE_DOMAINS=", route_domains);

        r = routing_policy_serialize_rules(m->rules, f);
        if (r < 0)
                goto fail;

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, m->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        if (m->operational_state != operstate) {
                m->operational_state = operstate;
                if (strv_extend(&p, "OperationalState") < 0)
                        log_oom();
        }

        if (m->carrier_state != carrier_state) {
                m->carrier_state = carrier_state;
                if (strv_extend(&p, "CarrierState") < 0)
                        log_oom();
        }

        if (m->address_state != address_state) {
                m->address_state = address_state;
                if (strv_extend(&p, "AddressState") < 0)
                        log_oom();
        }

        if (p) {
                r = manager_send_changed_strv(m, p);
                if (r < 0)
                        log_error_errno(r, "Could not emit changed properties: %m");
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

        assert(m);

        if (m->dirty)
                manager_save(m);

        SET_FOREACH(link, m->dirty_links, i)
                if (link_save(link) >= 0)
                        link_clean(link);

        return 1;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .speed_meter_interval_usec = SPEED_METER_DEFAULT_TIME_INTERVAL,
        };

        m->state_file = strdup("/run/systemd/netif/state");
        if (!m->state_file)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);
        (void) sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        r = sd_event_add_post(m->event, NULL, manager_dirty_handler, m);
        if (r < 0)
                return r;

        r = manager_connect_rtnl(m);
        if (r < 0)
                return r;

        r = manager_connect_genl(m);
        if (r < 0)
                return r;

        r = manager_connect_udev(m);
        if (r < 0)
                return r;

        r = sd_resolve_default(&m->resolve);
        if (r < 0)
                return r;

        r = sd_resolve_attach_event(m->resolve, m->event, 0);
        if (r < 0)
                return r;

        r = setup_default_address_pool(m);
        if (r < 0)
                return r;

        m->duid.type = DUID_TYPE_EN;

        (void) routing_policy_load_rules(m->state_file, &m->rules_saved);

        *ret = TAKE_PTR(m);

        return 0;
}

void manager_free(Manager *m) {
        struct in6_addr *a;
        AddressPool *pool;
        Link *link;

        if (!m)
                return;

        free(m->state_file);

        while ((a = hashmap_first_key(m->dhcp6_prefixes)))
                (void) dhcp6_prefix_remove(m, a);
        m->dhcp6_prefixes = hashmap_free(m->dhcp6_prefixes);

        while ((link = hashmap_steal_first(m->links))) {
                if (link->dhcp6_client)
                        (void) dhcp6_lease_pd_prefix_lost(link->dhcp6_client, link);

                (void) link_stop_clients(link, true);

                link_unref(link);
        }

        m->dirty_links = set_free_with_destructor(m->dirty_links, link_unref);
        m->links_requesting_uuid = set_free_with_destructor(m->links_requesting_uuid, link_unref);
        m->links = hashmap_free_with_destructor(m->links, link_unref);

        m->duids_requesting_uuid = set_free(m->duids_requesting_uuid);
        m->networks = ordered_hashmap_free_with_destructor(m->networks, network_unref);

        m->netdevs = hashmap_free_with_destructor(m->netdevs, netdev_unref);

        while ((pool = m->address_pools))
                address_pool_free(pool);

        /* routing_policy_rule_free() access m->rules and m->rules_foreign.
         * So, it is necessary to set NULL after the sets are freed. */
        m->rules = set_free_with_destructor(m->rules, routing_policy_rule_free);
        m->rules_foreign = set_free_with_destructor(m->rules_foreign, routing_policy_rule_free);
        set_free_with_destructor(m->rules_saved, routing_policy_rule_free);

        sd_netlink_unref(m->rtnl);
        sd_netlink_unref(m->genl);
        sd_resolve_unref(m->resolve);

        sd_event_source_unref(m->speed_meter_event_source);
        sd_event_unref(m->event);

        sd_device_monitor_unref(m->device_monitor);

        bus_verify_polkit_async_registry_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        free(m->dynamic_timezone);
        free(m->dynamic_hostname);

        free(m);
}

int manager_start(Manager *m) {
        Link *link;
        Iterator i;
        int r;

        assert(m);

        r = manager_start_speed_meter(m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize speed meter: %m");

        /* The dirty handler will deal with future serialization, but the first one
           must be done explicitly. */

        manager_save(m);

        HASHMAP_FOREACH(link, m->links, i)
                link_save(link);

        return 0;
}

int manager_load_config(Manager *m) {
        int r;

        /* update timestamp */
        paths_check_timestamp(NETWORK_DIRS, &m->network_dirs_ts_usec, true);

        r = netdev_load(m);
        if (r < 0)
                return r;

        r = network_load(m);
        if (r < 0)
                return r;

        return 0;
}

bool manager_should_reload(Manager *m) {
        return paths_check_timestamp(NETWORK_DIRS, &m->network_dirs_ts_usec, false);
}

int manager_rtnl_enumerate_links(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
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
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
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

int manager_rtnl_enumerate_neighbors(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *neigh;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_neigh(m->rtnl, &req, RTM_GETNEIGH, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (neigh = reply; neigh; neigh = sd_netlink_message_next(neigh)) {
                int k;

                m->enumerating = true;

                k = manager_rtnl_process_neighbor(m->rtnl, neigh, m);
                if (k < 0)
                        r = k;

                m->enumerating = false;
        }

        return r;
}

int manager_rtnl_enumerate_routes(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
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

int manager_rtnl_enumerate_rules(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *rule;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_routing_policy_rule(m->rtnl, &req, RTM_GETRULE, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0) {
                if (r == -EOPNOTSUPP) {
                        log_debug("FIB Rules are not supported by the kernel. Ignoring.");
                        return 0;
                }

                return r;
        }

        for (rule = reply; rule; rule = sd_netlink_message_next(rule)) {
                int k;

                m->enumerating = true;

                k = manager_rtnl_process_rule(m->rtnl, rule, m);
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

static int set_hostname_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = userdata;
        const sd_bus_error *e;

        assert(m);
        assert(manager);

        e = sd_bus_message_get_error(m);
        if (e)
                log_warning_errno(sd_bus_error_get_errno(e), "Could not set hostname: %s", e->message);

        return 1;
}

int manager_set_hostname(Manager *m, const char *hostname) {
        int r;

        log_debug("Setting transient hostname: '%s'", strna(hostname));

        if (free_and_strdup(&m->dynamic_hostname, hostname) < 0)
                return log_oom();

        if (!m->bus || sd_bus_is_ready(m->bus) <= 0) {
                log_debug("Not connected to system bus, setting hostname later.");
                return 0;
        }

        r = sd_bus_call_method_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "SetHostname",
                        set_hostname_handler,
                        m,
                        "sb",
                        hostname,
                        false);

        if (r < 0)
                return log_error_errno(r, "Could not set transient hostname: %m");

        return 0;
}

static int set_timezone_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = userdata;
        const sd_bus_error *e;

        assert(m);
        assert(manager);

        e = sd_bus_message_get_error(m);
        if (e)
                log_warning_errno(sd_bus_error_get_errno(e), "Could not set timezone: %s", e->message);

        return 1;
}

int manager_set_timezone(Manager *m, const char *tz) {
        int r;

        assert(m);
        assert(tz);

        log_debug("Setting system timezone: '%s'", tz);
        if (free_and_strdup(&m->dynamic_timezone, tz) < 0)
                return log_oom();

        if (!m->bus || sd_bus_is_ready(m->bus) <= 0) {
                log_debug("Not connected to system bus, setting timezone later.");
                return 0;
        }

        r = sd_bus_call_method_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetTimezone",
                        set_timezone_handler,
                        m,
                        "sb",
                        tz,
                        false);
        if (r < 0)
                return log_error_errno(r, "Could not set timezone: %m");

        return 0;
}

int manager_request_product_uuid(Manager *m, Link *link) {
        int r;

        assert(m);

        if (m->has_product_uuid)
                return 0;

        log_debug("Requesting product UUID");

        if (link) {
                DUID *duid;

                assert_se(duid = link_get_duid(link));

                r = set_ensure_allocated(&m->links_requesting_uuid, NULL);
                if (r < 0)
                        return log_oom();

                r = set_ensure_allocated(&m->duids_requesting_uuid, NULL);
                if (r < 0)
                        return log_oom();

                r = set_put(m->links_requesting_uuid, link);
                if (r < 0)
                        return log_oom();

                r = set_put(m->duids_requesting_uuid, duid);
                if (r < 0)
                        return log_oom();

                link_ref(link);
        }

        if (!m->bus || sd_bus_is_ready(m->bus) <= 0) {
                log_debug("Not connected to system bus, requesting product UUID later.");
                return 0;
        }

        r = sd_bus_call_method_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "GetProductUUID",
                        get_product_uuid_handler,
                        m,
                        "b",
                        false);
        if (r < 0)
                return log_warning_errno(r, "Failed to get product UUID: %m");

        return 0;
}

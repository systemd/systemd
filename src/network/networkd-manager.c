/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/fib_rules.h>
#include <linux/nexthop.h>

#include "sd-daemon.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
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
#include "networkd-address-pool.h"
#include "networkd-dhcp-server-bus.h"
#include "networkd-dhcp6.h"
#include "networkd-link-bus.h"
#include "networkd-manager-bus.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network-bus.h"
#include "networkd-nexthop.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-speed-meter.h"
#include "ordered-set.h"
#include "path-lookup.h"
#include "path-util.h"
#include "selinux-util.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"

/* use 128 MB for receive socket kernel queue. */
#define RCVBUF_SIZE    (128*1024*1024)

static int manager_reset_all(Manager *m) {
        Link *link;
        int r;

        assert(m);

        HASHMAP_FOREACH(link, m->links) {
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
                bus_log_parse_error(r);
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

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/network1/link", "org.freedesktop.network1.DHCPServer", dhcp_server_vtable, link_object_find, m);
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

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

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

        /* Ignore the "remove" uevent — let's remove a device only if rtnetlink says so. All other uevents
         * are "positive" events in some form, i.e. inform us about a changed or new network interface, that
         * still exists — and we are interested in that. */
        if (action == DEVICE_ACTION_REMOVE)
                return 0;

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0) {
                log_device_debug_errno(device, r, "Ignoring udev %s event for device without ifindex or with invalid ifindex: %m",
                                       device_action_to_string(action));
                return 0;
        }

        r = device_is_renaming(device);
        if (r < 0) {
                log_device_error_errno(device, r, "Failed to determine the device is renamed or not, ignoring '%s' uevent: %m",
                                       device_action_to_string(action));
                return 0;
        }
        if (r > 0) {
                log_device_debug(device, "Interface is under renaming, wait for the interface to be renamed.");
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

        /* udev does not initialize devices inside containers, so we rely on them being already
         * initialized before entering the container. */
        if (path_is_read_only_fs("/sys") > 0)
                return 0;

        r = sd_device_monitor_new(&m->device_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        r = sd_device_monitor_set_receive_buffer_size(m->device_monitor, RCVBUF_SIZE);
        if (r < 0)
                log_warning_errno(r, "Failed to increase buffer size for device monitor, ignoring: %m");

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

static int manager_rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
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
                        log_message_warning_errno(message, r, "rtnl: Could not receive link message, ignoring");

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
                log_warning_errno(r, "Failed to increase receive buffer size for general netlink socket, ignoring: %m");

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

        /* Bump receiver buffer, but only if we are not called via socket activation, as in that
         * case systemd sets the receive buffer size for us, and the value in the .socket unit
         * should take full effect. */
        if (fd < 0) {
                r = sd_netlink_inc_rcvbuf(m->rtnl, RCVBUF_SIZE);
                if (r < 0)
                        log_warning_errno(r, "Failed to increase receive buffer size for rtnl socket, ignoring: %m");
        }

        r = sd_netlink_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, &manager_rtnl_process_link, NULL, m, "network-rtnl_process_link");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELLINK, &manager_rtnl_process_link, NULL, m, "network-rtnl_process_link");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWADDR, &manager_rtnl_process_address, NULL, m, "network-rtnl_process_address");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELADDR, &manager_rtnl_process_address, NULL, m, "network-rtnl_process_address");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWNEIGH, &manager_rtnl_process_neighbor, NULL, m, "network-rtnl_process_neighbor");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELNEIGH, &manager_rtnl_process_neighbor, NULL, m, "network-rtnl_process_neighbor");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWROUTE, &manager_rtnl_process_route, NULL, m, "network-rtnl_process_route");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELROUTE, &manager_rtnl_process_route, NULL, m, "network-rtnl_process_route");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWRULE, &manager_rtnl_process_rule, NULL, m, "network-rtnl_process_rule");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELRULE, &manager_rtnl_process_rule, NULL, m, "network-rtnl_process_rule");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWNEXTHOP, &manager_rtnl_process_nexthop, NULL, m, "network-rtnl_process_nexthop");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELNEXTHOP, &manager_rtnl_process_nexthop, NULL, m, "network-rtnl_process_nexthop");
        if (r < 0)
                return r;

        return 0;
}

static int ordered_set_put_dns_server(OrderedSet *s, int ifindex, struct in_addr_full *dns) {
        const char *p;
        int r;

        assert(s);
        assert(dns);

        if (dns->ifindex != 0 && dns->ifindex != ifindex)
                return 0;

        p = in_addr_full_to_string(dns);
        if (!p)
                return 0;

        r = ordered_set_put_strdup(s, p);
        if (r == -EEXIST)
                return 0;

        return r;
}

static int ordered_set_put_dns_servers(OrderedSet *s, int ifindex, struct in_addr_full **dns, unsigned n) {
        int r, c = 0;
        unsigned i;

        assert(s);
        assert(dns || n == 0);

        for (i = 0; i < n; i++) {
                r = ordered_set_put_dns_server(s, ifindex, dns[i]);
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
        _cleanup_ordered_set_free_free_ OrderedSet *dns = NULL, *ntp = NULL, *sip = NULL, *search_domains = NULL, *route_domains = NULL;
        const char *operstate_str, *carrier_state_str, *address_state_str;
        LinkOperationalState operstate = LINK_OPERSTATE_OFF;
        LinkCarrierState carrier_state = LINK_CARRIER_STATE_OFF;
        LinkAddressState address_state = LINK_ADDRESS_STATE_OFF;
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_strv_free_ char **p = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        Link *link;
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

        sip = ordered_set_new(&string_hash_ops);
        if (!sip)
                return -ENOMEM;

        search_domains = ordered_set_new(&dns_name_hash_ops);
        if (!search_domains)
                return -ENOMEM;

        route_domains = ordered_set_new(&dns_name_hash_ops);
        if (!route_domains)
                return -ENOMEM;

        HASHMAP_FOREACH(link, m->links) {
                const struct in_addr *addresses;

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
                if (link->n_dns != (unsigned) -1)
                        r = ordered_set_put_dns_servers(dns, link->ifindex, link->dns, link->n_dns);
                else
                        r = ordered_set_put_dns_servers(dns, link->ifindex, link->network->dns, link->network->n_dns);
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
                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(dns, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_ntp) {
                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(ntp, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_sip) {
                        r = sd_dhcp_lease_get_sip(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(sip, addresses, r, in4_addr_is_non_local);
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
        ordered_set_print(f, "SIP=", sip);
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

        assert(m);

        if (m->dirty)
                manager_save(m);

        SET_FOREACH(link, m->dirty_links)
                (void) link_save_and_clean(link);

        return 1;
}

static int signal_terminate_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;

        assert(m);
        m->restarting = false;

        log_debug("Terminate operation initiated.");

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int signal_restart_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;

        assert(m);
        m->restarting = true;

        log_debug("Restart operation initiated.");

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .speed_meter_interval_usec = SPEED_METER_DEFAULT_TIME_INTERVAL,
                .manage_foreign_routes = true,
                .ethtool_fd = -1,
        };

        m->state_file = strdup("/run/systemd/netif/state");
        if (!m->state_file)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        assert_se(sigprocmask_many(SIG_SETMASK, NULL, SIGINT, SIGTERM, SIGUSR2, -1) >= 0);

        (void) sd_event_set_watchdog(m->event, true);
        (void) sd_event_add_signal(m->event, NULL, SIGTERM, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGUSR2, signal_restart_callback, m);

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

        r = address_pool_setup_default(m);
        if (r < 0)
                return r;

        m->duid.type = DUID_TYPE_EN;

        (void) routing_policy_load_rules(m->state_file, &m->rules_saved);

        *ret = TAKE_PTR(m);

        return 0;
}

void manager_free(Manager *m) {
        Link *link;

        if (!m)
                return;

        free(m->state_file);

        HASHMAP_FOREACH(link, m->links)
                (void) link_stop_engines(link, true);

        m->dhcp6_prefixes = hashmap_free_with_destructor(m->dhcp6_prefixes, dhcp6_pd_free);
        m->dhcp6_pd_prefixes = set_free_with_destructor(m->dhcp6_pd_prefixes, dhcp6_pd_free);

        m->dirty_links = set_free_with_destructor(m->dirty_links, link_unref);
        m->links_requesting_uuid = set_free_with_destructor(m->links_requesting_uuid, link_unref);
        m->links = hashmap_free_with_destructor(m->links, link_unref);

        m->duids_requesting_uuid = set_free(m->duids_requesting_uuid);
        m->networks = ordered_hashmap_free_with_destructor(m->networks, network_unref);

        m->netdevs = hashmap_free_with_destructor(m->netdevs, netdev_unref);

        ordered_set_free_free(m->address_pools);

        /* routing_policy_rule_free() access m->rules and m->rules_foreign.
         * So, it is necessary to set NULL after the sets are freed. */
        m->rules = set_free(m->rules);
        m->rules_foreign = set_free(m->rules_foreign);
        set_free(m->rules_saved);

        m->routes = set_free(m->routes);
        m->routes_foreign = set_free(m->routes_foreign);

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

        safe_close(m->ethtool_fd);

        free(m);
}

int manager_start(Manager *m) {
        Link *link;
        int r;

        assert(m);

        r = manager_start_speed_meter(m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize speed meter: %m");

        /* The dirty handler will deal with future serialization, but the first one
           must be done explicitly. */

        manager_save(m);

        HASHMAP_FOREACH(link, m->links)
                (void) link_save(link);

        return 0;
}

int manager_load_config(Manager *m) {
        int r;

        /* update timestamp */
        paths_check_timestamp(NETWORK_DIRS, &m->network_dirs_ts_usec, true);

        r = netdev_load(m, false);
        if (r < 0)
                return r;

        r = network_load(m, &m->networks);
        if (r < 0)
                return r;

        return 0;
}

bool manager_should_reload(Manager *m) {
        return paths_check_timestamp(NETWORK_DIRS, &m->network_dirs_ts_usec, false);
}

static int manager_enumerate_internal(
                Manager *m,
                sd_netlink_message *req,
                int (*process)(sd_netlink *, sd_netlink_message *, Manager *),
                const char *name) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        int r;

        assert(m);
        assert(m->rtnl);
        assert(req);
        assert(process);

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0) {
                if (name && (r == -EOPNOTSUPP || (r == -EINVAL && mac_selinux_enforcing()))) {
                        log_debug_errno(r, "%s are not supported by the kernel. Ignoring.", name);
                        return 0;
                }

                return r;
        }

        for (sd_netlink_message *reply_one = reply; reply_one; reply_one = sd_netlink_message_next(reply_one)) {
                int k;

                m->enumerating = true;

                k = process(m->rtnl, reply_one, m);
                if (k < 0 && r >= 0)
                        r = k;

                m->enumerating = false;
        }

        return r;
}

static int manager_enumerate_links(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_link, NULL);
}

static int manager_enumerate_addresses(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_address, NULL);
}

static int manager_enumerate_neighbors(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_neigh(m->rtnl, &req, RTM_GETNEIGH, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_neighbor, NULL);
}

static int manager_enumerate_routes(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        if (!m->manage_foreign_routes)
                return 0;

        r = sd_rtnl_message_new_route(m->rtnl, &req, RTM_GETROUTE, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_route, NULL);
}

static int manager_enumerate_rules(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_routing_policy_rule(m->rtnl, &req, RTM_GETRULE, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_rule, "Routing policy rules");
}

static int manager_enumerate_nexthop(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_nexthop(m->rtnl, &req, RTM_GETNEXTHOP, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, req, manager_rtnl_process_nexthop, "Nexthop rules");
}

int manager_enumerate(Manager *m) {
        int r;

        r = manager_enumerate_links(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate links: %m");

        r = manager_enumerate_addresses(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate addresses: %m");

        r = manager_enumerate_neighbors(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate neighbors: %m");

        r = manager_enumerate_routes(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routes: %m");

        r = manager_enumerate_rules(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routing policy rules: %m");

        r = manager_enumerate_nexthop(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate nexthop rules: %m");

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
        _unused_ Manager *manager = userdata;
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
        _unused_ Manager *manager = userdata;
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

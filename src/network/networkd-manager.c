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
#include "bus-error.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "conf-parser.h"
#include "def.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "firewall-util.h"
#include "fs-util.h"
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
#include "networkd-state-file.h"
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

static int systemd_netlink_fd(void) {
        int n, fd, rtnl_fd = -EINVAL;

        n = sd_listen_fds(true);
        if (n <= 0)
                return -EINVAL;

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd ++)
                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {
                        if (rtnl_fd >= 0)
                                return -EINVAL;

                        rtnl_fd = fd;
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

static int manager_dirty_handler(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Link *link;
        int r;

        assert(m);

        if (m->dirty) {
                r = manager_save(m);
                if (r < 0)
                        log_warning_errno(r, "Failed to update state file %s, ignoring: %m", m->state_file);
        }

        SET_FOREACH(link, m->dirty_links) {
                r = link_save_and_clean(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to update link state file %s, ignoring: %m", link->state_file);
        }

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

        *ret = TAKE_PTR(m);

        return 0;
}

Manager* manager_free(Manager *m) {
        Link *link;

        if (!m)
                return NULL;

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

        hashmap_free(m->route_table_names_by_number);
        hashmap_free(m->route_table_numbers_by_name);

        /* routing_policy_rule_free() access m->rules and m->rules_foreign.
         * So, it is necessary to set NULL after the sets are freed. */
        m->rules = set_free(m->rules);
        m->rules_foreign = set_free(m->rules_foreign);

        sd_netlink_unref(m->rtnl);
        sd_netlink_unref(m->genl);
        sd_resolve_unref(m->resolve);

        /* reject (e.g. unreachable) type routes are managed by Manager, but may be referenced by a
         * link. E.g., DHCP6 with prefix delegation creates unreachable routes, and they are referenced
         * by the upstream link. And the links may be referenced by netlink slots. Hence, two
         * set_free() must be called after the above sd_netlink_unref(). */
        m->routes = set_free(m->routes);
        m->routes_foreign = set_free(m->routes_foreign);

        m->nexthops = set_free(m->nexthops);
        m->nexthops_foreign = set_free(m->nexthops_foreign);
        m->nexthops_by_id = hashmap_free(m->nexthops_by_id);

        sd_event_source_unref(m->speed_meter_event_source);
        sd_event_unref(m->event);

        sd_device_monitor_unref(m->device_monitor);

        bus_verify_polkit_async_registry_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        free(m->dynamic_timezone);
        free(m->dynamic_hostname);

        safe_close(m->ethtool_fd);

        m->fw_ctx = fw_ctx_free(m->fw_ctx);

        return mfree(m);
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

        r = manager_save(m);
        if (r < 0)
                log_warning_errno(r, "Failed to update state file %s, ignoring: %m", m->state_file);

        HASHMAP_FOREACH(link, m->links) {
                r = link_save(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to update link state file %s, ignoring: %m", link->state_file);
        }

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

        r = manager_enumerate_nexthop(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate nexthop rules: %m");

        r = manager_enumerate_routes(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routes: %m");

        r = manager_enumerate_rules(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routing policy rules: %m");

        return 0;
}

Link* manager_find_uplink(Manager *m, Link *exclude) {
        _cleanup_free_ struct local_address *gateways = NULL;
        int n;

        assert(m);

        /* Looks for a suitable "uplink", via black magic: an
         * interface that is up and where the default route with the
         * highest priority points to. */

        n = local_gateways(m->rtnl, 0, AF_UNSPEC, &gateways);
        if (n < 0) {
                log_warning_errno(n, "Failed to determine list of default gateways: %m");
                return NULL;
        }

        for (int i = 0; i < n; i++) {
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

static int set_hostname_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        const sd_bus_error *e;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "Could not set hostname: %s", bus_error_message(e, r));
        }

        return 1;
}

int manager_set_hostname(Manager *m, const char *hostname) {
        int r;

        log_debug("Setting transient hostname: '%s'", strna(hostname));

        r = free_and_strdup_warn(&m->dynamic_hostname, hostname);
        if (r < 0)
                return r;

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
        const sd_bus_error *e;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "Could not set timezone: %s", bus_error_message(e, r));
        }

        return 1;
}

int manager_set_timezone(Manager *m, const char *tz) {
        int r;

        assert(m);
        assert(tz);

        log_debug("Setting system timezone: '%s'", tz);
        r = free_and_strdup_warn(&m->dynamic_timezone, tz);
        if (r < 0)
                return r;

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

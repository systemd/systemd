/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/filter.h>
#include <linux/nl80211.h>
#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-netlink.h"
#include "sd-resolve.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-util.h"
#include "capability-util.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "device-private.h"
#include "device-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "firewall-util.h"
#include "initrd-util.h"
#include "mount-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-address-label.h"
#include "networkd-address-pool.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-manager-bus.h"
#include "networkd-manager-varlink.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-serialize.h"
#include "networkd-speed-meter.h"
#include "networkd-state-file.h"
#include "networkd-wifi.h"
#include "networkd-wiphy.h"
#include "ordered-set.h"
#include "qdisc.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tclass.h"
#include "tuntap.h"
#include "udev-util.h"

/* use 128 MB for receive socket kernel queue. */
#define RCVBUF_SIZE    (128*1024*1024)

static int match_prepare_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = ASSERT_PTR(userdata);
        Link *link;
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (b)
                return 0;

        log_debug("Coming back from suspend, reconfiguring all connections...");

        HASHMAP_FOREACH(link, m->links_by_index)
                (void) link_reconfigure(link, LINK_RECONFIGURE_UNCONDITIONALLY);

        return 0;
}

static int on_connected(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(message);

        /* Did we get a timezone or transient hostname from DHCP while D-Bus wasn't up yet? */
        if (m->dynamic_hostname)
                (void) manager_set_hostname(m, m->dynamic_hostname);
        if (m->dynamic_timezone)
                (void) manager_set_timezone(m, m->dynamic_timezone);
        if (m->product_uuid_requested)
                (void) manager_request_product_uuid(m);

        return 0;
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-network");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

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

        r = bus_match_signal_async(
                        m->bus,
                        NULL,
                        bus_login_mgr,
                        "PrepareForSleep",
                        match_prepare_for_sleep, NULL, m);
        if (r < 0)
                log_warning_errno(r, "Failed to request match for PrepareForSleep, ignoring: %m");

        return 0;
}

static int manager_process_uevent(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        int r;

        assert(device);

        r = sd_device_get_action(device, &action);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to get udev action, ignoring: %m");

        if (device_in_subsystem(device, "net") > 0)
                r = manager_udev_process_link(m, device, action);
        else if (device_in_subsystem(device, "ieee80211") > 0)
                r = manager_udev_process_wiphy(m, device, action);
        else if (device_in_subsystem(device, "rfkill") > 0)
                r = manager_udev_process_rfkill(m, device, action);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process \"%s\" uevent, ignoring: %m",
                                         device_action_to_string(action));

        return 0;
}

static int manager_connect_udev(Manager *m) {
        int r;

        /* udev does not initialize devices inside containers, so we rely on them being already
         * initialized before entering the container. */
        if (!udev_available())
                return 0;

        r = sd_device_monitor_new(&m->device_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, "net", NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add device monitor filter for net subsystem: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, "ieee80211", NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add device monitor filter for ieee80211 subsystem: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, "rfkill", NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add device monitor filter for rfkill subsystem: %m");

        r = sd_device_monitor_attach_event(m->device_monitor, m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(m->device_monitor, manager_process_uevent, m);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        return 0;
}

static int manager_listen_fds(Manager *m, int *ret_rtnl_fd) {
        _cleanup_strv_free_ char **names = NULL;
        int n, rtnl_fd = -EBADF;

        assert(m);
        assert(ret_rtnl_fd);

        n = sd_listen_fds_with_names(/* unset_environment = */ true, &names);
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
                int fd = i + SD_LISTEN_FDS_START;

                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {
                        if (rtnl_fd >= 0) {
                                log_debug("Received multiple netlink socket, ignoring.");
                                goto unused;
                        }

                        rtnl_fd = fd;
                        continue;
                }

                if (manager_set_serialization_fd(m, fd, names[i]) >= 0)
                        continue;

                if (manager_add_tuntap_fd(m, fd, names[i]) >= 0)
                        continue;

        unused:
                if (m->test_mode)
                        safe_close(fd);
                else
                        close_and_notify_warn(fd, names[i]);
        }

        *ret_rtnl_fd = rtnl_fd;
        return 0;
}

static int manager_connect_genl(Manager *m) {
        int r;

        assert(m);

        r = sd_genl_socket_open(&m->genl);
        if (r < 0)
                return r;

        r = sd_netlink_increase_rxbuf(m->genl, RCVBUF_SIZE);
        if (r < 0)
                log_warning_errno(r, "Failed to increase receive buffer size for general netlink socket, ignoring: %m");

        r = sd_netlink_attach_event(m->genl, m->event, 0);
        if (r < 0)
                return r;

        /* If the kernel is built without CONFIG_WIRELESS, the below will fail with -EOPNOTSUPP. */
        r = genl_add_match(m->genl, NULL, NL80211_GENL_NAME, NL80211_MULTICAST_GROUP_CONFIG, 0,
                           &manager_genl_process_nl80211_config, NULL, m, "network-genl_process_nl80211_config");
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        r = genl_add_match(m->genl, NULL, NL80211_GENL_NAME, NL80211_MULTICAST_GROUP_MLME, 0,
                           &manager_genl_process_nl80211_mlme, NULL, m, "network-genl_process_nl80211_mlme");
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        return 0;
}

static int manager_setup_rtnl_filter(Manager *manager) {
        struct sock_filter filter[] = {
                /* Check the packet length. */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                      /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct nlmsghdr), 1, 0),         /* A (packet length) >= sizeof(struct nlmsghdr) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* reject */
                /* Always accept multipart message. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct nlmsghdr, nlmsg_flags)), /* A <- message flags */
                BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, htobe16(NLM_F_MULTI), 0, 1),           /* message flags has NLM_F_MULTI ? */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                      /* accept */
                /* Accept all message types except for RTM_NEWNEIGH or RTM_DELNEIGH. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct nlmsghdr, nlmsg_type)),  /* A <- message type */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, htobe16(RTM_NEWNEIGH), 2, 0),           /* message type == RTM_NEWNEIGH ? */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, htobe16(RTM_DELNEIGH), 1, 0),           /* message type == RTM_DELNEIGH ? */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                      /* accept */
                /* Check the packet length. */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                      /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct nlmsghdr) + sizeof(struct ndmsg), 1, 0),
                                                                                            /* packet length >= sizeof(struct nlmsghdr) + sizeof(struct ndmsg) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* reject */
                /* Reject the message when the neighbor state does not have NUD_PERMANENT flag. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, sizeof(struct nlmsghdr) + offsetof(struct ndmsg, ndm_state)),
                                                                                            /* A <- neighbor state */
                BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, htobe16(NUD_PERMANENT), 1, 0),         /* neighbor state has NUD_PERMANENT ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* reject */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                      /* accept */
        };

        assert(manager);
        assert(manager->rtnl);

        return sd_netlink_attach_filter(manager->rtnl, ELEMENTSOF(filter), filter);
}

static int manager_connect_rtnl(Manager *m, int fd) {
        _unused_ _cleanup_close_ int fd_close = fd;
        int r;

        assert(m);

        /* This takes input fd. */

        if (fd < 0)
                r = sd_netlink_open(&m->rtnl);
        else
                r = sd_netlink_open_fd(&m->rtnl, fd);
        if (r < 0)
                return r;
        TAKE_FD(fd_close);

        /* Bump receiver buffer, but only if we are not called via socket activation, as in that
         * case systemd sets the receive buffer size for us, and the value in the .socket unit
         * should take full effect. */
        if (fd < 0) {
                r = sd_netlink_increase_rxbuf(m->rtnl, RCVBUF_SIZE);
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

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWQDISC, &manager_rtnl_process_qdisc, NULL, m, "network-rtnl_process_qdisc");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELQDISC, &manager_rtnl_process_qdisc, NULL, m, "network-rtnl_process_qdisc");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWTCLASS, &manager_rtnl_process_tclass, NULL, m, "network-rtnl_process_tclass");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELTCLASS, &manager_rtnl_process_tclass, NULL, m, "network-rtnl_process_tclass");
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

        return manager_setup_rtnl_filter(m);
}

static int manager_post_handler(sd_event_source *s, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        /* To release dynamic leases, we need to process queued remove requests before stopping networkd.
         * This is especially important when KeepConfiguration=no. See issue #34837. */
        (void) manager_process_remove_requests(manager);

        switch (manager->state) {
        case MANAGER_RUNNING:
                (void) manager_process_requests(manager);
                (void) manager_clean_all(manager);
                return 0;

        case MANAGER_TERMINATING:
        case MANAGER_RESTARTING:
                if (!ordered_set_isempty(manager->remove_request_queue))
                        return 0; /* There are some unissued remove requests. */

                if (netlink_get_reply_callback_count(manager->rtnl) > 0 ||
                    netlink_get_reply_callback_count(manager->genl) > 0 ||
                    fw_ctx_get_reply_callback_count(manager->fw_ctx) > 0)
                        return 0; /* There are some message calls waiting for their replies. */

                (void) manager_serialize(manager);
                manager->state = MANAGER_STOPPED;
                return sd_event_exit(sd_event_source_get_event(s), 0);

        default:
                assert_not_reached();
        }

        return 0;
}

static int manager_stop(Manager *manager, ManagerState state) {
        assert(manager);
        assert(IN_SET(state, MANAGER_TERMINATING, MANAGER_RESTARTING));

        if (manager->state != MANAGER_RUNNING) {
                log_debug("Already terminating or restarting systemd-networkd, refusing further operation request.");
                return 0;
        }

        switch (state) {
        case MANAGER_TERMINATING:
                log_debug("Terminate operation initiated.");
                break;
        case MANAGER_RESTARTING:
                log_debug("Restart operation initiated.");
                break;
        default:
                assert_not_reached();
        }

        manager->state = state;

        Link *link;
        HASHMAP_FOREACH(link, manager->links_by_index)
                (void) link_stop_engines(link, /* may_keep_dynamic = */ true);

        return 0;
}

static int signal_terminate_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        return manager_stop(userdata, MANAGER_TERMINATING);
}

static int signal_restart_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        return manager_stop(userdata, MANAGER_RESTARTING);
}

static int signal_reload_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) manager_reload(m, /* message = */ NULL);

        return 0;
}

static int manager_set_keep_configuration(Manager *m) {
        int r;

        assert(m);

        if (in_initrd()) {
                log_debug("Running in initrd, keep dynamically assigned configurations on stopping networkd by default.");
                m->keep_configuration = KEEP_CONFIGURATION_DYNAMIC_ON_STOP;
                return 0;
        }

        r = path_is_network_fs_harder("/");
        if (r < 0) {
                log_warning_errno(r, "Failed to detect if root is network filesystem, assuming not: %m");
                return 0;
        }
        if (r == 0) {
                m->keep_configuration = _KEEP_CONFIGURATION_INVALID;
                return 0;
        }

        log_debug("Running on network filesystem, enabling KeepConfiguration= by default.");
        m->keep_configuration = KEEP_CONFIGURATION_YES;
        return 0;
}

int manager_setup(Manager *m) {
        _cleanup_close_ int rtnl_fd = -EBADF;
        int r;

        assert(m);

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);
        (void) sd_event_add_signal(m->event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGUSR2 | SD_EVENT_SIGNAL_PROCMASK, signal_restart_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, signal_reload_callback, m);
        (void) sd_event_add_signal(m->event, NULL, (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, NULL);

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        r = sd_event_add_post(m->event, NULL, manager_post_handler, m);
        if (r < 0)
                return r;

        r = manager_listen_fds(m, &rtnl_fd);
        if (r < 0)
                return r;

        r = manager_connect_rtnl(m, TAKE_FD(rtnl_fd));
        if (r < 0)
                return r;

        r = manager_connect_genl(m);
        if (r < 0)
                return r;

        if (m->test_mode)
                return 0;

        r = manager_connect_varlink(m);
        if (r < 0)
                return r;

        r = manager_connect_bus(m);
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

        r = manager_set_keep_configuration(m);
        if (r < 0)
                return r;

        m->state_file = strdup("/run/systemd/netif/state");
        if (!m->state_file)
                return -ENOMEM;

        return 0;
}

static int persistent_storage_open(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = getenv_bool("SYSTEMD_NETWORK_PERSISTENT_STORAGE_READY");
        if (r < 0 && r != -ENXIO)
                return log_debug_errno(r, "Failed to parse $SYSTEMD_NETWORK_PERSISTENT_STORAGE_READY environment variable, ignoring: %m");
        if (r <= 0)
                return -EBADF;

        fd = open("/var/lib/systemd/network/", O_CLOEXEC | O_DIRECTORY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s, ignoring: %m", "/var/lib/systemd/network/");

        r = fd_is_read_only_fs(fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if /var/lib/systemd/network/ is writable: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EROFS), "The directory /var/lib/systemd/network/ is on read-only filesystem.");

        return TAKE_FD(fd);
}

int manager_new(Manager **ret, bool test_mode) {
        _cleanup_(manager_freep) Manager *m = NULL;

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .keep_configuration = _KEEP_CONFIGURATION_INVALID,
                .ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_NO,
                .test_mode = test_mode,
                .speed_meter_interval_usec = SPEED_METER_DEFAULT_TIME_INTERVAL,
                .online_state = _LINK_ONLINE_STATE_INVALID,
                .manage_foreign_routes = true,
                .manage_foreign_rules = true,
                .manage_foreign_nexthops = true,
                .ethtool_fd = -EBADF,
                .persistent_storage_fd = persistent_storage_open(),
                .dhcp_use_domains = _USE_DOMAINS_INVALID,
                .dhcp6_use_domains = _USE_DOMAINS_INVALID,
                .ndisc_use_domains = _USE_DOMAINS_INVALID,
                .dhcp_client_identifier = DHCP_CLIENT_ID_DUID,
                .dhcp_duid.type = DUID_TYPE_EN,
                .dhcp6_duid.type = DUID_TYPE_EN,
                .duid_product_uuid.type = DUID_TYPE_UUID,
                .dhcp_server_persist_leases = true,
                .serialization_fd = -EBADF,
                .ip_forwarding = { -1, -1, },
#if HAVE_VMLINUX_H
                .cgroup_fd = -EBADF,
#endif
        };

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        manager_remove_sysctl_monitor(m);

        free(m->state_file);

        m->request_queue = ordered_set_free(m->request_queue);
        m->remove_request_queue = ordered_set_free(m->remove_request_queue);

        m->new_wlan_ifindices = set_free(m->new_wlan_ifindices);

        m->dirty_links = set_free(m->dirty_links);
        m->links_by_name = hashmap_free(m->links_by_name);
        m->links_by_hw_addr = hashmap_free(m->links_by_hw_addr);
        m->links_by_dhcp_pd_subnet_prefix = hashmap_free(m->links_by_dhcp_pd_subnet_prefix);
        m->links_by_index = hashmap_free(m->links_by_index);

        m->dhcp_pd_subnet_ids = set_free(m->dhcp_pd_subnet_ids);
        m->networks = ordered_hashmap_free(m->networks);

        /* The same object may be registered with multiple names, and netdev_detach() may drop multiple entries. */
        for (NetDev *n; (n = hashmap_first(m->netdevs)); )
                netdev_detach(n);
        m->netdevs = hashmap_free(m->netdevs);

        m->tuntap_fds_by_name = hashmap_free(m->tuntap_fds_by_name);

        m->wiphy_by_name = hashmap_free(m->wiphy_by_name);
        m->wiphy_by_index = hashmap_free(m->wiphy_by_index);

        ordered_set_free(m->address_pools);

        hashmap_free(m->route_table_names_by_number);
        hashmap_free(m->route_table_numbers_by_name);

        set_free(m->rules);

        sd_netlink_unref(m->rtnl);
        sd_netlink_unref(m->genl);
        sd_resolve_unref(m->resolve);

        m->routes = set_free(m->routes);

        m->nexthops_by_id = hashmap_free(m->nexthops_by_id);
        m->nexthop_ids = set_free(m->nexthop_ids);

        m->address_labels_by_section = hashmap_free(m->address_labels_by_section);

        sd_event_source_unref(m->speed_meter_event_source);
        sd_event_unref(m->event);

        sd_device_monitor_unref(m->device_monitor);

        manager_varlink_done(m);
        hashmap_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        free(m->dynamic_timezone);
        free(m->dynamic_hostname);

        safe_close(m->ethtool_fd);
        safe_close(m->persistent_storage_fd);

        m->fw_ctx = fw_ctx_free(m->fw_ctx);

        m->serialization_fd = safe_close(m->serialization_fd);

        return mfree(m);
}

int manager_start(Manager *m) {
        Link *link;
        int r;

        assert(m);

        log_debug("Starting...");

        (void) manager_install_sysctl_monitor(m);

        /* Loading BPF programs requires CAP_SYS_ADMIN and CAP_BPF.
         * Drop the capabilities here, regardless if the load succeeds or not. */
        r = drop_capability(CAP_SYS_ADMIN);
        if (r < 0)
                log_warning_errno(r, "Failed to drop CAP_SYS_ADMIN, ignoring: %m.");

        r = drop_capability(CAP_BPF);
        if (r < 0)
                log_warning_errno(r, "Failed to drop CAP_BPF, ignoring: %m.");

        manager_set_sysctl(m);

        r = manager_request_static_address_labels(m);
        if (r < 0)
                return r;

        r = manager_start_speed_meter(m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize speed meter: %m");

        HASHMAP_FOREACH(link, m->links_by_index) {
                if (link->state != LINK_STATE_PENDING)
                        continue;

                r = link_check_initialized(link);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to check if link is initialized: %m");
                        link_enter_failed(link);
                }
        }

        /* The dirty handler will deal with future serialization, but the first one
           must be done explicitly. */

        r = manager_save(m);
        if (r < 0)
                log_warning_errno(r, "Failed to update state file %s, ignoring: %m", m->state_file);

        HASHMAP_FOREACH(link, m->links_by_index) {
                r = link_save_and_clean(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to update link state file %s, ignoring: %m", link->state_file);
        }

        log_debug("Started.");
        return 0;
}

int manager_load_config(Manager *m) {
        int r;

        log_debug("Loading...");

        r = netdev_load(m);
        if (r < 0)
                return log_debug_errno(r, "Failed to load .netdev files: %m");

        manager_clear_unmanaged_tuntap_fds(m);

        r = network_load(m, &m->networks);
        if (r < 0)
                return log_debug_errno(r, "Failed to load .network files: %m");

        r = manager_build_dhcp_pd_subnet_ids(m);
        if (r < 0)
                return log_debug_errno(r, "Failed to build DHCP-PD subnet ID map: %m");

        r = manager_build_nexthop_ids(m);
        if (r < 0)
                return log_debug_errno(r, "Failed to build nexthop ID map: %m");

        log_debug("Loaded.");
        return 0;
}

int manager_enumerate_internal(
                Manager *m,
                sd_netlink *nl,
                sd_netlink_message *req,
                int (*process)(sd_netlink *, sd_netlink_message *, Manager *)) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        int r;

        assert(m);
        assert(nl);
        assert(req);
        assert(process);

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        m->enumerating = true;
        for (sd_netlink_message *reply_one = reply; reply_one; reply_one = sd_netlink_message_next(reply_one))
                RET_GATHER(r, process(nl, reply_one, m));
        m->enumerating = false;

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

        r = manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_link);
        if (r < 0)
                return r;

        req = sd_netlink_message_unref(req);

        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_family(req, AF_BRIDGE);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_link);
}

static int manager_enumerate_qdisc(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_traffic_control(m->rtnl, &req, RTM_GETQDISC, 0, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_qdisc);
}

static int manager_enumerate_tclass(Manager *m) {
        Link *link;
        int r = 0;

        assert(m);
        assert(m->rtnl);

        /* TC class can be enumerated only per link. See tc_dump_tclass() in net/sched/sched_api.c. */

        HASHMAP_FOREACH(link, m->links_by_index)
                RET_GATHER(r, link_enumerate_tclass(link, 0));

        return r;
}

static int manager_enumerate_addresses(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_address);
}

static int manager_enumerate_neighbors(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_neigh(m->rtnl, &req, RTM_GETNEIGH, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_neighbor);
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

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_route);
}

static int manager_enumerate_rules(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        if (!m->manage_foreign_rules)
                return 0;

        r = sd_rtnl_message_new_routing_policy_rule(m->rtnl, &req, RTM_GETRULE, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_rule);
}

static int manager_enumerate_nexthop(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        if (!m->manage_foreign_nexthops)
                return 0;

        r = sd_rtnl_message_new_nexthop(m->rtnl, &req, RTM_GETNEXTHOP, 0, 0);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->rtnl, req, manager_rtnl_process_nexthop);
}

static int manager_enumerate_nl80211_wiphy(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->genl);

        r = sd_genl_message_new(m->genl, NL80211_GENL_NAME, NL80211_CMD_GET_WIPHY, &req);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->genl, req, manager_genl_process_nl80211_wiphy);
}

static int manager_enumerate_nl80211_config(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->genl);

        r = sd_genl_message_new(m->genl, NL80211_GENL_NAME, NL80211_CMD_GET_INTERFACE, &req);
        if (r < 0)
                return r;

        return manager_enumerate_internal(m, m->genl, req, manager_genl_process_nl80211_config);
}

static int manager_enumerate_nl80211_mlme(Manager *m) {
        Link *link;
        int r;

        assert(m);
        assert(m->genl);

        HASHMAP_FOREACH(link, m->links_by_index) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;

                if (link->wlan_iftype != NL80211_IFTYPE_STATION)
                        continue;

                r = sd_genl_message_new(m->genl, NL80211_GENL_NAME, NL80211_CMD_GET_STATION, &req);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u32(req, NL80211_ATTR_IFINDEX, link->ifindex);
                if (r < 0)
                        return r;

                r = manager_enumerate_internal(m, m->genl, req, manager_genl_process_nl80211_mlme);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_enumerate(Manager *m) {
        int r;

        log_debug("Enumerating...");

        r = manager_enumerate_links(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate links: %m");

        /* If the kernel is built without CONFIG_NET_SCHED, the below will fail with -EOPNOTSUPP. */
        r = manager_enumerate_qdisc(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate QDiscs, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate QDisc: %m");

        /* If the kernel is built without CONFIG_NET_CLS, the below will fail with -EOPNOTSUPP. */
        r = manager_enumerate_tclass(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate TClasses, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate TClass: %m");

        r = manager_enumerate_addresses(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate addresses: %m");

        r = manager_enumerate_neighbors(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate neighbors: %m");

        r = manager_enumerate_nexthop(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate nexthops: %m");

        r = manager_enumerate_routes(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routes: %m");

        /* If the kernel is built without CONFIG_FIB_RULES, the below will fail with -EOPNOTSUPP. */
        r = manager_enumerate_rules(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate routing policy rules, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate routing policy rules: %m");

        /* If the kernel is built without CONFIG_WIRELESS, the below will fail with -EOPNOTSUPP. */
        r = manager_enumerate_nl80211_wiphy(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate wireless LAN phy, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate wireless LAN phy: %m");

        r = manager_enumerate_nl80211_config(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate wireless LAN interfaces, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate wireless LAN interfaces: %m");

        r = manager_enumerate_nl80211_mlme(m);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Could not enumerate wireless LAN stations, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Could not enumerate wireless LAN stations: %m");

        log_debug("Enumeration completed.");
        return 0;
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

        if (sd_bus_is_ready(m->bus) <= 0) {
                log_debug("Not connected to system bus, setting system hostname later.");
                return 0;
        }

        r = bus_call_method_async(
                        m->bus,
                        NULL,
                        bus_hostname,
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

        if (sd_bus_is_ready(m->bus) <= 0) {
                log_debug("Not connected to system bus, setting system timezone later.");
                return 0;
        }

        r = bus_call_method_async(
                        m->bus,
                        NULL,
                        bus_timedate,
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

int manager_reload(Manager *m, sd_bus_message *message) {
        Link *link;
        int r;

        assert(m);

        log_debug("Reloading...");
        (void) notify_reloading();

        r = netdev_reload(m);
        if (r < 0) {
                log_debug_errno(r, "Failed to reload .netdev files: %m");
                goto finish;
        }

        r = network_reload(m);
        if (r < 0) {
                log_debug_errno(r, "Failed to reload .network files: %m");
                goto finish;
        }

        HASHMAP_FOREACH(link, m->links_by_index)
                (void) link_reconfigure_full(link, /* flags = */ 0, message,
                                             /* counter = */ message ? &m->reloading : NULL);

        log_debug("Reloaded.");
        r = 0;
finish:
        (void) sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        return r;
}

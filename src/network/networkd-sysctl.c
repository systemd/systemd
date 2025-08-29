/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "sd-messages.h"

#include "af-list.h"
#include "conf-parser.h"
#include "alloc-util.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-network.h"
#include "networkd-sysctl.h"
#include "path-util.h"
#include "set.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "sysctl-util.h"

#if ENABLE_SYSCTL_BPF

#include "bpf-link.h"
#include "bpf/sysctl-monitor/sysctl-monitor-skel.h"
#include "bpf/sysctl-monitor/sysctl-write-event.h"

static struct sysctl_monitor_bpf* sysctl_monitor_bpf_free(struct sysctl_monitor_bpf *obj) {
        sysctl_monitor_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct sysctl_monitor_bpf *, sysctl_monitor_bpf_free);

static int sysctl_event_handler(void *ctx, void *data, size_t data_sz) {
        struct sysctl_write_event *we = ASSERT_PTR(data);
        Hashmap **sysctl_shadow = ASSERT_PTR(ctx);
        _cleanup_free_ char *path = NULL;
        char *value;

        /* Returning a negative value interrupts the ring buffer polling,
         * so do it only in case of a fatal error like a version mismatch. */
        if (we->version != 1)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Unexpected sysctl event, disabling sysctl monitoring: %d", we->version);

        if (we->errorcode != 0) {
                log_warning_errno(we->errorcode, "Sysctl monitor BPF returned error: %m");
                return 0;
        }

        path = path_join("/proc/sys", we->path);
        if (!path) {
                log_oom_warning();
                return 0;
        }

        /* If we never managed this handle, ignore it. */
        value = hashmap_get(*sysctl_shadow, path);
        if (!value)
                return 0;

        if (!strneq(value, we->newvalue, sizeof(we->newvalue)))
                log_struct(LOG_WARNING,
                           LOG_MESSAGE_ID(SD_MESSAGE_SYSCTL_CHANGED_STR),
                           LOG_ITEM("OBJECT_PID=" PID_FMT, we->pid),
                           LOG_ITEM("OBJECT_COMM=%s", we->comm),
                           LOG_ITEM("SYSCTL=%s", path),
                           LOG_ITEM("OLDVALUE=%s", we->current),
                           LOG_ITEM("NEWVALUE=%s", we->newvalue),
                           LOG_ITEM("OURVALUE=%s", value),
                           LOG_MESSAGE("Foreign process '%s[" PID_FMT "]' changed sysctl '%s' from '%s' to '%s', conflicting with our setting to '%s'.",
                                       we->comm, we->pid, path, we->current, we->newvalue, value));

        return 0;
}

static int on_ringbuf_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct ring_buffer *rb = ASSERT_PTR(userdata);
        int r;

        r = sym_ring_buffer__poll(rb, /* timeout_msec= */ 0);
        if (r < 0 && errno != EINTR)
                log_error_errno(errno, "Error polling ring buffer: %m");

        return 0;
}

int manager_install_sysctl_monitor(Manager *manager) {
        _cleanup_(sysctl_monitor_bpf_freep) struct sysctl_monitor_bpf *obj = NULL;
        _cleanup_(bpf_link_freep) struct bpf_link *sysctl_link = NULL;
        _cleanup_(bpf_ring_buffer_freep) struct ring_buffer *sysctl_buffer = NULL;
        _cleanup_close_ int cgroup_fd = -EBADF, root_cgroup_fd = -EBADF;
        _cleanup_free_ char *cgroup = NULL;
        int idx = 0, r, fd;

        assert(manager);

        r = dlopen_bpf();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return log_debug_errno(r, "sysctl monitor disabled, as BPF support is not available.");
        if (r < 0)
                return log_warning_errno(r, "Failed to load libbpf, not installing sysctl monitor: %m");

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        if (r < 0)
                return log_warning_errno(r, "Failed to get cgroup path, ignoring: %m.");

        root_cgroup_fd = cg_path_open("/");
        if (root_cgroup_fd < 0)
                return log_warning_errno(root_cgroup_fd, "Failed to open cgroup, ignoring: %m");

        obj = sysctl_monitor_bpf__open_and_load();
        if (!obj)
                return log_full_errno(errno == EINVAL ? LOG_DEBUG : LOG_INFO, errno,
                                      "Unable to load sysctl monitor BPF program, ignoring: %m");

        cgroup_fd = cg_path_open(cgroup);
        if (cgroup_fd < 0)
                return log_warning_errno(cgroup_fd, "Failed to open cgroup: %m");

        if (sym_bpf_map_update_elem(sym_bpf_map__fd(obj->maps.cgroup_map), &idx, &cgroup_fd, BPF_ANY))
                return log_warning_errno(errno, "Failed to update cgroup map: %m");

        sysctl_link = sym_bpf_program__attach_cgroup(obj->progs.sysctl_monitor, root_cgroup_fd);
        r = bpf_get_error_translated(sysctl_link);
        if (r < 0)
                return log_warning_errno(r, "Unable to attach sysctl monitor BPF program to cgroup, ignoring: %m");

        fd = sym_bpf_map__fd(obj->maps.written_sysctls);
        if (fd < 0)
                return log_warning_errno(fd, "Failed to get fd of sysctl maps: %m");

        sysctl_buffer = sym_ring_buffer__new(fd, sysctl_event_handler, &manager->sysctl_shadow, NULL);
        if (!sysctl_buffer)
                return log_warning_errno(errno, "Failed to create ring buffer: %m");

        fd = sym_ring_buffer__epoll_fd(sysctl_buffer);
        if (fd < 0)
                return log_warning_errno(fd, "Failed to get poll fd of ring buffer: %m");

        r = sd_event_add_io(manager->event, &manager->sysctl_event_source,
                            fd, EPOLLIN, on_ringbuf_io, sysctl_buffer);
        if (r < 0)
                return log_warning_errno(r, "Failed to watch sysctl event ringbuffer: %m");

        manager->sysctl_link = TAKE_PTR(sysctl_link);
        manager->sysctl_skel = TAKE_PTR(obj);
        manager->sysctl_buffer = TAKE_PTR(sysctl_buffer);
        manager->cgroup_fd = TAKE_FD(cgroup_fd);

        return 0;
}

void manager_remove_sysctl_monitor(Manager *manager) {
        assert(manager);

        manager->sysctl_event_source = sd_event_source_disable_unref(manager->sysctl_event_source);
        manager->sysctl_buffer = bpf_ring_buffer_free(manager->sysctl_buffer);
        manager->sysctl_link = bpf_link_free(manager->sysctl_link);
        manager->sysctl_skel = sysctl_monitor_bpf_free(manager->sysctl_skel);
        manager->cgroup_fd = safe_close(manager->cgroup_fd);
        manager->sysctl_shadow = hashmap_free(manager->sysctl_shadow);
}

int link_clear_sysctl_shadows(Link *link) {
        _cleanup_free_ char *ipv4 = NULL, *ipv6 = NULL;
        char *key = NULL, *value = NULL;

        assert(link);
        assert(link->manager);

        ipv4 = path_join("/proc/sys/net/ipv4/conf", link->ifname);
        if (!ipv4)
                return log_oom();

        ipv6 = path_join("/proc/sys/net/ipv6/conf", link->ifname);
        if (!ipv6)
                return log_oom();

        HASHMAP_FOREACH_KEY(value, key, link->manager->sysctl_shadow)
                if (path_startswith(key, ipv4) || path_startswith(key, ipv6)) {
                        assert_se(hashmap_remove_value(link->manager->sysctl_shadow, key, value));
                        free(key);
                        free(value);
                }

        return 0;
}
#endif

static void manager_set_ip_forwarding(Manager *manager, int family) {
        int r, t;

        assert(manager);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return;

        t = manager->ip_forwarding[family == AF_INET6];
        if (t < 0)
                return; /* keep */

        /* First, set the default value. */
        r = sysctl_write_ip_property_boolean(family, "default", "forwarding", t, manager_get_sysctl_shadow(manager));
        if (r < 0)
                log_warning_errno(r, "Failed to %s the default %s forwarding: %m",
                                  enable_disable(t), af_to_ipv4_ipv6(family));

        /* Then, set the value to all interfaces. */
        r = sysctl_write_ip_property_boolean(family, "all", "forwarding", t, manager_get_sysctl_shadow(manager));
        if (r < 0)
                log_warning_errno(r, "Failed to %s %s forwarding for all interfaces: %m",
                                  enable_disable(t), af_to_ipv4_ipv6(family));
}

void manager_set_sysctl(Manager *manager) {
        assert(manager);
        assert(!manager->test_mode);

        manager_set_ip_forwarding(manager, AF_INET);
        manager_set_ip_forwarding(manager, AF_INET6);
}

static bool link_is_configured_for_family(Link *link, int family) {
        assert(link);

        if (!link->network)
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        /* CAN devices do not support IP layer. Most of the functions below are never called for CAN devices,
         * but link_set_ipv6_mtu() may be called after setting interface MTU, and warn about the failure. For
         * safety, let's unconditionally check if the interface is not a CAN device. */
        if (IN_SET(family, AF_INET, AF_INET6, AF_MPLS) && link->iftype == ARPHRD_CAN)
                return false;

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return false;

        return true;
}

static int link_update_ipv6_sysctl(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (!link_ipv6_enabled(link))
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "disable_ipv6", false, manager_get_sysctl_shadow(link->manager));
}

static int link_set_proxy_arp(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->proxy_arp < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "proxy_arp", link->network->proxy_arp > 0, manager_get_sysctl_shadow(link->manager));
}

static int link_set_proxy_arp_pvlan(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->proxy_arp_pvlan < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "proxy_arp_pvlan", link->network->proxy_arp_pvlan > 0, manager_get_sysctl_shadow(link->manager));
}

int link_get_ip_forwarding(Link *link, int family) {
        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* If it is explicitly specified, then honor the setting. */
        int t = link->network->ip_forwarding[family == AF_INET6];
        if (t >= 0)
                return t;

        /* If IPMasquerade= is enabled, also enable IP forwarding. */
        if (FLAGS_SET(link->network->ip_masquerade, AF_TO_ADDRESS_FAMILY(family)))
                return true;

        /* If IPv6SendRA= is enabled, also enable IPv6 forwarding. */
        if (family == AF_INET6 && link_radv_enabled(link))
                return true;

        /* Otherwise, use the global setting. */
        return link->manager->ip_forwarding[family == AF_INET6];
}

static int link_set_ip_forwarding_impl(Link *link, int family) {
        int r, t;

        assert(link);
        assert(link->manager);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (!link_is_configured_for_family(link, family))
                return 0;

        t = link_get_ip_forwarding(link, family);
        if (t < 0)
                return 0; /* keep */

        r = sysctl_write_ip_property_boolean(family, link->ifname, "forwarding", t, manager_get_sysctl_shadow(link->manager));
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to %s %s forwarding, ignoring: %m",
                                              enable_disable(t), af_to_ipv4_ipv6(family));

        return 0;
}

static int link_reapply_ip_forwarding(Link *link, int family) {
        int r, ret = 0;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        (void) link_set_ip_forwarding_impl(link, family);

        r = link_lldp_tx_update_capabilities(link);
        if (r < 0)
                RET_GATHER(ret, log_link_warning_errno(link, r, "Could not update LLDP capabilities, ignoring: %m"));

        if (family == AF_INET6 && !link_ndisc_enabled(link)) {
                r = ndisc_stop(link);
                if (r < 0)
                        RET_GATHER(ret, log_link_warning_errno(link, r, "Could not stop IPv6 Router Discovery, ignoring: %m"));

                ndisc_flush(link);
        }

        return ret;
}

static int link_set_ip_forwarding(Link *link, int family) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (!link_is_configured_for_family(link, family))
                return 0;

        /* When IPMasquerade= is enabled and the global setting is unset, enable _global_ IP forwarding, and
         * re-apply per-link setting for all links. */
        if (FLAGS_SET(link->network->ip_masquerade, AF_TO_ADDRESS_FAMILY(family)) &&
            link->manager->ip_forwarding[family == AF_INET6] < 0) {

                link->manager->ip_forwarding[family == AF_INET6] = true;
                manager_set_ip_forwarding(link->manager, family);

                Link *other;
                HASHMAP_FOREACH(other, link->manager->links_by_index) {
                        r = link_reapply_ip_forwarding(other, family);
                        if (r < 0)
                                link_enter_failed(other);
                }

                return 0;
        }

        /* Otherwise, apply per-link setting for _this_ link. */
        return link_set_ip_forwarding_impl(link, family);
}

static int link_set_ipv4_rp_filter(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_rp_filter < 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET, link->ifname, "rp_filter", link->network->ipv4_rp_filter, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv4_force_igmp_version(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_force_igmp_version < 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET, link->ifname, "force_igmp_version", link->network->ipv4_force_igmp_version, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_privacy_extensions(Link *link) {
        IPv6PrivacyExtensions val;

        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        val = link->network->ipv6_privacy_extensions;
        if (val < 0) /* If not specified, then use the global setting. */
                val = link->manager->ipv6_privacy_extensions;

        /* When "kernel", do not update the setting. */
        if (val == IPV6_PRIVACY_EXTENSIONS_KERNEL)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "use_tempaddr", (int) val, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_accept_ra(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        return sysctl_write_ip_property(AF_INET6, link->ifname, "accept_ra", "0", manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_dad_transmits(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_dad_transmits < 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "dad_transmits", link->network->ipv6_dad_transmits, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_hop_limit(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_hop_limit <= 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "hop_limit", link->network->ipv6_hop_limit, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_retransmission_time(Link *link) {
        usec_t retrans_time_ms;

        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (!timestamp_is_set(link->network->ipv6_retransmission_time))
                return 0;

        retrans_time_ms = DIV_ROUND_UP(link->network->ipv6_retransmission_time, USEC_PER_MSEC);
         if (retrans_time_ms <= 0 || retrans_time_ms > UINT32_MAX)
                return 0;

        return sysctl_write_ip_neighbor_property_uint32(AF_INET6, link->ifname, "retrans_time_ms", retrans_time_ms, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv6_proxy_ndp(Link *link) {
        bool v;

        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_proxy_ndp >= 0)
                v = link->network->ipv6_proxy_ndp;
        else
                v = !set_isempty(link->network->ipv6_proxy_ndp_addresses);

        return sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "proxy_ndp", v, manager_get_sysctl_shadow(link->manager));
}

int link_set_ipv6_mtu(Link *link, int log_level) {
        uint32_t mtu = 0;
        int r;

        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (sd_event_source_get_enabled(link->ipv6_mtu_wait_synced_event_source, /* ret = */ NULL) > 0) {
                log_link_debug(link, "Waiting for IPv6 MTU is synced to link MTU, delaying to set IPv6 MTU.");
                return 0;
        }

        assert(link->network);

        if (link->network->ndisc_use_mtu)
                mtu = link->ndisc_mtu;
        if (mtu == 0)
                mtu = link->network->ipv6_mtu;
        if (mtu == 0)
                return 0;

        if (mtu > link->mtu) {
                log_link_full(link, log_level,
                              "Reducing requested IPv6 MTU %"PRIu32" to the interface's maximum MTU %"PRIu32".",
                              mtu, link->mtu);
                mtu = link->mtu;
        }

        r = sysctl_write_ip_property_uint32(AF_INET6, link->ifname, "mtu", mtu, manager_get_sysctl_shadow(link->manager));
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set IPv6 MTU to %"PRIu32": %m", mtu);

        return 0;
}

static int ipv6_mtu_wait_synced_handler(sd_event_source *s, uint64_t usec, void *userdata);

static int link_set_ipv6_mtu_async_impl(Link *link) {
        uint32_t current_mtu;
        int r;

        assert(link);

        /* When the link MTU is updated, it seems that the kernel IPv6 MTU of the interface is asynchronously
         * reset to the link MTU. Hence, we need to check if it is already reset, and wait for a while if not. */

        if (++link->ipv6_mtu_wait_trial_count >= 10) {
                log_link_debug(link, "Timed out waiting for IPv6 MTU being synced to link MTU, proceeding anyway.");
                r = link_set_ipv6_mtu(link, LOG_INFO);
                if (r < 0)
                        return r;

                return 1; /* done */
        }

        /* Check if IPv6 MTU is synced. */
        r = sysctl_read_ip_property_uint32(AF_INET6, link->ifname, "mtu", &current_mtu);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to read IPv6 MTU: %m");

        if (current_mtu == link->mtu) {
                /* Already synced. Update IPv6 MTU now. */
                r = link_set_ipv6_mtu(link, LOG_INFO);
                if (r < 0)
                        return r;

                return 1; /* done */
        }

        /* If not, set up a timer event source. */
        r = event_reset_time_relative(
                        link->manager->event, &link->ipv6_mtu_wait_synced_event_source,
                        CLOCK_BOOTTIME, 100 * USEC_PER_MSEC, 0,
                        ipv6_mtu_wait_synced_handler, link,
                        /* priority = */ 0, "ipv6-mtu-wait-synced", /* force_reset = */ true);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure timer event source for waiting for IPv6 MTU being synced: %m");

        /* Check again. */
        r = sysctl_read_ip_property_uint32(AF_INET6, link->ifname, "mtu", &current_mtu);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to read IPv6 MTU: %m");

        if (current_mtu == link->mtu) {
                /* Synced while setting up the timer event source. Disable it and update IPv6 MTU now. */
                r = sd_event_source_set_enabled(link->ipv6_mtu_wait_synced_event_source, SD_EVENT_OFF);
                if (r < 0)
                        log_link_debug_errno(link, r, "Failed to disable timer event source for IPv6 MTU, ignoring: %m");

                r = link_set_ipv6_mtu(link, LOG_INFO);
                if (r < 0)
                        return r;

                return 1; /* done */
        }

        log_link_debug(link, "IPv6 MTU is not synced to the link MTU after it is changed. Waiting for a while.");
        return 0; /* waiting */
}

static int ipv6_mtu_wait_synced_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        (void) link_set_ipv6_mtu_async_impl(ASSERT_PTR(userdata));
        return 0;
}

int link_set_ipv6_mtu_async(Link *link) {
        assert(link);

        link->ipv6_mtu_wait_trial_count = 0;
        return link_set_ipv6_mtu_async_impl(link);
}

static int link_set_ipv4_accept_local(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_accept_local < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "accept_local", link->network->ipv4_accept_local > 0, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv4_route_localnet(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_route_localnet < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "route_localnet", link->network->ipv4_route_localnet > 0, manager_get_sysctl_shadow(link->manager));
}

static int link_set_ipv4_promote_secondaries(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        /* If promote_secondaries is not set, DHCP will work only as long as the IP address does not
         * changes between leases. The kernel will remove all secondary IP addresses of an interface
         * otherwise. The way systemd-networkd works is that the new IP of a lease is added as a
         * secondary IP and when the primary one expires it relies on the kernel to promote the
         * secondary IP. See also https://github.com/systemd/systemd/issues/7163 */
        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "promote_secondaries", true, manager_get_sysctl_shadow(link->manager));
}

static int link_set_mpls_input(Link *link) {
        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_MPLS))
                return 0;

        if (link->network->mpls_input < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_MPLS, link->ifname, "input", link->network->mpls_input > 0, manager_get_sysctl_shadow(link->manager));
}

int link_set_sysctl(Link *link) {
        int r;

        assert(link);

        /* If IPv6 configured that is static IPv6 address and IPv6LL autoconfiguration is enabled
         * for this interface, then enable IPv6 */
        r = link_update_ipv6_sysctl(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable IPv6, ignoring: %m");

        r = link_set_proxy_arp(link);
        if (r < 0)
               log_link_warning_errno(link, r, "Cannot configure proxy ARP for interface, ignoring: %m");

        r = link_set_proxy_arp_pvlan(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure proxy ARP private VLAN for interface, ignoring: %m");

        (void) link_set_ip_forwarding(link, AF_INET);
        (void) link_set_ip_forwarding(link, AF_INET6);

        r = link_set_ipv6_privacy_extensions(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 privacy extensions for interface, ignoring: %m");

        r = link_set_ipv6_accept_ra(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot disable kernel IPv6 accept_ra for interface, ignoring: %m");

        r = link_set_ipv6_dad_transmits(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 dad transmits for interface, ignoring: %m");

        r = link_set_ipv6_hop_limit(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 hop limit for interface, ignoring: %m");

        r = link_set_ipv6_retransmission_time(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 retransmission time for interface, ignoring: %m");

        r = link_set_ipv6_proxy_ndp(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 proxy NDP, ignoring: %m");

        (void) link_set_ipv6_mtu(link, LOG_INFO);

        r = link_set_ipv6ll_stable_secret(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set stable secret address for IPv6 link-local address: %m");

        r = link_set_ipv4_accept_local(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 accept_local flag for interface, ignoring: %m");

        r = link_set_ipv4_route_localnet(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 route_localnet flag for interface, ignoring: %m");

        r = link_set_ipv4_rp_filter(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 reverse path filtering for interface, ignoring: %m");

        r = link_set_ipv4_force_igmp_version(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 force igmp version, ignoring: %m");

        r = link_set_ipv4_promote_secondaries(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable promote_secondaries for interface, ignoring: %m");

        r = link_set_mpls_input(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set MPLS input, ignoring: %m");

        return 0;
}

static const char* const ipv6_privacy_extensions_table[_IPV6_PRIVACY_EXTENSIONS_MAX] = {
        [IPV6_PRIVACY_EXTENSIONS_NO]            = "no",
        [IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC] = "prefer-public",
        [IPV6_PRIVACY_EXTENSIONS_YES]           = "yes",
        [IPV6_PRIVACY_EXTENSIONS_KERNEL]        = "kernel",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(ipv6_privacy_extensions, IPv6PrivacyExtensions,
                                        IPV6_PRIVACY_EXTENSIONS_YES);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_privacy_extensions, ipv6_privacy_extensions, IPv6PrivacyExtensions);

static const char* const ip_reverse_path_filter_table[_IP_REVERSE_PATH_FILTER_MAX] = {
        [IP_REVERSE_PATH_FILTER_NO]     = "no",
        [IP_REVERSE_PATH_FILTER_STRICT] = "strict",
        [IP_REVERSE_PATH_FILTER_LOOSE]  = "loose",
};

DEFINE_STRING_TABLE_LOOKUP(ip_reverse_path_filter, IPReversePathFilter);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ip_reverse_path_filter, ip_reverse_path_filter, IPReversePathFilter);

int config_parse_ip_forward_deprecated(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "IPForward= setting is deprecated. "
                   "Please use IPv4Forwarding= and/or IPv6Forwarding= in networkd.conf for global setting, "
                   "and the same settings in .network files for per-interface setting.");
        return 0;
}

static const char* const ipv4_force_igmp_version_table[_IPV4_FORCE_IGMP_VERSION_MAX] = {
        [IPV4_FORCE_IGMP_VERSION_NO] = "no",
        [IPV4_FORCE_IGMP_VERSION_1]  = "v1",
        [IPV4_FORCE_IGMP_VERSION_2]  = "v2",
        [IPV4_FORCE_IGMP_VERSION_3]  = "v3",
};

DEFINE_STRING_TABLE_LOOKUP(ipv4_force_igmp_version, IPv4ForceIgmpVersion);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv4_force_igmp_version, ipv4_force_igmp_version, IPv4ForceIgmpVersion);

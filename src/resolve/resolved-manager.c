/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-netlink.h"
#include "sd-network.h"

#include "af-list.h"
#include "alloc-util.h"
#include "daemon-util.h"
#include "dirent-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "memstream-util.h"
#include "missing-network.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "random-util.h"
#include "resolved-bus.h"
#include "resolved-conf.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stub.h"
#include "resolved-dns-transaction.h"
#include "resolved-dnssd.h"
#include "resolved-etc-hosts.h"
#include "resolved-link.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "resolved-resolv-conf.h"
#include "resolved-socket-graveyard.h"
#include "resolved-util.h"
#include "resolved-varlink.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-util.h"

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

static int manager_process_link(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uint16_t type;
        Link *l;
        int ifindex, r;

        assert(rtnl);
        assert(mm);

        r = sd_netlink_message_get_type(mm, &type);
        if (r < 0)
                goto fail;

        r = sd_rtnl_message_link_get_ifindex(mm, &ifindex);
        if (r < 0)
                goto fail;

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));

        switch (type) {

        case RTM_NEWLINK:{
                bool is_new = !l;

                if (!l) {
                        r = link_new(m, &l, ifindex);
                        if (r < 0)
                                goto fail;
                }

                r = link_process_rtnl(l, mm);
                if (r < 0)
                        goto fail;

                r = link_update(l);
                if (r < 0)
                        goto fail;

                if (is_new)
                        log_debug("Found new link %i/%s", ifindex, l->ifname);

                break;
        }

        case RTM_DELLINK:
                if (l) {
                        log_debug("Removing link %i/%s", l->ifindex, l->ifname);
                        link_remove_user(l);
                        link_free(l);

                        /* Make sure DNS servers are dropped from written resolv.conf if their link goes away */
                        manager_write_resolv_conf(m);
                }

                break;
        }

        /* Now check all the links, and if mDNS/llmr are disabled everywhere, stop them globally too. */
        manager_llmnr_maybe_stop(m);
        manager_mdns_maybe_stop(m);

        /* The accessible flag on link DNS servers will have been reset by
         * link_update(). Just reset the global DNS servers. */
        (void) manager_send_dns_configuration_changed(m, NULL, /* reset= */ true);

        return 0;

fail:
        log_warning_errno(r, "Failed to process RTNL link message: %m");
        return 0;
}

static int manager_process_address(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        union in_addr_union address, broadcast = {};
        uint16_t type;
        int r, ifindex, family;
        LinkAddress *a;
        Link *l;

        assert(rtnl);
        assert(mm);

        r = sd_netlink_message_get_type(mm, &type);
        if (r < 0)
                goto fail;

        r = sd_rtnl_message_addr_get_ifindex(mm, &ifindex);
        if (r < 0)
                goto fail;

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!l)
                return 0;

        r = sd_rtnl_message_addr_get_family(mm, &family);
        if (r < 0)
                goto fail;

        switch (family) {

        case AF_INET:
                sd_netlink_message_read_in_addr(mm, IFA_BROADCAST, &broadcast.in);
                r = sd_netlink_message_read_in_addr(mm, IFA_LOCAL, &address.in);
                if (r < 0) {
                        r = sd_netlink_message_read_in_addr(mm, IFA_ADDRESS, &address.in);
                        if (r < 0)
                                goto fail;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(mm, IFA_LOCAL, &address.in6);
                if (r < 0) {
                        r = sd_netlink_message_read_in6_addr(mm, IFA_ADDRESS, &address.in6);
                        if (r < 0)
                                goto fail;
                }

                break;

        default:
                return 0;
        }

        a = link_find_address(l, family, &address);

        switch (type) {

        case RTM_NEWADDR:

                if (!a) {
                        r = link_address_new(l, &a, family, &address, &broadcast);
                        if (r < 0)
                                return r;
                }

                r = link_address_update_rtnl(a, mm);
                if (r < 0)
                        return r;

                break;

        case RTM_DELADDR:
                link_address_free(a);
                break;
        }

        (void) manager_send_dns_configuration_changed(m, l, /* reset= */ true);

        return 0;

fail:
        log_warning_errno(r, "Failed to process RTNL address message: %m");
        return 0;
}

static int manager_process_route(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Link *l = NULL;
        uint16_t type;
        uint32_t ifindex = 0;
        int r;

        assert(rtnl);
        assert(mm);

        r = sd_netlink_message_get_type(mm, &type);
        if (r < 0) {
                log_warning_errno(r, "Failed to get rtnl message type, ignoring: %m");
                return 0;
        }

        if (!IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE)) {
                log_warning("Unexpected message type %u when processing route, ignoring.", type);
                return 0;
        }

        r = sd_netlink_message_read_u32(mm, RTA_OIF, &ifindex);
        if (r < 0)
                log_full_errno(r == -ENODATA ? LOG_DEBUG : LOG_WARNING, r, "Failed to get route ifindex, ignoring: %m");
        else
                l = hashmap_get(m->links, INT_TO_PTR(ifindex));

        (void) manager_send_dns_configuration_changed(m, l, /* reset= */ true);

        return 0;
}

static int manager_rtnl_listen(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(m);

        /* First, subscribe to interfaces coming and going */
        r = sd_netlink_open(&m->rtnl);
        if (r < 0)
                return r;

        r = sd_netlink_attach_event(m->rtnl, m->event, SD_EVENT_PRIORITY_IMPORTANT);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, manager_process_link, NULL, m, "resolve-NEWLINK");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELLINK, manager_process_link, NULL, m, "resolve-DELLINK");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWADDR, manager_process_address, NULL, m, "resolve-NEWADDR");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELADDR, manager_process_address, NULL, m, "resolve-DELADDR");
        if (r < 0)
                return r;

        /* Then, enumerate all links */
        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_link(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        req = sd_netlink_message_unref(req);
        reply = sd_netlink_message_unref(reply);

        /* Finally, enumerate all addresses, too */
        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_address(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        return r;
}

static int on_network_event(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        int r;

        sd_network_monitor_flush(m->network_monitor);

        HASHMAP_FOREACH(l, m->links) {
                r = link_update(l);
                if (r < 0)
                        log_warning_errno(r, "Failed to update monitor information for %i: %m", l->ifindex);
        }

        (void) manager_write_resolv_conf(m);
        (void) manager_send_changed(m, "DNS");
        (void) manager_send_dns_configuration_changed(m, NULL, /* reset= */ true);

        /* Now check all the links, and if mDNS/llmr are disabled everywhere, stop them globally too. */
        manager_llmnr_maybe_stop(m);
        manager_mdns_maybe_stop(m);
        return 0;
}

static int manager_network_monitor_listen(Manager *m) {
        int r, fd, events;

        assert(m);

        r = sd_network_monitor_new(&m->network_monitor, NULL);
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(m->network_monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(m->network_monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &m->network_event_source, fd, events, &on_network_event, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->network_event_source, SD_EVENT_PRIORITY_IMPORTANT+5);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->network_event_source, "network-monitor");

        return 0;
}

static int manager_clock_change_listen(Manager *m);

static int on_clock_change(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        /* The clock has changed, let's flush all caches. Why that? That's because DNSSEC validation takes
         * the system clock into consideration, and if the clock changes the old validations might have been
         * wrong. Let's redo all validation with the new, correct time.
         *
         * (Also, this is triggered after system suspend, which is also a good reason to drop caches, since
         * we might be connected to a different network now without this being visible in a dropped link
         * carrier or so.) */

        log_info("Clock change detected. Flushing caches.");
        manager_flush_caches(m, LOG_DEBUG /* downgrade the functions own log message, since we already logged here at LOG_INFO level */);

        /* The clock change timerfd is unusable after it triggered once, create a new one. */
        return manager_clock_change_listen(m);
}

static int manager_clock_change_listen(Manager *m) {
        int r;

        assert(m);

        m->clock_change_event_source = sd_event_source_disable_unref(m->clock_change_event_source);

        r = event_add_time_change(m->event, &m->clock_change_event_source, on_clock_change, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create clock change event source: %m");

        return 0;
}

static int determine_hostnames(char **full_hostname, char **llmnr_hostname, char **mdns_hostname) {
        _cleanup_free_ char *h = NULL, *n = NULL;
        int r;

        assert(full_hostname);
        assert(llmnr_hostname);
        assert(mdns_hostname);

        r = resolve_system_hostname(&h, &n);
        if (r < 0)
                return r;

        r = dns_name_concat(n, "local", 0, mdns_hostname);
        if (r < 0)
                return log_error_errno(r, "Failed to determine mDNS hostname: %m");

        *llmnr_hostname = TAKE_PTR(n);
        *full_hostname = TAKE_PTR(h);

        return 0;
}

static char* fallback_hostname(void) {

        /* Determine the fall back hostname. For exposing this system to the outside world, we cannot have it
         * to be "localhost" even if that's the default hostname. In this case, let's revert to "linux"
         * instead. */

        _cleanup_free_ char *n = get_default_hostname();
        if (!n)
                return NULL;

        if (is_localhost(n))
                return strdup("linux");

        return TAKE_PTR(n);
}

static int make_fallback_hostnames(char **full_hostname, char **llmnr_hostname, char **mdns_hostname) {
        _cleanup_free_ char *h = NULL, *n = NULL, *m = NULL;
        char label[DNS_LABEL_MAX+1];
        const char *p;
        int r;

        assert(full_hostname);
        assert(llmnr_hostname);
        assert(mdns_hostname);

        p = h = fallback_hostname();
        if (!h)
                return log_oom();

        r = dns_label_unescape(&p, label, sizeof label, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unescape fallback hostname: %m");

        assert(r > 0); /* The fallback hostname must have at least one label */

        r = dns_label_escape_new(label, r, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to escape fallback hostname: %m");

        r = dns_name_concat(n, "local", 0, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to concatenate mDNS hostname: %m");

        *llmnr_hostname = TAKE_PTR(n);
        *mdns_hostname = TAKE_PTR(m);
        *full_hostname = TAKE_PTR(h);

        return 0;
}

static int on_hostname_change(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ char *full_hostname = NULL, *llmnr_hostname = NULL, *mdns_hostname = NULL;
        Manager *m = ASSERT_PTR(userdata);
        bool llmnr_hostname_changed;
        int r;

        r = determine_hostnames(&full_hostname, &llmnr_hostname, &mdns_hostname);
        if (r < 0) {
                log_warning_errno(r, "Failed to determine the local hostname and LLMNR/mDNS names, ignoring: %m");
                return 0; /* ignore invalid hostnames */
        }

        llmnr_hostname_changed = !streq(llmnr_hostname, m->llmnr_hostname);
        if (streq(full_hostname, m->full_hostname) &&
            !llmnr_hostname_changed &&
            streq(mdns_hostname, m->mdns_hostname))
                return 0;

        log_info("System hostname changed to '%s'.", full_hostname);

        free_and_replace(m->full_hostname, full_hostname);
        free_and_replace(m->llmnr_hostname, llmnr_hostname);
        free_and_replace(m->mdns_hostname, mdns_hostname);

        manager_refresh_rrs(m);
        (void) manager_send_changed(m, "LLMNRHostname");

        return 0;
}

static int manager_watch_hostname(Manager *m) {
        int r;

        assert(m);

        m->hostname_fd = open("/proc/sys/kernel/hostname",
                              O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (m->hostname_fd < 0) {
                log_warning_errno(errno, "Failed to watch hostname: %m");
                return 0;
        }

        r = sd_event_add_io(m->event, &m->hostname_event_source, m->hostname_fd, 0, on_hostname_change, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add hostname event source: %m");

        (void) sd_event_source_set_description(m->hostname_event_source, "hostname");

        r = determine_hostnames(&m->full_hostname, &m->llmnr_hostname, &m->mdns_hostname);
        if (r < 0) {
                _cleanup_free_ char *d = NULL;

                d = fallback_hostname();
                if (!d)
                        return log_oom();

                log_info("Defaulting to hostname '%s'.", d);

                r = make_fallback_hostnames(&m->full_hostname, &m->llmnr_hostname, &m->mdns_hostname);
                if (r < 0)
                        return r;
        } else
                log_info("Using system hostname '%s'.", m->full_hostname);

        return 0;
}

static int manager_sigusr1(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        _cleanup_(memstream_done) MemStream ms = {};
        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        FILE *f;

        assert(s);
        assert(si);

        f = memstream_init(&ms);
        if (!f)
                return log_oom();

        LIST_FOREACH(scopes, scope, m->dns_scopes)
                dns_scope_dump(scope, f);

        LIST_FOREACH(servers, server, m->dns_servers)
                dns_server_dump(server, f);
        LIST_FOREACH(servers, server, m->fallback_dns_servers)
                dns_server_dump(server, f);
        HASHMAP_FOREACH(l, m->links)
                LIST_FOREACH(servers, server, l->dns_servers)
                        dns_server_dump(server, f);
        DnsDelegate *delegate;
        HASHMAP_FOREACH(delegate, m->delegates)
                LIST_FOREACH(servers, server, delegate->dns_servers)
                        dns_server_dump(server, f);

        return memstream_dump(LOG_INFO, &ms);
}

static int manager_sigusr2(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);
        assert(si);

        manager_flush_caches(m, LOG_INFO);

        return 0;
}

static int manager_sigrtmin1(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);
        assert(si);

        manager_reset_server_features(m);
        return 0;
}

static int manager_memory_pressure(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        log_info("Under memory pressure, flushing caches.");

        manager_flush_caches(m, LOG_INFO);
        sd_event_trim_memory();

        return 0;
}

static int manager_memory_pressure_listen(Manager *m) {
        int r;

        assert(m);

        r = sd_event_add_memory_pressure(m->event, NULL, manager_memory_pressure, m);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN )? LOG_DEBUG : LOG_NOTICE, r,
                               "Failed to install memory pressure event source, ignoring: %m");

        return 0;
}

static void manager_set_defaults(Manager *m) {
        assert(m);

        m->llmnr_support = DEFAULT_LLMNR_MODE;
        m->mdns_support = DEFAULT_MDNS_MODE;
        m->dnssec_mode = DEFAULT_DNSSEC_MODE;
        m->dns_over_tls_mode = DEFAULT_DNS_OVER_TLS_MODE;
        m->enable_cache = DNS_CACHE_MODE_YES;
        m->dns_stub_listener_mode = DNS_STUB_LISTENER_YES;
        m->read_etc_hosts = true;
        m->resolve_unicast_single_label = false;
        m->cache_from_localhost = false;
        m->stale_retention_usec = 0;
        m->refuse_record_types = set_free(m->refuse_record_types);
        m->resolv_conf_stat = (struct stat) {};
}

static int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        int r;

        (void) notify_reloading();

        dns_server_unlink_on_reload(m->dns_servers);
        dns_server_unlink_on_reload(m->fallback_dns_servers);
        m->dns_extra_stub_listeners = ordered_set_free(m->dns_extra_stub_listeners);
        manager_dns_stub_stop(m);
        dnssd_registered_service_clear_on_reload(m->dnssd_registered_services);
        m->unicast_scope = dns_scope_free(m->unicast_scope);
        m->delegates = hashmap_free(m->delegates);
        dns_trust_anchor_flush(&m->trust_anchor);

        manager_set_defaults(m);

        r = dns_trust_anchor_load(&m->trust_anchor);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), r);

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file on reload, ignoring: %m");
        else
                log_info("Config file reloaded.");

        (void) dnssd_load(m);
        (void) manager_load_delegates(m);

        /* The default scope configuration is influenced by the manager's configuration (modes, etc.), so
         * recreate it on reload. */
        r = dns_scope_new(m, &m->unicast_scope, DNS_SCOPE_GLOBAL, /* link= */ NULL, /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_UNSPEC);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), r);

        /* A link's unicast scope may also be influenced by the manager's configuration. I.e., DNSSEC= and DNSOverTLS=
         * from the manager will be used if not explicitly configured on the link. Free the scopes here so that
         * link_allocate_scopes() in on_network_event() re-creates them. */
        HASHMAP_FOREACH(l, m->links)
                l->unicast_scope = dns_scope_free(l->unicast_scope);

        /* The configuration has changed, so reload the per-interface configuration too in order to take
         * into account any changes (e.g.: enable/disable DNSSEC). */
        r = on_network_event(/* source= */ NULL, -EBADF, /* revents= */ 0, m);
        if (r < 0)
                log_warning_errno(r, "Failed to update network information on reload, ignoring: %m");

        /* We have new configuration, which means potentially new servers, so close all connections and drop
         * all caches, so that we can start fresh. */
        (void) dns_stream_disconnect_all(m);
        manager_flush_caches(m, LOG_INFO);
        manager_verify_all(m);

        r = manager_dns_stub_start(m);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), r);

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .llmnr_ipv4_udp_fd = -EBADF,
                .llmnr_ipv6_udp_fd = -EBADF,
                .llmnr_ipv4_tcp_fd = -EBADF,
                .llmnr_ipv6_tcp_fd = -EBADF,
                .mdns_ipv4_fd = -EBADF,
                .mdns_ipv6_fd = -EBADF,
                .hostname_fd = -EBADF,

                .read_resolv_conf = true,
                .need_builtin_fallbacks = true,
                .etc_hosts_last = USEC_INFINITY,

                .sigrtmin18_info.memory_pressure_handler = manager_memory_pressure,
                .sigrtmin18_info.memory_pressure_userdata = m,
        };

        manager_set_defaults(m);

        r = dns_trust_anchor_load(&m->trust_anchor);
        if (r < 0)
                return r;

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file, ignoring: %m");

#if ENABLE_DNS_OVER_TLS
        r = dnstls_manager_init(m);
        if (r < 0)
                return r;
#endif

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        r = manager_watch_hostname(m);
        if (r < 0)
                return r;

        (void) dnssd_load(m);
        (void) manager_load_delegates(m);

        r = dns_scope_new(m, &m->unicast_scope, DNS_SCOPE_GLOBAL, /* link= */ NULL, /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_UNSPEC);
        if (r < 0)
                return r;

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        r = manager_rtnl_listen(m);
        if (r < 0)
                return r;

        r = manager_clock_change_listen(m);
        if (r < 0)
                return r;

        r = manager_memory_pressure_listen(m);
        if (r < 0)
                return r;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, manager_dispatch_reload_signal, m);
        if (r < 0)
                return log_debug_errno(r, "Failed to install SIGHUP handler: %m");

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGUSR1 | SD_EVENT_SIGNAL_PROCMASK, manager_sigusr1, m);
        if (r < 0)
                return log_debug_errno(r, "Failed to install SIGUSR1 handler: %m");

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGUSR2 | SD_EVENT_SIGNAL_PROCMASK, manager_sigusr2, m);
        if (r < 0)
                return log_debug_errno(r, "Failed to install SIGUSR2 handler: %m");

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+1) | SD_EVENT_SIGNAL_PROCMASK, manager_sigrtmin1, m);
        if (r < 0)
                return log_debug_errno(r, "Failed to install SIGRTMIN+1 handler: %m");

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, &m->sigrtmin18_info);
        if (r < 0)
                return log_debug_errno(r, "Failed to install SIGRTMIN+18 handler: %m");

        manager_cleanup_saved_user(m);

        *ret = TAKE_PTR(m);

        return 0;
}

int manager_start(Manager *m) {
        int r;

        assert(m);

        r = manager_dns_stub_start(m);
        if (r < 0)
                return r;

        r = manager_varlink_init(m);
        if (r < 0)
                return r;

        return 0;
}

Manager* manager_free(Manager *m) {
        Link *l;
        DnssdRegisteredService *s;
        DnsServiceBrowser *sb;

        if (!m)
                return NULL;

        dns_server_unlink_all(m->dns_servers);
        dns_server_unlink_all(m->fallback_dns_servers);
        dns_search_domain_unlink_all(m->search_domains);

        while ((l = hashmap_first(m->links)))
               link_free(l);

        m->delegates = hashmap_free(m->delegates);

        while (m->dns_queries)
                dns_query_free(m->dns_queries);

        m->stub_queries_by_packet = hashmap_free(m->stub_queries_by_packet);
        m->unicast_scope = dns_scope_free(m->unicast_scope);

        /* At this point only orphaned streams should remain. All others should have been freed already by their
         * owners */
        while (m->dns_streams)
                dns_stream_unref(m->dns_streams);

#if ENABLE_DNS_OVER_TLS
        dnstls_manager_free(m);
#endif

        set_free(m->refuse_record_types);
        hashmap_free(m->links);
        hashmap_free(m->dns_transactions);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_netlink_slot_unref(m->netlink_new_route_slot);
        sd_netlink_slot_unref(m->netlink_del_route_slot);
        sd_netlink_unref(m->rtnl);
        sd_event_source_unref(m->rtnl_event_source);
        sd_event_source_unref(m->clock_change_event_source);

        sd_json_variant_unref(m->dns_configuration_json);

        manager_llmnr_stop(m);
        manager_mdns_stop(m);
        manager_dns_stub_stop(m);
        manager_varlink_done(m);

        set_free(m->varlink_query_results_subscription);
        set_free(m->varlink_dns_configuration_subscription);

        manager_socket_graveyard_clear(m);

        ordered_set_free(m->dns_extra_stub_listeners);

        hashmap_free(m->polkit_registry);

        sd_bus_flush_close_unref(m->bus);

        dns_resource_key_unref(m->llmnr_host_ipv4_key);
        dns_resource_key_unref(m->llmnr_host_ipv6_key);
        dns_resource_key_unref(m->mdns_host_ipv4_key);
        dns_resource_key_unref(m->mdns_host_ipv6_key);

        sd_event_source_unref(m->hostname_event_source);
        safe_close(m->hostname_fd);

        sd_event_unref(m->event);

        free(m->full_hostname);
        free(m->llmnr_hostname);
        free(m->mdns_hostname);

        while ((s = hashmap_first(m->dnssd_registered_services)))
               dnssd_registered_service_free(s);
        hashmap_free(m->dnssd_registered_services);

        dns_trust_anchor_flush(&m->trust_anchor);
        manager_etc_hosts_flush(m);

        while ((sb = hashmap_first(m->dns_service_browsers)))
                dns_service_browser_free(sb);
        hashmap_free(m->dns_service_browsers);

        hashmap_free(m->hooks);

        return mfree(m);
}

int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        CMSG_BUFFER_TYPE(CMSG_SPACE(MAXSIZE(struct in_pktinfo, struct in6_pktinfo))
                         + CMSG_SPACE(int) /* ttl/hoplimit */
                         + EXTRA_CMSG_SPACE /* kernel appears to require extra buffer space */) control;
        union sockaddr_union sa;
        struct iovec iov;
        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t ms, l;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(ret);

        ms = next_datagram_size_fd(fd);
        if (ms < 0)
                return ms;

        r = dns_packet_new(&p, protocol, ms, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        iov = IOVEC_MAKE(DNS_PACKET_DATA(p), p->allocated);

        l = recvmsg_safe(fd, &mh, 0);
        if (ERRNO_IS_NEG_TRANSIENT(l))
                return 0;
        if (l <= 0)
                return l;

        p->size = (size_t) l;

        p->family = sa.sa.sa_family;
        p->ipproto = IPPROTO_UDP;
        if (p->family == AF_INET) {
                p->sender.in = sa.in.sin_addr;
                p->sender_port = be16toh(sa.in.sin_port);
        } else if (p->family == AF_INET6) {
                p->sender.in6 = sa.in6.sin6_addr;
                p->sender_port = be16toh(sa.in6.sin6_port);
                p->ifindex = sa.in6.sin6_scope_id;
        } else
                return -EAFNOSUPPORT;

        p->timestamp = now(CLOCK_BOOTTIME);

        CMSG_FOREACH(cmsg, &mh) {

                if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        assert(p->family == AF_INET6);

                        switch (cmsg->cmsg_type) {

                        case IPV6_PKTINFO: {
                                struct in6_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi6_ifindex;

                                p->destination.in6 = i->ipi6_addr;
                                break;
                        }

                        case IPV6_HOPLIMIT:
                                p->ttl = *CMSG_TYPED_DATA(cmsg, int);
                                break;

                        case IPV6_RECVFRAGSIZE:
                                p->fragsize = *CMSG_TYPED_DATA(cmsg, int);
                                break;
                        }
                } else if (cmsg->cmsg_level == IPPROTO_IP) {
                        assert(p->family == AF_INET);

                        switch (cmsg->cmsg_type) {

                        case IP_PKTINFO: {
                                struct in_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in_pktinfo);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi_ifindex;

                                p->destination.in = i->ipi_addr;
                                break;
                        }

                        case IP_TTL:
                                p->ttl = *CMSG_TYPED_DATA(cmsg, int);
                                break;

                        case IP_RECVFRAGSIZE:
                                p->fragsize = *CMSG_TYPED_DATA(cmsg, int);
                                break;
                        }
                }
        }

        /* The Linux kernel sets the interface index to the loopback
         * device if the packet came from the local host since it
         * avoids the routing table in such a case. Let's unset the
         * interface index in such a case. */
        if (p->ifindex == LOOPBACK_IFINDEX)
                p->ifindex = 0;

        if (protocol != DNS_PROTOCOL_DNS) {
                /* If we don't know the interface index still, we look for the
                 * first local interface with a matching address. Yuck! */
                if (p->ifindex <= 0)
                        p->ifindex = manager_find_ifindex(m, p->family, &p->destination);
        }

        log_debug("Received %s UDP packet of size %zu, ifindex=%i, ttl=%u, fragsize=%zu, sender=%s, destination=%s",
                  dns_protocol_to_string(protocol), p->size, p->ifindex, p->ttl, p->fragsize,
                  IN_ADDR_TO_STRING(p->family, &p->sender),
                  IN_ADDR_TO_STRING(p->family, &p->destination));

        *ret = TAKE_PTR(p);
        return 1;
}

int sendmsg_loop(int fd, struct msghdr *mh, int flags) {
        usec_t end;
        int r;

        assert(fd >= 0);
        assert(mh);

        end = usec_add(now(CLOCK_MONOTONIC), SEND_TIMEOUT_USEC);

        for (;;) {
                if (sendmsg(fd, mh, flags) >= 0)
                        return 0;
                if (errno == EINTR)
                        continue;
                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(fd, POLLOUT, LESS_BY(end, now(CLOCK_MONOTONIC)));
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }
}

static int write_loop(int fd, void *message, size_t length) {
        usec_t end;
        int r;

        assert(fd >= 0);
        assert(message);

        end = usec_add(now(CLOCK_MONOTONIC), SEND_TIMEOUT_USEC);

        for (;;) {
                if (write(fd, message, length) >= 0)
                        return 0;
                if (errno == EINTR)
                        continue;
                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(fd, POLLOUT, LESS_BY(end, now(CLOCK_MONOTONIC)));
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }
}

int manager_write(Manager *m, int fd, DnsPacket *p) {
        int r;

        log_debug("Sending %s%s packet with id %" PRIu16 " of size %zu.",
                  DNS_PACKET_TC(p) ? "truncated (!) " : "",
                  DNS_PACKET_QR(p) ? "response" : "query",
                  DNS_PACKET_ID(p),
                  p->size);

        r = write_loop(fd, DNS_PACKET_DATA(p), p->size);
        if (r < 0)
                return r;

        return 0;
}

static int manager_ipv4_send(
                Manager *m,
                int fd,
                int ifindex,
                const struct in_addr *destination,
                uint16_t port,
                const struct in_addr *source,
                DnsPacket *p) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        union sockaddr_union sa;
        struct iovec iov;
        struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.in),
        };

        assert(m);
        assert(fd >= 0);
        assert(destination);
        assert(port > 0);
        assert(p);

        iov = IOVEC_MAKE(DNS_PACKET_DATA(p), p->size);

        sa = (union sockaddr_union) {
                .in.sin_family = AF_INET,
                .in.sin_addr = *destination,
                .in.sin_port = htobe16(port),
        };

        if (ifindex > 0) {
                struct cmsghdr *cmsg;
                struct in_pktinfo *pi;

                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;

                pi = CMSG_TYPED_DATA(cmsg, struct in_pktinfo);
                pi->ipi_ifindex = ifindex;

                if (source)
                        pi->ipi_spec_dst = *source;
        }

        return sendmsg_loop(fd, &mh, 0);
}

static int manager_ipv6_send(
                Manager *m,
                int fd,
                int ifindex,
                const struct in6_addr *destination,
                uint16_t port,
                const struct in6_addr *source,
                DnsPacket *p) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        union sockaddr_union sa;
        struct iovec iov;
        struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.in6),
        };

        assert(m);
        assert(fd >= 0);
        assert(destination);
        assert(port > 0);
        assert(p);

        iov = IOVEC_MAKE(DNS_PACKET_DATA(p), p->size);

        sa = (union sockaddr_union) {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = *destination,
                .in6.sin6_port = htobe16(port),
                .in6.sin6_scope_id = ifindex,
        };

        if (ifindex > 0) {
                struct cmsghdr *cmsg;
                struct in6_pktinfo *pi;

                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;

                pi = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);
                pi->ipi6_ifindex = ifindex;

                if (source)
                        pi->ipi6_addr = *source;
        }

        return sendmsg_loop(fd, &mh, 0);
}

static int dns_question_to_json(DnsQuestion *q, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;
        DnsResourceKey *key;
        int r;

        assert(ret);

        DNS_QUESTION_FOREACH(key, q) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_resource_key_to_json(key, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&l, v);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

int manager_monitor_send(Manager *m, DnsQuery *q) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jquestion = NULL, *jcollected_questions = NULL, *janswer = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *merged = NULL;
        DnsAnswerItem *rri;
        int r;

        assert(m);

        if (set_isempty(m->varlink_query_results_subscription))
                return 0;

        /* Merge all questions into one */
        r = dns_question_merge(q->question_idna, q->question_utf8, &merged);
        if (r < 0)
                return log_error_errno(r, "Failed to merge UTF8/IDNA questions: %m");

        if (q->question_bypass) {
                _cleanup_(dns_question_unrefp) DnsQuestion *merged2 = NULL;

                r = dns_question_merge(merged, q->question_bypass->question, &merged2);
                if (r < 0)
                        return log_error_errno(r, "Failed to merge UTF8/IDNA questions and DNS packet question: %m");

                dns_question_unref(merged);
                merged = TAKE_PTR(merged2);
        }

        /* Convert the current primary question to JSON */
        r = dns_question_to_json(merged, &jquestion);
        if (r < 0)
                return log_error_errno(r, "Failed to convert question to JSON: %m");

        /* Generate a JSON array of the questions preceding the current one in the CNAME chain */
        r = dns_question_to_json(q->collected_questions, &jcollected_questions);
        if (r < 0)
                return log_error_errno(r, "Failed to convert question to JSON: %m");

        DNS_ANSWER_FOREACH_ITEM(rri, q->answer) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_resource_record_to_json(rri->rr, &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert answer resource record to JSON: %m");

                r = dns_resource_record_to_wire_format(rri->rr, /* canonical= */ false); /* don't use DNSSEC canonical format, since it removes casing, but we want that for DNS_SD compat */
                if (r < 0)
                        return log_error_errno(r, "Failed to generate RR wire format: %m");

                r = sd_json_variant_append_arraybo(
                                &janswer,
                                SD_JSON_BUILD_PAIR_CONDITION(!!v, "rr", SD_JSON_BUILD_VARIANT(v)),
                                SD_JSON_BUILD_PAIR_BASE64("raw", rri->rr->wire_format, rri->rr->wire_format_size),
                                SD_JSON_BUILD_PAIR_CONDITION(rri->ifindex > 0, "ifindex", SD_JSON_BUILD_INTEGER(rri->ifindex)));
                if (r < 0)
                        return log_debug_errno(r, "Failed to append notification entry to array: %m");
        }

        r = varlink_many_notifybo(
                        m->varlink_query_results_subscription,
                        SD_JSON_BUILD_PAIR_STRING("state", dns_transaction_state_to_string(q->state)),
                        SD_JSON_BUILD_PAIR_CONDITION(q->state == DNS_TRANSACTION_DNSSEC_FAILED,
                                                     "result", SD_JSON_BUILD_STRING(dnssec_result_to_string(q->answer_dnssec_result))),
                        SD_JSON_BUILD_PAIR_CONDITION(q->state == DNS_TRANSACTION_RCODE_FAILURE,
                                                     "rcode", SD_JSON_BUILD_INTEGER(q->answer_rcode)),
                        SD_JSON_BUILD_PAIR_CONDITION(q->state == DNS_TRANSACTION_ERRNO,
                                                     "errno", SD_JSON_BUILD_INTEGER(q->answer_errno)),
                        SD_JSON_BUILD_PAIR_CONDITION(IN_SET(q->state,
                                                            DNS_TRANSACTION_DNSSEC_FAILED,
                                                            DNS_TRANSACTION_RCODE_FAILURE) &&
                                                     q->answer_ede_rcode >= 0,
                                                     "extendedDNSErrorCode", SD_JSON_BUILD_INTEGER(q->answer_ede_rcode)),
                        SD_JSON_BUILD_PAIR_CONDITION(IN_SET(q->state,
                                                            DNS_TRANSACTION_DNSSEC_FAILED,
                                                            DNS_TRANSACTION_RCODE_FAILURE) &&
                                                     q->answer_ede_rcode >= 0 && !isempty(q->answer_ede_msg),
                                                     "extendedDNSErrorMessage", SD_JSON_BUILD_STRING(q->answer_ede_msg)),
                        SD_JSON_BUILD_PAIR_VARIANT("question", jquestion),
                        SD_JSON_BUILD_PAIR_CONDITION(!!jcollected_questions,
                                                     "collectedQuestions", SD_JSON_BUILD_VARIANT(jcollected_questions)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!janswer,
                                                             "answer", SD_JSON_BUILD_VARIANT(janswer)));
        if (r < 0)
                log_debug_errno(r, "Failed to send monitor event, ignoring: %m");

        return 0;
}

int manager_send(
                Manager *m,
                int fd,
                int ifindex,
                int family,
                const union in_addr_union *destination,
                uint16_t port,
                const union in_addr_union *source,
                DnsPacket *p) {

        assert(m);
        assert(fd >= 0);
        assert(destination);
        assert(port > 0);
        assert(p);

        /* For mDNS, it is natural that the packet have truncated flag when we have many known answers. */
        bool truncated = DNS_PACKET_TC(p) && (p->protocol != DNS_PROTOCOL_MDNS || !p->more);

        log_debug("Sending %s%s packet with id %" PRIu16 " on interface %i/%s of size %zu.",
                  truncated ? "truncated (!) " : "",
                  DNS_PACKET_QR(p) ? "response" : "query",
                  DNS_PACKET_ID(p),
                  ifindex, af_to_name(family),
                  p->size);

        if (family == AF_INET)
                return manager_ipv4_send(m, fd, ifindex, &destination->in, port, source ? &source->in : NULL, p);
        if (family == AF_INET6)
                return manager_ipv6_send(m, fd, ifindex, &destination->in6, port, source ? &source->in6 : NULL, p);

        return -EAFNOSUPPORT;
}

uint32_t manager_find_mtu(Manager *m) {
        uint32_t mtu = 0;
        Link *l;

        /* If we don't know on which link a DNS packet would be delivered, let's find the largest MTU that
         * works on all interfaces we know of that have an IP address associated */

        HASHMAP_FOREACH(l, m->links) {
                /* Let's filter out links without IP addresses (e.g. AF_CAN links and suchlike) */
                if (!l->addresses)
                        continue;

                /* Safety check: MTU shorter than what we need for the absolutely shortest DNS request? Then
                 * let's ignore this link. */
                if (l->mtu < MIN(UDP4_PACKET_HEADER_SIZE + DNS_PACKET_HEADER_SIZE,
                                 UDP6_PACKET_HEADER_SIZE + DNS_PACKET_HEADER_SIZE))
                        continue;

                if (mtu <= 0 || l->mtu < mtu)
                        mtu = l->mtu;
        }

        if (mtu == 0) /* found nothing? then let's assume the typical Ethernet MTU for lack of anything more precise */
                return 1500;

        return mtu;
}

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(m);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return 0;

        if (!in_addr)
                return 0;

        a = manager_find_link_address(m, family, in_addr);
        if (a)
                return a->link->ifindex;

        return 0;
}

void manager_refresh_rrs(Manager *m) {
        Link *l;
        DnssdRegisteredService *s;

        assert(m);

        m->llmnr_host_ipv4_key = dns_resource_key_unref(m->llmnr_host_ipv4_key);
        m->llmnr_host_ipv6_key = dns_resource_key_unref(m->llmnr_host_ipv6_key);
        m->mdns_host_ipv4_key = dns_resource_key_unref(m->mdns_host_ipv4_key);
        m->mdns_host_ipv6_key = dns_resource_key_unref(m->mdns_host_ipv6_key);

        HASHMAP_FOREACH(l, m->links)
                link_add_rrs(l, true);

        if (m->mdns_support == RESOLVE_SUPPORT_YES)
                HASHMAP_FOREACH(s, m->dnssd_registered_services)
                        if (dnssd_update_rrs(s) < 0)
                                log_warning("Failed to refresh DNS-SD service '%s'", s->id);

        HASHMAP_FOREACH(l, m->links)
                link_add_rrs(l, false);
}

static int manager_next_random_name(const char *old, char **ret_new) {
        const char *p;
        uint64_t u, a;
        char *n;

        p = strchr(old, 0);
        assert(p);

        while (p > old) {
                if (!ascii_isdigit(p[-1]))
                        break;

                p--;
        }

        if (*p == 0 || safe_atou64(p, &u) < 0 || u <= 0)
                u = 1;

        /* Add a random number to the old value. This way we can avoid
         * that two hosts pick the same hostname, win on IPv4 and lose
         * on IPv6 (or vice versa), and pick the same hostname
         * replacement hostname, ad infinitum. We still want the
         * numbers to go up monotonically, hence we just add a random
         * value 1..10 */

        random_bytes(&a, sizeof(a));
        u += 1 + a % 10;

        if (asprintf(&n, "%.*s%" PRIu64, (int) (p - old), old, u) < 0)
                return -ENOMEM;

        *ret_new = n;

        return 0;
}

int manager_next_hostname(Manager *m) {
        _cleanup_free_ char *h = NULL, *k = NULL;
        int r;

        assert(m);

        r = manager_next_random_name(m->llmnr_hostname, &h);
        if (r < 0)
                return r;

        r = dns_name_concat(h, "local", 0, &k);
        if (r < 0)
                return r;

        log_info("Hostname conflict, changing published hostname from '%s' to '%s'.", m->llmnr_hostname, h);

        free_and_replace(m->llmnr_hostname, h);
        free_and_replace(m->mdns_hostname, k);

        manager_refresh_rrs(m);
        (void) manager_send_changed(m, "LLMNRHostname");

        return 0;
}

LinkAddress* manager_find_link_address(Manager *m, int family, const union in_addr_union *in_addr) {
        Link *l;

        assert(m);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return NULL;

        if (!in_addr)
                return NULL;

        HASHMAP_FOREACH(l, m->links) {
                LinkAddress *a;

                a = link_find_address(l, family, in_addr);
                if (a)
                        return a;
        }

        return NULL;
}

bool manager_packet_from_local_address(Manager *m, DnsPacket *p) {
        assert(m);
        assert(p);

        /* Let's see if this packet comes from an IP address we have on any local interface */

        return !!manager_find_link_address(m, p->family, &p->sender);
}

bool manager_packet_from_our_transaction(Manager *m, DnsPacket *p) {
        DnsTransaction *t;

        assert(m);
        assert(p);

        /* Let's see if we have a transaction with a query message with the exact same binary contents as the
         * one we just got. If so, it's almost definitely a packet loop of some kind. */

        t = hashmap_get(m->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
        if (!t)
                return false;

        return t->sent && dns_packet_equal(t->sent, p);
}

DnsScope* manager_find_scope_from_protocol(Manager *m, int ifindex, DnsProtocol protocol, int family) {
        Link *l;

        assert(m);

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!l)
                return NULL;

        switch (protocol) {
        case DNS_PROTOCOL_LLMNR:
                if (family == AF_INET)
                        return l->llmnr_ipv4_scope;
                else if (family == AF_INET6)
                        return l->llmnr_ipv6_scope;

                break;

        case DNS_PROTOCOL_MDNS:
                if (family == AF_INET)
                        return l->mdns_ipv4_scope;
                else if (family == AF_INET6)
                        return l->mdns_ipv6_scope;

                break;

        default:
                ;
        }

        return NULL;
}

void manager_verify_all(Manager *m) {
        assert(m);

        LIST_FOREACH(scopes, s, m->dns_scopes)
                dns_zone_verify_all(&s->zone);
}

int manager_is_own_hostname(Manager *m, const char *name) {
        int r;

        assert(m);
        assert(name);

        if (m->llmnr_hostname) {
                r = dns_name_equal(name, m->llmnr_hostname);
                if (r != 0)
                        return r;
        }

        if (m->mdns_hostname) {
                r = dns_name_equal(name, m->mdns_hostname);
                if (r != 0)
                        return r;
        }

        if (m->full_hostname)
                return dns_name_equal(name, m->full_hostname);

        return 0;
}

int manager_compile_dns_servers(Manager *m, OrderedSet **servers) {
        Link *l;
        int r;

        assert(m);
        assert(servers);

        r = ordered_set_ensure_allocated(servers, &dns_server_hash_ops);
        if (r < 0)
                return r;

        /* First add the system-wide servers and domains */
        LIST_FOREACH(servers, s, m->dns_servers) {
                r = ordered_set_put(*servers, s);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
        }

        /* Then, add the per-link servers */
        HASHMAP_FOREACH(l, m->links)
                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = ordered_set_put(*servers, s);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

        /* Third, add the delegate servers and domains */
        DnsDelegate *d;
        HASHMAP_FOREACH(d, m->delegates)
                LIST_FOREACH(servers, s, d->dns_servers) {
                        r = ordered_set_put(*servers, s);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

        /* If we found nothing, add the fallback servers */
        if (ordered_set_isempty(*servers)) {
                LIST_FOREACH(servers, s, m->fallback_dns_servers) {
                        r = ordered_set_put(*servers, s);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

/* filter_route is a tri-state:
 *   < 0: no filtering
 *   = 0 or false: return only domains which should be used for searching
 *   > 0 or true: return only domains which are for routing only
 */
int manager_compile_search_domains(Manager *m, OrderedSet **domains, int filter_route) {
        int r;

        assert(m);
        assert(domains);

        r = ordered_set_ensure_allocated(domains, &dns_name_hash_ops);
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, m->search_domains) {

                if (filter_route >= 0 &&
                    d->route_only != !!filter_route)
                        continue;

                r = ordered_set_put(*domains, d->name);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
        }

        DnsDelegate *delegate;
        HASHMAP_FOREACH(delegate, m->delegates)
                LIST_FOREACH(domains, d, delegate->search_domains) {

                        if (filter_route >= 0 &&
                            d->route_only != !!filter_route)
                                continue;

                        r = ordered_set_put(*domains, d->name);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

        Link *l;
        HASHMAP_FOREACH(l, m->links)
                LIST_FOREACH(domains, d, l->search_domains) {

                        if (filter_route >= 0 &&
                            d->route_only != !!filter_route)
                                continue;

                        r = ordered_set_put(*domains, d->name);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

        return 0;
}

DnssecMode manager_get_dnssec_mode(Manager *m) {
        assert(m);

        if (m->dnssec_mode != _DNSSEC_MODE_INVALID)
                return m->dnssec_mode;

        return DNSSEC_NO;
}

bool manager_dnssec_supported(Manager *m) {
        DnsServer *server;
        Link *l;

        assert(m);

        if (manager_get_dnssec_mode(m) == DNSSEC_NO)
                return false;

        server = manager_get_dns_server(m);
        if (server && !dns_server_dnssec_supported(server))
                return false;

        HASHMAP_FOREACH(l, m->links)
                if (!link_dnssec_supported(l))
                        return false;

        return true;
}

DnsOverTlsMode manager_get_dns_over_tls_mode(Manager *m) {
        assert(m);

        if (m->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                return m->dns_over_tls_mode;

        return DNS_OVER_TLS_NO;
}

void manager_dnssec_verdict(Manager *m, DnssecVerdict verdict, const DnsResourceKey *key) {

        assert(verdict >= 0);
        assert(verdict < _DNSSEC_VERDICT_MAX);

        if (DEBUG_LOGGING) {
                char s[DNS_RESOURCE_KEY_STRING_MAX];

                log_debug("Found verdict for lookup %s: %s",
                          dns_resource_key_to_string(key, s, sizeof s),
                          dnssec_verdict_to_string(verdict));
        }

        m->n_dnssec_verdict[verdict]++;
}

bool manager_routable(Manager *m) {
        Link *l;

        assert(m);

        /* Returns true if the host has at least one interface with a routable address (regardless if IPv4 or IPv6) */

        HASHMAP_FOREACH(l, m->links)
                if (link_relevant(l, AF_UNSPEC, false))
                        return true;

        return false;
}

void manager_flush_caches(Manager *m, int log_level) {
        assert(m);

        LIST_FOREACH(scopes, scope, m->dns_scopes)
                dns_cache_flush(&scope->cache);

        dns_browse_services_purge(m, AF_UNSPEC); /* Clear records of DNS service browse subscriber, since caches are flushed */
        dns_browse_services_restart(m);

        log_full(log_level, "Flushed all caches.");
}

void manager_reset_server_features(Manager *m) {

        dns_server_reset_features_all(m->dns_servers);
        dns_server_reset_features_all(m->fallback_dns_servers);

        Link *l;
        HASHMAP_FOREACH(l, m->links)
                dns_server_reset_features_all(l->dns_servers);

        DnsDelegate *d;
        HASHMAP_FOREACH(d, m->delegates)
                dns_server_reset_features_all(d->dns_servers);

        log_info("Resetting learnt feature levels on all servers.");
}

void manager_cleanup_saved_user(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;

        assert(m);

        /* Clean up all saved per-link files in /run/systemd/resolve/netif/ that don't have a matching interface
         * anymore. These files are created to persist settings pushed in by the user via the bus, so that resolved can
         * be restarted without losing this data. */

        d = opendir("/run/systemd/resolve/netif/");
        if (!d) {
                if (errno == ENOENT)
                        return;

                log_warning_errno(errno, "Failed to open interface directory: %m");
                return;
        }

        FOREACH_DIRENT_ALL(de, d, log_error_errno(errno, "Failed to read interface directory: %m")) {
                int ifindex;
                Link *l;

                if (!IN_SET(de->d_type, DT_UNKNOWN, DT_REG))
                        continue;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                ifindex = parse_ifindex(de->d_name);
                if (ifindex < 0) /* Probably some temporary file from a previous run. Delete it */
                        goto rm;

                l = hashmap_get(m->links, INT_TO_PTR(ifindex));
                if (!l) /* link vanished */
                        goto rm;

                if (l->is_managed) /* now managed by networkd, hence the bus settings are useless */
                        goto rm;

                continue;

        rm:
                if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                        log_warning_errno(errno, "Failed to remove left-over interface configuration file '%s', ignoring: %m", de->d_name);
        }
}

bool manager_next_dnssd_names(Manager *m) {
        DnssdRegisteredService *s;
        bool tried = false;
        int r;

        assert(m);

        HASHMAP_FOREACH(s, m->dnssd_registered_services) {
                _cleanup_free_ char * new_name = NULL;

                if (!s->withdrawn)
                        continue;

                r = manager_next_random_name(s->name_template, &new_name);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get new name for service '%s': %m", s->id);
                        continue;
                }

                free_and_replace(s->name_template, new_name);

                s->withdrawn = false;

                tried = true;
        }

        if (tried)
                manager_refresh_rrs(m);

        return tried;
}

bool manager_server_is_stub(Manager *m, DnsServer *s) {
        DnsStubListenerExtra *l;

        assert(m);
        assert(s);

        /* Safety check: we generally already skip the main stub when parsing configuration. But let's be
         * extra careful, and check here again */
        if (s->family == AF_INET &&
            s->address.in.s_addr == htobe32(INADDR_DNS_STUB) &&
            dns_server_port(s) == 53)
                return true;

        /* Main reason to call this is to check server data against the extra listeners, and filter things
         * out. */
        ORDERED_SET_FOREACH(l, m->dns_extra_stub_listeners)
                if (s->family == l->family &&
                    in_addr_equal(s->family, &s->address, &l->address) &&
                    dns_server_port(s) == dns_stub_listener_extra_port(l))
                        return true;

        return false;
}

int socket_disable_pmtud(int fd, int af) {
        int r;

        assert(fd >= 0);

        if (af == AF_UNSPEC) {
                af = socket_get_family(fd);
                if (af < 0)
                        return af;
        }

        switch (af) {

        case AF_INET: {
                /* Turn off path MTU discovery, let's rather fragment on the way than to open us up against
                 * PMTU forgery vulnerabilities.
                 *
                 * There appears to be no documentation about IP_PMTUDISC_OMIT, but it has the effect that
                 * the "Don't Fragment" bit in the IPv4 header is turned off, thus enforcing fragmentation if
                 * our datagram size exceeds the MTU of a router in the path, and turning off path MTU
                 * discovery.
                 *
                 * This helps mitigating the PMTUD vulnerability described here:
                 *
                 * https://blog.apnic.net/2019/07/12/its-time-to-consider-avoiding-ip-fragmentation-in-the-dns/
                 *
                 * Similar logic is in place in most DNS servers.
                 *
                 * There are multiple conflicting goals: we want to allow the largest datagrams possible (for
                 * efficiency reasons), but not have fragmentation (for security reasons), nor use PMTUD (for
                 * security reasons, too). Our strategy to deal with this is: use large packets, turn off
                 * PMTUD, but watch fragmentation taking place, and then size our packets to the max of the
                 * fragments seen — and if we need larger packets always go to TCP.
                 */

                r = setsockopt_int(fd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_OMIT);
                if (r < 0)
                        return r;

                return 0;
        }

        case AF_INET6: {
                /* On IPv6 fragmentation only is done by the sender — never by routers on the path. PMTUD is
                 * mandatory. If we want to turn off PMTUD, the only way is by sending with minimal MTU only,
                 * so that we apply maximum fragmentation locally already, and thus PMTUD doesn't happen
                 * because there's nothing that could be fragmented further anymore. */

                r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_MTU, IPV6_MIN_MTU);
                if (r < 0)
                        return r;

                return 0;
        }

        default:
                return -EAFNOSUPPORT;
        }
}

int dns_manager_dump_statistics_json(Manager *m, sd_json_variant **ret) {
        uint64_t size = 0, hit = 0, miss = 0;

        assert(m);
        assert(ret);

        LIST_FOREACH(scopes, s, m->dns_scopes) {
                size += dns_cache_size(&s->cache);
                hit += s->cache.n_hit;
                miss += s->cache.n_miss;
        }

        return sd_json_buildo(ret,
                              SD_JSON_BUILD_PAIR("transactions", SD_JSON_BUILD_OBJECT(
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("currentTransactions", hashmap_size(m->dns_transactions)),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("totalTransactions", m->n_transactions_total),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("totalTimeouts", m->n_timeouts_total),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("totalTimeoutsServedStale", m->n_timeouts_served_stale_total),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("totalFailedResponses", m->n_failure_responses_total),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("totalFailedResponsesServedStale", m->n_failure_responses_served_stale_total)
                                                 )),
                              SD_JSON_BUILD_PAIR("cache", SD_JSON_BUILD_OBJECT(
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("size", size),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("hits", hit),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("misses", miss)
                                                 )),
                              SD_JSON_BUILD_PAIR("dnssec", SD_JSON_BUILD_OBJECT(
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("secure", m->n_dnssec_verdict[DNSSEC_SECURE]),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("insecure", m->n_dnssec_verdict[DNSSEC_INSECURE]),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("bogus", m->n_dnssec_verdict[DNSSEC_BOGUS]),
                                                                 SD_JSON_BUILD_PAIR_UNSIGNED("indeterminate", m->n_dnssec_verdict[DNSSEC_INDETERMINATE])
                                                 )));
}

void dns_manager_reset_statistics(Manager *m) {

        assert(m);

        LIST_FOREACH(scopes, s, m->dns_scopes)
                s->cache.n_hit = s->cache.n_miss = 0;

        m->n_transactions_total = 0;
        m->n_timeouts_total = 0;
        m->n_timeouts_served_stale_total = 0;
        m->n_failure_responses_total = 0;
        m->n_failure_responses_served_stale_total = 0;
        zero(m->n_dnssec_verdict);
}

static int dns_configuration_json_append(
                const char *ifname,
                int ifindex,
                const char *delegate,
                int default_route,
                DnsServer *current_dns_server,
                DnsServer *dns_servers,
                DnsServer *fallback_dns_servers,
                DnsSearchDomain *search_domains,
                Set *negative_trust_anchors,
                Set *dns_scopes,
                DnssecMode dnssec_mode,
                bool dnssec_supported,
                DnsOverTlsMode dns_over_tls_mode,
                ResolveSupport llmnr_support,
                ResolveSupport mdns_support,
                ResolvConfMode resolv_conf_mode,
                sd_json_variant **configuration) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dns_servers_json = NULL,
                                                          *fallback_dns_servers_json = NULL,
                                                          *search_domains_json = NULL,
                                                          *current_dns_server_json = NULL,
                                                          *scopes_json = NULL;
        DnsScope *scope;
        int r;

        assert(configuration);

        if (current_dns_server) {
                r = dns_server_dump_configuration_to_json(current_dns_server, &current_dns_server_json);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(scope, dns_scopes) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_scope_to_json(scope, /* with_cache= */ false, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&scopes_json, v);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(servers, s, dns_servers) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_server_dump_configuration_to_json(s, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&dns_servers_json, v);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(domains, d, search_domains) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_search_domain_dump_to_json(d, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&search_domains_json, v);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(servers, s, fallback_dns_servers) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_server_dump_configuration_to_json(s, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&fallback_dns_servers_json, v);
                if (r < 0)
                        return r;
        }

        return sd_json_variant_append_arraybo(
                        configuration,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ifname", ifname),
                        SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_UNSIGNED(ifindex)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("delegate", delegate),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("defaultRoute", default_route),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("currentServer", current_dns_server_json),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("servers", dns_servers_json),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("fallbackServers", fallback_dns_servers_json),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("searchDomains", search_domains_json),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(negative_trust_anchors),
                                                     "negativeTrustAnchors",
                                                     JSON_BUILD_STRING_SET(negative_trust_anchors)),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(dnssec_mode >= 0, "dnssecSupported", dnssec_supported),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("dnssec", dnssec_mode_to_string(dnssec_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("dnsOverTLS", dns_over_tls_mode_to_string(dns_over_tls_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("llmnr", resolve_support_to_string(llmnr_support)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("mDNS", resolve_support_to_string(mdns_support)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("resolvConfMode", resolv_conf_mode_to_string(resolv_conf_mode)),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("scopes", scopes_json));
}

static int global_dns_configuration_json_append(Manager *m, sd_json_variant **configuration) {
        _cleanup_set_free_ Set *scopes = NULL;
        int r;

        assert(m);
        assert(configuration);

        r = set_ensure_put(&scopes, NULL, m->unicast_scope);
        if (r < 0)
                return r;

        return dns_configuration_json_append(
                        /* ifname= */ NULL,
                        /* ifindex= */ 0,
                        /* delegate= */ NULL,
                        /* default_route= */ -1,
                        manager_get_dns_server(m),
                        m->dns_servers,
                        m->fallback_dns_servers,
                        m->search_domains,
                        m->trust_anchor.negative_by_name,
                        scopes,
                        manager_get_dnssec_mode(m),
                        manager_dnssec_supported(m),
                        manager_get_dns_over_tls_mode(m),
                        m->llmnr_support,
                        m->mdns_support,
                        resolv_conf_mode(),
                        configuration);
}

static int link_dns_configuration_json_append(Link *l, sd_json_variant **configuration) {
        _cleanup_set_free_ Set *scopes = NULL;
        int r;

        assert(l);
        assert(configuration);

        if (l->unicast_scope) {
                r = set_ensure_put(&scopes, NULL, l->unicast_scope);
                if (r < 0)
                        return r;
        }

        if (l->llmnr_ipv4_scope) {
                r = set_ensure_put(&scopes, NULL, l->llmnr_ipv4_scope);
                if (r < 0)
                        return r;
        }

        if (l->llmnr_ipv6_scope) {
                r = set_ensure_put(&scopes, NULL, l->llmnr_ipv6_scope);
                if (r < 0)
                        return r;
        }

        if (l->mdns_ipv4_scope) {
                r = set_ensure_put(&scopes, NULL, l->mdns_ipv4_scope);
                if (r < 0)
                        return r;
        }

        if (l->mdns_ipv6_scope) {
                r = set_ensure_put(&scopes, NULL, l->mdns_ipv6_scope);
                if (r < 0)
                        return r;
        }

        return dns_configuration_json_append(
                        l->ifname,
                        l->ifindex,
                        /* delegate= */ NULL,
                        link_get_default_route(l),
                        link_get_dns_server(l),
                        l->dns_servers,
                        /* fallback_dns_servers= */ NULL,
                        l->search_domains,
                        l->dnssec_negative_trust_anchors,
                        scopes,
                        link_get_dnssec_mode(l),
                        link_dnssec_supported(l),
                        link_get_dns_over_tls_mode(l),
                        link_get_llmnr_support(l),
                        link_get_mdns_support(l),
                        /* resolv_conf_mode= */ _RESOLV_CONF_MODE_INVALID,
                        configuration);
}

static int delegate_dns_configuration_json_append(DnsDelegate *d, sd_json_variant **configuration) {
        _cleanup_set_free_ Set *scopes = NULL;
        int r;

        assert(d);
        assert(configuration);

        r = set_ensure_put(&scopes, NULL, d->scope);
        if (r < 0)
                return r;

        return dns_configuration_json_append(
                        /* ifname= */ NULL,
                        /* ifindex= */ 0,
                        d->id,
                        d->default_route > 0, /* Defaults to false. See dns_scope_is_default_route(). */
                        dns_delegate_get_dns_server(d),
                        d->dns_servers,
                        /* fallback_dns_servers= */ NULL,
                        d->search_domains,
                        /* negative_trust_anchors= */ NULL,
                        scopes,
                        /* dnssec_mode= */ _DNSSEC_MODE_INVALID,
                        /* dnssec_supported= */ false,
                        /* dns_over_tls_mode= */ _DNS_OVER_TLS_MODE_INVALID,
                        /* llmnr_support= */ _RESOLVE_SUPPORT_INVALID,
                        /* mdns_support= */ _RESOLVE_SUPPORT_INVALID,
                        /* resolv_conf_mode= */ _RESOLV_CONF_MODE_INVALID,
                        configuration);
}

int manager_dump_dns_configuration_json(Manager *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *configuration = NULL;
        Link *l;
        DnsDelegate *d;
        int r;

        assert(m);
        assert(ret);

        /* Global DNS configuration */
        r = global_dns_configuration_json_append(m, &configuration);
        if (r < 0)
                return r;

        /* Append configuration for each link */
        HASHMAP_FOREACH(l, m->links) {
                r = link_dns_configuration_json_append(l, &configuration);
                if (r < 0)
                        return r;
        }

        /* Append configuration for each delegate */
        HASHMAP_FOREACH(d, m->delegates) {
                r = delegate_dns_configuration_json_append(d, &configuration);
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR_VARIANT("configuration", configuration));
}

int manager_send_dns_configuration_changed(Manager *m, Link *l, bool reset) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *configuration = NULL;
        int r;

        assert(m);

        if (set_isempty(m->varlink_dns_configuration_subscription))
                return 0;

        if (reset) {
                dns_server_reset_accessible_all(m->dns_servers);

                if (l)
                        dns_server_reset_accessible_all(l->dns_servers);
        }

        r = manager_dump_dns_configuration_json(m, &configuration);
        if (r < 0)
                return log_warning_errno(r, "Failed to dump DNS configuration json: %m");

        if (sd_json_variant_equal(configuration, m->dns_configuration_json))
                return 0;

        JSON_VARIANT_REPLACE(m->dns_configuration_json, TAKE_PTR(configuration));

        r = varlink_many_notify(m->varlink_dns_configuration_subscription, m->dns_configuration_json);
        if (r < 0)
                return log_warning_errno(r, "Failed to send DNS configuration event: %m");

        return 0;
}

int manager_start_dns_configuration_monitor(Manager *m) {
        Link *l;
        int r;

        assert(m);
        assert(!m->dns_configuration_json);
        assert(!m->netlink_new_route_slot);
        assert(!m->netlink_del_route_slot);

        dns_server_reset_accessible_all(m->dns_servers);

        HASHMAP_FOREACH(l, m->links)
                dns_server_reset_accessible_all(l->dns_servers);

        r = manager_dump_dns_configuration_json(m, &m->dns_configuration_json);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, &m->netlink_new_route_slot, RTM_NEWROUTE, manager_process_route, NULL, m, "resolve-NEWROUTE");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, &m->netlink_del_route_slot, RTM_DELROUTE, manager_process_route, NULL, m, "resolve-DELROUTE");
        if (r < 0)
                return r;

        return 0;
}

void manager_stop_dns_configuration_monitor(Manager *m) {
        assert(m);

        m->dns_configuration_json = sd_json_variant_unref(m->dns_configuration_json);
        m->netlink_new_route_slot = sd_netlink_slot_unref(m->netlink_new_route_slot);
        m->netlink_del_route_slot = sd_netlink_slot_unref(m->netlink_del_route_slot);
}

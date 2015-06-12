/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

#include <resolv.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netinet/in.h>

#include "netlink-util.h"
#include "network-internal.h"
#include "socket-util.h"
#include "af-list.h"
#include "utf8.h"
#include "fileio-label.h"
#include "ordered-set.h"
#include "random-util.h"
#include "hostname-util.h"

#include "dns-domain.h"
#include "resolved-conf.h"
#include "resolved-bus.h"
#include "resolved-manager.h"

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

static int manager_process_link(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = userdata;
        uint16_t type;
        Link *l;
        int ifindex, r;

        assert(rtnl);
        assert(m);
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

                r = link_update_rtnl(l, mm);
                if (r < 0)
                        goto fail;

                r = link_update_monitor(l);
                if (r < 0)
                        goto fail;

                if (is_new)
                        log_debug("Found new link %i/%s", ifindex, l->name);

                break;
        }

        case RTM_DELLINK:
                if (l) {
                        log_debug("Removing link %i/%s", l->ifindex, l->name);
                        link_free(l);
                }

                break;
        }

        return 0;

fail:
        log_warning_errno(r, "Failed to process RTNL link message: %m");
        return 0;
}

static int manager_process_address(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = userdata;
        union in_addr_union address;
        uint16_t type;
        int r, ifindex, family;
        LinkAddress *a;
        Link *l;

        assert(rtnl);
        assert(mm);
        assert(m);

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
                        r = link_address_new(l, &a, family, &address);
                        if (r < 0)
                                return r;
                }

                r = link_address_update_rtnl(a, mm);
                if (r < 0)
                        return r;

                break;

        case RTM_DELADDR:
                if (a)
                        link_address_free(a);
                break;
        }

        return 0;

fail:
        log_warning_errno(r, "Failed to process RTNL address message: %m");
        return 0;
}

static int manager_rtnl_listen(Manager *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
        sd_netlink_message *i;
        int r;

        assert(m);

        /* First, subscribe to interfaces coming and going */
        r = sd_netlink_open(&m->rtnl);
        if (r < 0)
                return r;

        r = sd_netlink_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_NEWLINK, manager_process_link, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELLINK, manager_process_link, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_NEWADDR, manager_process_address, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELADDR, manager_process_address, m);
        if (r < 0)
                return r;

        /* Then, enumerate all links */
        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (i = reply; i; i = sd_netlink_message_next(i)) {
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

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_address(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        return r;
}

static int on_network_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Iterator i;
        Link *l;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        HASHMAP_FOREACH(l, m->links, i) {
                r = link_update_monitor(l);
                if (r < 0)
                        log_warning_errno(r, "Failed to update monitor information for %i: %m", l->ifindex);
        }

        r = manager_write_resolv_conf(m);
        if (r < 0)
                log_warning_errno(r, "Could not update resolv.conf: %m");

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

        return 0;
}

static int determine_hostname(char **ret) {
        _cleanup_free_ char *h = NULL, *n = NULL;
        int r;

        assert(ret);

        h = gethostname_malloc();
        if (!h)
                return log_oom();

        if (!utf8_is_valid(h)) {
                log_error("System hostname is not UTF-8 clean.");
                return -EINVAL;
        }

        r = dns_name_normalize(h, &n);
        if (r < 0) {
                log_error("System hostname '%s' cannot be normalized.", h);
                return r;
        }

        *ret = n;
        n = NULL;

        return 0;
}

static int on_hostname_change(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ char *h = NULL;
        Manager *m = userdata;
        int r;

        assert(m);

        r = determine_hostname(&h);
        if (r < 0)
                return 0; /* ignore invalid hostnames */

        if (streq(h, m->hostname))
                return 0;

        log_info("System hostname changed to '%s'.", h);
        free(m->hostname);
        m->hostname = h;
        h = NULL;

        manager_refresh_rrs(m);

        return 0;
}

static int manager_watch_hostname(Manager *m) {
        int r;

        assert(m);

        m->hostname_fd = open("/proc/sys/kernel/hostname", O_RDONLY|O_CLOEXEC|O_NDELAY|O_NOCTTY);
        if (m->hostname_fd < 0) {
                log_warning_errno(errno, "Failed to watch hostname: %m");
                return 0;
        }

        r = sd_event_add_io(m->event, &m->hostname_event_source, m->hostname_fd, 0, on_hostname_change, m);
        if (r < 0) {
                if (r == -EPERM)
                        /* kernels prior to 3.2 don't support polling this file. Ignore the failure. */
                        m->hostname_fd = safe_close(m->hostname_fd);
                else
                        return log_error_errno(r, "Failed to add hostname event source: %m");
        }

        r = determine_hostname(&m->hostname);
        if (r < 0) {
                log_info("Defaulting to hostname 'linux'.");
                m->hostname = strdup("linux");
                if (!m->hostname)
                        return log_oom();
        } else
                log_info("Using system hostname '%s'.", m->hostname);

        return 0;
}

static void manager_llmnr_stop(Manager *m) {
        assert(m);

        m->llmnr_ipv4_udp_event_source = sd_event_source_unref(m->llmnr_ipv4_udp_event_source);
        m->llmnr_ipv4_udp_fd = safe_close(m->llmnr_ipv4_udp_fd);

        m->llmnr_ipv6_udp_event_source = sd_event_source_unref(m->llmnr_ipv6_udp_event_source);
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);

        m->llmnr_ipv4_tcp_event_source = sd_event_source_unref(m->llmnr_ipv4_tcp_event_source);
        m->llmnr_ipv4_tcp_fd = safe_close(m->llmnr_ipv4_tcp_fd);

        m->llmnr_ipv6_tcp_event_source = sd_event_source_unref(m->llmnr_ipv6_tcp_event_source);
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
}

static int manager_llmnr_start(Manager *m) {
        int r;

        assert(m);

        if (m->llmnr_support == SUPPORT_NO)
                return 0;

        r = manager_llmnr_ipv4_udp_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        r = manager_llmnr_ipv4_tcp_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        if (socket_ipv6_is_supported()) {
                r = manager_llmnr_ipv6_udp_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;

                r = manager_llmnr_ipv6_tcp_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;
        }

        return 0;

eaddrinuse:
        log_warning("There appears to be another LLMNR responder running. Turning off LLMNR support.");
        m->llmnr_support = SUPPORT_NO;
        manager_llmnr_stop(m);

        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->dns_ipv4_fd = m->dns_ipv6_fd = -1;
        m->llmnr_ipv4_udp_fd = m->llmnr_ipv6_udp_fd = -1;
        m->llmnr_ipv4_tcp_fd = m->llmnr_ipv6_tcp_fd = -1;
        m->hostname_fd = -1;

        m->llmnr_support = SUPPORT_YES;
        m->read_resolv_conf = true;

        r = manager_parse_dns_server(m, DNS_SERVER_FALLBACK, DNS_SERVERS);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        sd_event_set_watchdog(m->event, true);

        r = manager_watch_hostname(m);
        if (r < 0)
                return r;

        r = dns_scope_new(m, &m->unicast_scope, NULL, DNS_PROTOCOL_DNS, AF_UNSPEC);
        if (r < 0)
                return r;

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        r = manager_rtnl_listen(m);
        if (r < 0)
                return r;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

int manager_start(Manager *m) {
        int r;

        assert(m);

        r = manager_llmnr_start(m);
        if (r < 0)
                return r;

        return 0;
}

Manager *manager_free(Manager *m) {
        Link *l;

        if (!m)
                return NULL;

        while ((l = hashmap_first(m->links)))
               link_free(l);

        while (m->dns_queries)
                dns_query_free(m->dns_queries);

        manager_flush_dns_servers(m, DNS_SERVER_SYSTEM);
        manager_flush_dns_servers(m, DNS_SERVER_FALLBACK);

        dns_scope_free(m->unicast_scope);

        hashmap_free(m->links);
        hashmap_free(m->dns_transactions);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->dns_ipv4_event_source);
        sd_event_source_unref(m->dns_ipv6_event_source);
        safe_close(m->dns_ipv4_fd);
        safe_close(m->dns_ipv6_fd);

        manager_llmnr_stop(m);

        sd_bus_slot_unref(m->prepare_for_sleep_slot);
        sd_event_source_unref(m->bus_retry_event_source);
        sd_bus_unref(m->bus);

        sd_event_unref(m->event);

        dns_resource_key_unref(m->host_ipv4_key);
        dns_resource_key_unref(m->host_ipv6_key);

        safe_close(m->hostname_fd);
        sd_event_source_unref(m->hostname_event_source);
        free(m->hostname);

        free(m);

        return NULL;
}

int manager_read_resolv_conf(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st, own;
        char line[LINE_MAX];
        DnsServer *s, *nx;
        usec_t t;
        int r;

        assert(m);

        /* Reads the system /etc/resolv.conf, if it exists and is not
         * symlinked to our own resolv.conf instance */

        if (!m->read_resolv_conf)
                return 0;

        r = stat("/etc/resolv.conf", &st);
        if (r < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open /etc/resolv.conf: %m");
                r = -errno;
                goto clear;
        }

        /* Have we already seen the file? */
        t = timespec_load(&st.st_mtim);
        if (t == m->resolv_conf_mtime)
                return 0;

        m->resolv_conf_mtime = t;

        /* Is it symlinked to our own file? */
        if (stat("/run/systemd/resolve/resolv.conf", &own) >= 0 &&
            st.st_dev == own.st_dev &&
            st.st_ino == own.st_ino) {
                r = 0;
                goto clear;
        }

        f = fopen("/etc/resolv.conf", "re");
        if (!f) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open /etc/resolv.conf: %m");
                r = -errno;
                goto clear;
        }

        if (fstat(fileno(f), &st) < 0) {
                log_error_errno(errno, "Failed to stat open file: %m");
                r = -errno;
                goto clear;
        }

        LIST_FOREACH(servers, s, m->dns_servers)
                s->marked = true;

        FOREACH_LINE(line, f, r = -errno; goto clear) {
                union in_addr_union address;
                int family;
                char *l;
                const char *a;

                truncate_nl(line);

                l = strstrip(line);
                if (*l == '#' || *l == ';')
                        continue;

                a = first_word(l, "nameserver");
                if (!a)
                        continue;

                r = in_addr_from_string_auto(a, &family, &address);
                if (r < 0) {
                        log_warning("Failed to parse name server %s.", a);
                        continue;
                }

                LIST_FOREACH(servers, s, m->dns_servers)
                        if (s->family == family && in_addr_equal(family, &s->address, &address) > 0)
                                break;

                if (s)
                        s->marked = false;
                else {
                        r = dns_server_new(m, NULL, DNS_SERVER_SYSTEM, NULL, family, &address);
                        if (r < 0)
                                goto clear;
                }
        }

        LIST_FOREACH_SAFE(servers, s, nx, m->dns_servers)
                if (s->marked)
                        dns_server_free(s);

        /* Whenever /etc/resolv.conf changes, start using the first
         * DNS server of it. This is useful to deal with broken
         * network managing implementations (like NetworkManager),
         * that when connecting to a VPN place both the VPN DNS
         * servers and the local ones in /etc/resolv.conf. Without
         * resetting the DNS server to use back to the first entry we
         * will continue to use the local one thus being unable to
         * resolve VPN domains. */
        manager_set_dns_server(m, m->dns_servers);

        return 0;

clear:
        while (m->dns_servers)
                dns_server_free(m->dns_servers);

        return r;
}

static void write_resolv_conf_server(DnsServer *s, FILE *f, unsigned *count) {
        _cleanup_free_ char *t  = NULL;
        int r;

        assert(s);
        assert(f);
        assert(count);

        r = in_addr_to_string(s->family, &s->address, &t);
        if (r < 0) {
                log_warning_errno(r, "Invalid DNS address. Ignoring: %m");
                return;
        }

        if (*count == MAXNS)
                fputs("# Too many DNS servers configured, the following entries may be ignored.\n", f);

        fprintf(f, "nameserver %s\n", t);
        (*count) ++;
}

static void write_resolv_conf_search(
                const char *domain, FILE *f,
                unsigned *count,
                unsigned *length) {

        assert(domain);
        assert(f);
        assert(length);

        if (*count >= MAXDNSRCH ||
            *length + strlen(domain) > 256) {
                if (*count == MAXDNSRCH)
                        fputs(" # Too many search domains configured, remaining ones ignored.", f);
                if (*length <= 256)
                        fputs(" # Total length of all search domains is too long, remaining ones ignored.", f);

                return;
        }

        fprintf(f, " %s", domain);

        (*length) += strlen(domain);
        (*count) ++;
}

static int write_resolv_conf_contents(FILE *f, OrderedSet *dns, OrderedSet *domains) {
        Iterator i;

        fputs("# This file is managed by systemd-resolved(8). Do not edit.\n#\n"
              "# Third party programs must not access this file directly, but\n"
              "# only through the symlink at /etc/resolv.conf. To manage\n"
              "# resolv.conf(5) in a different way, replace the symlink by a\n"
              "# static file or a different symlink.\n\n", f);

        if (ordered_set_isempty(dns))
                fputs("# No DNS servers known.\n", f);
        else {
                DnsServer *s;
                unsigned count = 0;

                ORDERED_SET_FOREACH(s, dns, i)
                        write_resolv_conf_server(s, f, &count);
        }

        if (!ordered_set_isempty(domains)) {
                unsigned length = 0, count = 0;
                char *domain;

                fputs("search", f);
                ORDERED_SET_FOREACH(domain, domains, i)
                        write_resolv_conf_search(domain, f, &count, &length);
                fputs("\n", f);
        }

        return fflush_and_check(f);
}

int manager_write_resolv_conf(Manager *m) {
        static const char path[] = "/run/systemd/resolve/resolv.conf";
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_ordered_set_free_ OrderedSet *dns = NULL, *domains = NULL;
        DnsServer *s;
        Iterator i;
        Link *l;
        int r;

        assert(m);

        /* Read the system /etc/resolv.conf first */
        manager_read_resolv_conf(m);

        /* Add the full list to a set, to filter out duplicates */
        dns = ordered_set_new(&dns_server_hash_ops);
        if (!dns)
                return -ENOMEM;

        domains = ordered_set_new(&dns_name_hash_ops);
        if (!domains)
                return -ENOMEM;

        /* First add the system-wide servers */
        LIST_FOREACH(servers, s, m->dns_servers) {
                r = ordered_set_put(dns, s);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
        }

        /* Then, add the per-link servers and domains */
        HASHMAP_FOREACH(l, m->links, i) {
                char **domain;

                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = ordered_set_put(dns, s);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

                if (!l->unicast_scope)
                        continue;

                STRV_FOREACH(domain, l->unicast_scope->domains) {
                        r = ordered_set_put(domains, *domain);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }
        }

        /* If we found nothing, add the fallback servers */
        if (ordered_set_isempty(dns)) {
                LIST_FOREACH(servers, s, m->fallback_dns_servers) {
                        r = ordered_set_put(dns, s);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }
        }

        r = fopen_temporary_label(path, path, &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        r = write_resolv_conf_contents(f, dns, domains);
        if (r < 0)
                goto fail;

        if (rename(temp_path, path) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(path);
        (void) unlink(temp_path);
        return r;
}

int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        union {
                struct cmsghdr header; /* For alignment */
                uint8_t buffer[CMSG_SPACE(MAXSIZE(struct in_pktinfo, struct in6_pktinfo))
                               + CMSG_SPACE(int) /* ttl/hoplimit */
                               + EXTRA_CMSG_SPACE /* kernel appears to require extra buffer space */];
        } control;
        union sockaddr_union sa;
        struct msghdr mh = {};
        struct cmsghdr *cmsg;
        struct iovec iov;
        int ms = 0, r;
        ssize_t l;

        assert(m);
        assert(fd >= 0);
        assert(ret);

        r = ioctl(fd, FIONREAD, &ms);
        if (r < 0)
                return -errno;
        if (ms < 0)
                return -EIO;

        r = dns_packet_new(&p, protocol, ms);
        if (r < 0)
                return r;

        iov.iov_base = DNS_PACKET_DATA(p);
        iov.iov_len = p->allocated;

        mh.msg_name = &sa.sa;
        mh.msg_namelen = sizeof(sa);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = &control;
        mh.msg_controllen = sizeof(control);

        l = recvmsg(fd, &mh, 0);
        if (l < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        if (l <= 0)
                return -EIO;

        assert(!(mh.msg_flags & MSG_CTRUNC));
        assert(!(mh.msg_flags & MSG_TRUNC));

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

        CMSG_FOREACH(cmsg, &mh) {

                if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        assert(p->family == AF_INET6);

                        switch (cmsg->cmsg_type) {

                        case IPV6_PKTINFO: {
                                struct in6_pktinfo *i = (struct in6_pktinfo*) CMSG_DATA(cmsg);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi6_ifindex;

                                p->destination.in6 = i->ipi6_addr;
                                break;
                        }

                        case IPV6_HOPLIMIT:
                                p->ttl = *(int *) CMSG_DATA(cmsg);
                                break;

                        }
                } else if (cmsg->cmsg_level == IPPROTO_IP) {
                        assert(p->family == AF_INET);

                        switch (cmsg->cmsg_type) {

                        case IP_PKTINFO: {
                                struct in_pktinfo *i = (struct in_pktinfo*) CMSG_DATA(cmsg);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi_ifindex;

                                p->destination.in = i->ipi_addr;
                                break;
                        }

                        case IP_TTL:
                                p->ttl = *(int *) CMSG_DATA(cmsg);
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

        /* If we don't know the interface index still, we look for the
         * first local interface with a matching address. Yuck! */
        if (p->ifindex <= 0)
                p->ifindex = manager_find_ifindex(m, p->family, &p->destination);

        *ret = p;
        p = NULL;

        return 1;
}

static int on_dns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = NULL;
        Manager *m = userdata;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_DNS, &p);
        if (r <= 0)
                return r;

        if (dns_packet_validate_reply(p) > 0) {
                t = hashmap_get(m->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (!t)
                        return 0;

                dns_transaction_process_reply(t, p);

        } else
                log_debug("Invalid DNS packet.");

        return 0;
}

int manager_dns_ipv4_fd(Manager *m) {
        const int one = 1;
        int r;

        assert(m);

        if (m->dns_ipv4_fd >= 0)
                return m->dns_ipv4_fd;

        m->dns_ipv4_fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->dns_ipv4_fd < 0)
                return -errno;

        r = setsockopt(m->dns_ipv4_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->dns_ipv4_event_source, m->dns_ipv4_fd, EPOLLIN, on_dns_packet, m);
        if (r < 0)
                goto fail;

        return m->dns_ipv4_fd;

fail:
        m->dns_ipv4_fd = safe_close(m->dns_ipv4_fd);
        return r;
}

int manager_dns_ipv6_fd(Manager *m) {
        const int one = 1;
        int r;

        assert(m);

        if (m->dns_ipv6_fd >= 0)
                return m->dns_ipv6_fd;

        m->dns_ipv6_fd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->dns_ipv6_fd < 0)
                return -errno;

        r = setsockopt(m->dns_ipv6_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->dns_ipv6_event_source, m->dns_ipv6_fd, EPOLLIN, on_dns_packet, m);
        if (r < 0)
                goto fail;

        return m->dns_ipv6_fd;

fail:
        m->dns_ipv6_fd = safe_close(m->dns_ipv6_fd);
        return r;
}

static int sendmsg_loop(int fd, struct msghdr *mh, int flags) {
        int r;

        assert(fd >= 0);
        assert(mh);

        for (;;) {
                if (sendmsg(fd, mh, flags) >= 0)
                        return 0;

                if (errno == EINTR)
                        continue;

                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(fd, POLLOUT, SEND_TIMEOUT_USEC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }
}

static int manager_ipv4_send(Manager *m, int fd, int ifindex, const struct in_addr *addr, uint16_t port, DnsPacket *p) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
        };
        union {
                struct cmsghdr header; /* For alignment */
                uint8_t buffer[CMSG_SPACE(sizeof(struct in_pktinfo))];
        } control;
        struct msghdr mh = {};
        struct iovec iov;

        assert(m);
        assert(fd >= 0);
        assert(addr);
        assert(port > 0);
        assert(p);

        iov.iov_base = DNS_PACKET_DATA(p);
        iov.iov_len = p->size;

        sa.in.sin_addr = *addr;
        sa.in.sin_port = htobe16(port),

        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_name = &sa.sa;
        mh.msg_namelen = sizeof(sa.in);

        if (ifindex > 0) {
                struct cmsghdr *cmsg;
                struct in_pktinfo *pi;

                zero(control);

                mh.msg_control = &control;
                mh.msg_controllen = CMSG_LEN(sizeof(struct in_pktinfo));

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = mh.msg_controllen;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;

                pi = (struct in_pktinfo*) CMSG_DATA(cmsg);
                pi->ipi_ifindex = ifindex;
        }

        return sendmsg_loop(fd, &mh, 0);
}

static int manager_ipv6_send(Manager *m, int fd, int ifindex, const struct in6_addr *addr, uint16_t port, DnsPacket *p) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
        };
        union {
                struct cmsghdr header; /* For alignment */
                uint8_t buffer[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        } control;
        struct msghdr mh = {};
        struct iovec iov;

        assert(m);
        assert(fd >= 0);
        assert(addr);
        assert(port > 0);
        assert(p);

        iov.iov_base = DNS_PACKET_DATA(p);
        iov.iov_len = p->size;

        sa.in6.sin6_addr = *addr;
        sa.in6.sin6_port = htobe16(port),
        sa.in6.sin6_scope_id = ifindex;

        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_name = &sa.sa;
        mh.msg_namelen = sizeof(sa.in6);

        if (ifindex > 0) {
                struct cmsghdr *cmsg;
                struct in6_pktinfo *pi;

                zero(control);

                mh.msg_control = &control;
                mh.msg_controllen = CMSG_LEN(sizeof(struct in6_pktinfo));

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_len = mh.msg_controllen;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;

                pi = (struct in6_pktinfo*) CMSG_DATA(cmsg);
                pi->ipi6_ifindex = ifindex;
        }

        return sendmsg_loop(fd, &mh, 0);
}

int manager_send(Manager *m, int fd, int ifindex, int family, const union in_addr_union *addr, uint16_t port, DnsPacket *p) {
        assert(m);
        assert(fd >= 0);
        assert(addr);
        assert(port > 0);
        assert(p);

        log_debug("Sending %s packet with id %u on interface %i/%s", DNS_PACKET_QR(p) ? "response" : "query", DNS_PACKET_ID(p), ifindex, af_to_name(family));

        if (family == AF_INET)
                return manager_ipv4_send(m, fd, ifindex, &addr->in, port, p);
        else if (family == AF_INET6)
                return manager_ipv6_send(m, fd, ifindex, &addr->in6, port, p);

        return -EAFNOSUPPORT;
}

DnsServer* manager_find_dns_server(Manager *m, int family, const union in_addr_union *in_addr) {
        DnsServer *s;

        assert(m);
        assert(in_addr);

        LIST_FOREACH(servers, s, m->dns_servers)
                if (s->family == family && in_addr_equal(family, &s->address, in_addr) > 0)
                        return s;

        LIST_FOREACH(servers, s, m->fallback_dns_servers)
                if (s->family == family && in_addr_equal(family, &s->address, in_addr) > 0)
                        return s;

        return NULL;
}

DnsServer *manager_set_dns_server(Manager *m, DnsServer *s) {
        assert(m);

        if (m->current_dns_server == s)
                return s;

        if (s) {
                _cleanup_free_ char *ip = NULL;

                in_addr_to_string(s->family, &s->address, &ip);
                log_info("Switching to system DNS server %s.", strna(ip));
        }

        m->current_dns_server = s;

        if (m->unicast_scope)
                dns_cache_flush(&m->unicast_scope->cache);

        return s;
}

DnsServer *manager_get_dns_server(Manager *m) {
        Link *l;
        assert(m);

        /* Try to read updates resolv.conf */
        manager_read_resolv_conf(m);

        if (!m->current_dns_server)
                manager_set_dns_server(m, m->dns_servers);

        if (!m->current_dns_server) {
                bool found = false;
                Iterator i;

                /* No DNS servers configured, let's see if there are
                 * any on any links. If not, we use the fallback
                 * servers */

                HASHMAP_FOREACH(l, m->links, i)
                        if (l->dns_servers) {
                                found = true;
                                break;
                        }

                if (!found)
                        manager_set_dns_server(m, m->fallback_dns_servers);
        }

        return m->current_dns_server;
}

void manager_next_dns_server(Manager *m) {
        assert(m);

        /* If there's currently no DNS server set, then the next
         * manager_get_dns_server() will find one */
        if (!m->current_dns_server)
                return;

        /* Change to the next one */
        if (m->current_dns_server->servers_next) {
                manager_set_dns_server(m, m->current_dns_server->servers_next);
                return;
        }

        /* If there was no next one, then start from the beginning of
         * the list */
        if (m->current_dns_server->type == DNS_SERVER_FALLBACK)
                manager_set_dns_server(m, m->fallback_dns_servers);
        else
                manager_set_dns_server(m, m->dns_servers);
}

uint32_t manager_find_mtu(Manager *m) {
        uint32_t mtu = 0;
        Link *l;
        Iterator i;

        /* If we don't know on which link a DNS packet would be
         * delivered, let's find the largest MTU that works on all
         * interfaces we know of */

        HASHMAP_FOREACH(l, m->links, i) {
                if (l->mtu <= 0)
                        continue;

                if (mtu <= 0 || l->mtu < mtu)
                        mtu = l->mtu;
        }

        return mtu;
}

static int on_llmnr_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = NULL;
        Manager *m = userdata;
        DnsScope *scope;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_LLMNR, &p);
        if (r <= 0)
                return r;

        scope = manager_find_scope(m, p);
        if (!scope) {
                log_warning("Got LLMNR UDP packet on unknown scope. Ignoring.");
                return 0;
        }

        if (dns_packet_validate_reply(p) > 0) {
                log_debug("Got reply packet for id %u", DNS_PACKET_ID(p));

                dns_scope_check_conflicts(scope, p);

                t = hashmap_get(m->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (t)
                        dns_transaction_process_reply(t, p);

        } else if (dns_packet_validate_query(p) > 0)  {
                log_debug("Got query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, NULL, p);
        } else
                log_debug("Invalid LLMNR UDP packet.");

        return 0;
}

int manager_llmnr_ipv4_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(5355),
        };
        static const int one = 1, pmtu = IP_PMTUDISC_DONT, ttl = 255;
        int r;

        assert(m);

        if (m->llmnr_ipv4_udp_fd >= 0)
                return m->llmnr_ipv4_udp_fd;

        m->llmnr_ipv4_udp_fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv4_udp_fd < 0)
                return -errno;

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv4_udp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_udp_event_source, m->llmnr_ipv4_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                goto fail;

        return m->llmnr_ipv4_udp_fd;

fail:
        m->llmnr_ipv4_udp_fd = safe_close(m->llmnr_ipv4_udp_fd);
        return r;
}

int manager_llmnr_ipv6_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(5355),
        };
        static const int one = 1, ttl = 255;
        int r;

        assert(m);

        if (m->llmnr_ipv6_udp_fd >= 0)
                return m->llmnr_ipv6_udp_fd;

        m->llmnr_ipv6_udp_fd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv6_udp_fd < 0)
                return -errno;

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv6_udp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_udp_event_source, m->llmnr_ipv6_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        return m->llmnr_ipv6_udp_fd;

fail:
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);
        return r;
}

static int on_llmnr_stream_packet(DnsStream *s) {
        DnsScope *scope;

        assert(s);

        scope = manager_find_scope(s->manager, s->read_packet);
        if (!scope) {
                log_warning("Got LLMNR TCP packet on unknown scope. Ignroing.");
                return 0;
        }

        if (dns_packet_validate_query(s->read_packet) > 0) {
                log_debug("Got query packet for id %u", DNS_PACKET_ID(s->read_packet));

                dns_scope_process_query(scope, s, s->read_packet);

                /* If no reply packet was set, we free the stream */
                if (s->write_packet)
                        return 0;
        } else
                log_debug("Invalid LLMNR TCP packet.");

        dns_stream_free(s);
        return 0;
}

static int on_llmnr_stream(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        DnsStream *stream;
        Manager *m = userdata;
        int cfd, r;

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        r = dns_stream_new(m, &stream, DNS_PROTOCOL_LLMNR, cfd);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        stream->on_packet = on_llmnr_stream_packet;
        return 0;
}

int manager_llmnr_ipv4_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(5355),
        };
        static const int one = 1, pmtu = IP_PMTUDISC_DONT;
        int r;

        assert(m);

        if (m->llmnr_ipv4_tcp_fd >= 0)
                return m->llmnr_ipv4_tcp_fd;

        m->llmnr_ipv4_tcp_fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv4_tcp_fd < 0)
                return -errno;

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_TTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv4_tcp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = listen(m->llmnr_ipv4_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_tcp_event_source, m->llmnr_ipv4_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                goto fail;

        return m->llmnr_ipv4_tcp_fd;

fail:
        m->llmnr_ipv4_tcp_fd = safe_close(m->llmnr_ipv4_tcp_fd);
        return r;
}

int manager_llmnr_ipv6_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(5355),
        };
        static const int one = 1;
        int r;

        assert(m);

        if (m->llmnr_ipv6_tcp_fd >= 0)
                return m->llmnr_ipv6_tcp_fd;

        m->llmnr_ipv6_tcp_fd = socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv6_tcp_fd < 0)
                return -errno;

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv6_tcp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = listen(m->llmnr_ipv6_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_tcp_event_source, m->llmnr_ipv6_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        return m->llmnr_ipv6_tcp_fd;

fail:
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
        return r;
}

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(m);

        a = manager_find_link_address(m, family, in_addr);
        if (a)
                return a->link->ifindex;

        return 0;
}

void manager_refresh_rrs(Manager *m) {
        Iterator i;
        Link *l;

        assert(m);

        m->host_ipv4_key = dns_resource_key_unref(m->host_ipv4_key);
        m->host_ipv6_key = dns_resource_key_unref(m->host_ipv6_key);

        HASHMAP_FOREACH(l, m->links, i) {
                link_add_rrs(l, true);
                link_add_rrs(l, false);
        }
}

int manager_next_hostname(Manager *m) {
        const char *p;
        uint64_t u, a;
        char *h;

        assert(m);

        p = strchr(m->hostname, 0);
        assert(p);

        while (p > m->hostname) {
                if (!strchr("0123456789", p[-1]))
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

        if (asprintf(&h, "%.*s%" PRIu64, (int) (p - m->hostname), m->hostname, u) < 0)
                return -ENOMEM;

        log_info("Hostname conflict, changing published hostname from '%s' to '%s'.", m->hostname, h);

        free(m->hostname);
        m->hostname = h;

        manager_refresh_rrs(m);

        return 0;
}

LinkAddress* manager_find_link_address(Manager *m, int family, const union in_addr_union *in_addr) {
        Iterator i;
        Link *l;

        assert(m);

        HASHMAP_FOREACH(l, m->links, i) {
                LinkAddress *a;

                a = link_find_address(l, family, in_addr);
                if (a)
                        return a;
        }

        return NULL;
}

bool manager_our_packet(Manager *m, DnsPacket *p) {
        assert(m);
        assert(p);

        return !!manager_find_link_address(m, p->family, &p->sender);
}

DnsScope* manager_find_scope(Manager *m, DnsPacket *p) {
        Link *l;

        assert(m);
        assert(p);

        l = hashmap_get(m->links, INT_TO_PTR(p->ifindex));
        if (!l)
                return NULL;

        if (p->protocol == DNS_PROTOCOL_LLMNR) {
                if (p->family == AF_INET)
                        return l->llmnr_ipv4_scope;
                else if (p->family == AF_INET6)
                        return l->llmnr_ipv6_scope;
        }

        return NULL;
}

void manager_verify_all(Manager *m) {
        DnsScope *s;

        assert(m);

        LIST_FOREACH(scopes, s, m->dns_scopes)
                dns_zone_verify_all(&s->zone);
}

void manager_flush_dns_servers(Manager *m, DnsServerType t) {
        assert(m);

        if (t == DNS_SERVER_SYSTEM)
                while (m->dns_servers)
                        dns_server_free(m->dns_servers);

        if (t == DNS_SERVER_FALLBACK)
                while (m->fallback_dns_servers)
                        dns_server_free(m->fallback_dns_servers);
}

static const char* const support_table[_SUPPORT_MAX] = {
        [SUPPORT_NO] = "no",
        [SUPPORT_YES] = "yes",
        [SUPPORT_RESOLVE] = "resolve",
};
DEFINE_STRING_TABLE_LOOKUP(support, Support);

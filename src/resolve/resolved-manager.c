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

#include <arpa/inet.h>
#include <resolv.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include "rtnl-util.h"
#include "event-util.h"
#include "network-util.h"
#include "network-internal.h"
#include "conf-parser.h"
#include "socket-util.h"
#include "af-list.h"
#include "resolved.h"

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

static int manager_process_link(sd_rtnl *rtnl, sd_rtnl_message *mm, void *userdata) {
        Manager *m = userdata;
        uint16_t type;
        Link *l;
        int ifindex, r;

        assert(rtnl);
        assert(m);
        assert(mm);

        r = sd_rtnl_message_get_type(mm, &type);
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
        log_warning("Failed to process RTNL link message: %s", strerror(-r));
        return 0;
}

static int manager_process_address(sd_rtnl *rtnl, sd_rtnl_message *mm, void *userdata) {
        Manager *m = userdata;
        union in_addr_union address;
        uint16_t type;
        int r, ifindex, family;
        LinkAddress *a;
        Link *l;

        assert(rtnl);
        assert(mm);
        assert(m);

        r = sd_rtnl_message_get_type(mm, &type);
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
                r = sd_rtnl_message_read_in_addr(mm, IFA_LOCAL, &address.in);
                if (r < 0) {
                        r = sd_rtnl_message_read_in_addr(mm, IFA_ADDRESS, &address.in);
                        if (r < 0)
                                goto fail;
                }

                break;

        case AF_INET6:
                r = sd_rtnl_message_read_in6_addr(mm, IFA_LOCAL, &address.in6);
                if (r < 0) {
                        r = sd_rtnl_message_read_in6_addr(mm, IFA_ADDRESS, &address.in6);
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
        log_warning("Failed to process RTNL address message: %s", strerror(-r));
        return 0;
}


static int manager_rtnl_listen(Manager *m) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        sd_rtnl_message *i;
        int r;

        assert(m);

        /* First, subscibe to interfaces coming and going */
        r = sd_rtnl_open(&m->rtnl, 3, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR);
        if (r < 0)
                return r;

        r = sd_rtnl_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_NEWLINK, manager_process_link, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_DELLINK, manager_process_link, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_NEWADDR, manager_process_address, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_DELADDR, manager_process_address, m);
        if (r < 0)
                return r;

        /* Then, enumerate all links */
        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_rtnl_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (i = reply; i; i = sd_rtnl_message_next(i)) {
                r = manager_process_link(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        req = sd_rtnl_message_unref(req);
        reply = sd_rtnl_message_unref(reply);

        /* Finally, enumerate all addresses, too */
        r = sd_rtnl_message_new_addr(m->rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_rtnl_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (i = reply; i; i = sd_rtnl_message_next(i)) {
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
                        log_warning("Failed to update monitor information for %i: %s", l->ifindex, strerror(-r));
        }

        r = manager_write_resolv_conf(m);
        if (r < 0)
                log_warning("Could not update resolv.conf: %s", strerror(-r));

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

static int parse_dns_server_string(Manager *m, const char *string) {
        const char *word, *state;
        size_t length;
        int r;

        assert(m);
        assert(string);

        FOREACH_WORD_QUOTED(word, length, string, state) {
                char buffer[length+1];
                int family;
                union in_addr_union addr;

                memcpy(buffer, word, length);
                buffer[length] = 0;

                r = in_addr_from_string_auto(buffer, &family, &addr);
                if (r < 0) {
                        log_warning("Ignoring invalid DNS address '%s'", buffer);
                        continue;
                }

                /* filter out duplicates */
                if (manager_find_dns_server(m, family, &addr))
                        continue;

                r = dns_server_new(m, NULL, NULL, family, &addr);
                if (r < 0)
                        return r;
        }
        /* do not warn about state here, since probably systemd already did */

        return 0;
}

int config_parse_dnsv(
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

        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);

        /* Empty assignment means clear the list */
        if (isempty(rvalue)) {
                while (m->dns_servers)
                        dns_server_free(m->dns_servers);

                return 0;
        }

        r = parse_dns_server_string(m, rvalue);
        if (r < 0) {
                log_error("Failed to parse DNS server string");
                return r;
        }

        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse(NULL, "/etc/systemd/resolved.conf", NULL,
                            "Resolve\0",
                            config_item_perf_lookup, resolved_gperf_lookup,
                            false, false, true, m);
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

        m->use_llmnr = true;

        r = parse_dns_server_string(m, DNS_SERVERS);
        if (r < 0)
                return r;

        m->hostname = gethostname_malloc();
        if (!m->hostname)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        sd_event_set_watchdog(m->event, true);

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

        r = manager_llmnr_ipv4_udp_fd(m);
        if (r < 0)
                return r;
        r = manager_llmnr_ipv6_udp_fd(m);
        if (r < 0)
                return r;
        r = manager_llmnr_ipv4_tcp_fd(m);
        if (r < 0)
                return r;
        r = manager_llmnr_ipv6_tcp_fd(m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

Manager *manager_free(Manager *m) {
        Link *l;

        if (!m)
                return NULL;

        while (m->dns_queries)
                dns_query_free(m->dns_queries);

        hashmap_free(m->dns_query_transactions);

        while ((l = hashmap_first(m->links)))
               link_free(l);
        hashmap_free(m->links);

        dns_scope_free(m->unicast_scope);

        while (m->dns_servers)
                dns_server_free(m->dns_servers);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->dns_ipv4_event_source);
        sd_event_source_unref(m->dns_ipv6_event_source);
        safe_close(m->dns_ipv4_fd);
        safe_close(m->dns_ipv6_fd);

        sd_event_source_unref(m->llmnr_ipv4_udp_event_source);
        sd_event_source_unref(m->llmnr_ipv6_udp_event_source);
        safe_close(m->llmnr_ipv4_udp_fd);
        safe_close(m->llmnr_ipv6_udp_fd);

        sd_event_source_unref(m->llmnr_ipv4_tcp_event_source);
        sd_event_source_unref(m->llmnr_ipv6_tcp_event_source);
        safe_close(m->llmnr_ipv4_tcp_fd);
        safe_close(m->llmnr_ipv6_tcp_fd);

        sd_event_source_unref(m->bus_retry_event_source);
        sd_bus_unref(m->bus);

        sd_event_unref(m->event);

        dns_resource_key_unref(m->host_ipv4_key);
        dns_resource_key_unref(m->host_ipv6_key);
        free(m->hostname);
        free(m);

        return NULL;
}

static void write_resolve_conf_server(DnsServer *s, FILE *f, unsigned *count) {
        _cleanup_free_ char *t  = NULL;
        int r;

        assert(s);
        assert(f);
        assert(count);

        r = in_addr_to_string(s->family, &s->address, &t);
       if (r < 0) {
                log_warning("Invalid DNS address. Ignoring.");
                return;
        }

        if (*count == MAXNS)
                fputs("# Too many DNS servers configured, the following entries may be ignored\n", f);

        fprintf(f, "nameserver %s\n", t);
        (*count) ++;
}

int manager_write_resolv_conf(Manager *m) {
        const char *path = "/run/systemd/resolve/resolv.conf";
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        unsigned count = 0;
        DnsServer *s;
        Iterator i;
        Link *l;
        int r;

        assert(m);

        r = fopen_temporary(path, &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        fputs("# This file is managed by systemd-resolved(8). Do not edit.\n#\n"
              "# Third party programs must not access this file directly, but\n"
              "# only through the symlink at /etc/resolv.conf. To manage\n"
              "# resolv.conf(5) in a different way, replace the symlink by a\n"
              "# static file or a different symlink.\n\n", f);

        HASHMAP_FOREACH(l, m->links, i)
                LIST_FOREACH(servers, s, l->dns_servers)
                        write_resolve_conf_server(s, f, &count);

        LIST_FOREACH(servers, s, m->dns_servers)
                write_resolve_conf_server(s, f, &count);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, path) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        unlink(path);
        unlink(temp_path);
        return r;
}

int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        union {
                struct cmsghdr header; /* For alignment */
                uint8_t buffer[CMSG_SPACE(MAX(sizeof(struct in_pktinfo), sizeof(struct in6_pktinfo)))
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

        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {

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
        if (p->ifindex > 0 && manager_ifindex_is_loopback(m, p->ifindex) != 0)
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
        DnsQueryTransaction *t = NULL;
        Manager *m = userdata;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_DNS, &p);
        if (r <= 0)
                return r;

        if (dns_packet_validate_reply(p) > 0) {
                t = hashmap_get(m->dns_query_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (!t)
                        return 0;

                dns_query_transaction_process_reply(t, p);

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

        LIST_FOREACH(servers, s, m->dns_servers) {

                if (s->family == family &&
                    in_addr_equal(family, &s->address, in_addr))
                        return s;
        }

        return NULL;
}

DnsServer *manager_get_dns_server(Manager *m) {
        assert(m);

        if (!m->current_dns_server)
                m->current_dns_server = m->dns_servers;

        return m->current_dns_server;
}

void manager_next_dns_server(Manager *m) {
        assert(m);

        if (!m->current_dns_server) {
                m->current_dns_server = m->dns_servers;
                return;
        }

        if (!m->current_dns_server)
                return;

        if (m->current_dns_server->servers_next) {
                m->current_dns_server = m->current_dns_server->servers_next;
                return;
        }

        m->current_dns_server = m->dns_servers;
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
        DnsQueryTransaction *t = NULL;
        Manager *m = userdata;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_LLMNR, &p);
        if (r <= 0)
                return r;

        if (dns_packet_validate_reply(p) > 0) {
                log_debug("Got reply packet for id %u", DNS_PACKET_ID(p));

                t = hashmap_get(m->dns_query_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (!t)
                        return 0;

                dns_query_transaction_process_reply(t, p);

        } else if (dns_packet_validate_query(p) > 0) {
                Link *l;

                l = hashmap_get(m->links, INT_TO_PTR(p->ifindex));
                if (l) {
                        DnsScope *scope = NULL;

                        if (p->family == AF_INET)
                                scope = l->llmnr_ipv4_scope;
                        else if (p->family == AF_INET6)
                                scope = l->llmnr_ipv6_scope;

                        if (scope)
                                dns_scope_process_query(scope, NULL, p);
                }
        } else
                log_debug("Invalid LLMNR packet.");

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
        assert(s);

        if (dns_packet_validate_query(s->read_packet) > 0) {
                Link *l;

                l = hashmap_get(s->manager->links, INT_TO_PTR(s->read_packet->ifindex));
                if (l) {
                        DnsScope *scope = NULL;

                        if (s->read_packet->family == AF_INET)
                                scope = l->llmnr_ipv4_scope;
                        else if (s->read_packet->family == AF_INET6)
                                scope = l->llmnr_ipv6_scope;

                        if (scope) {
                                dns_scope_process_query(scope, s, s->read_packet);

                                /* If no reply packet was set, we free the stream */
                                if (s->write_packet)
                                        return 0;
                        }
                }
        }

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

int manager_ifindex_is_loopback(Manager *m, int ifindex) {
        Link *l;
        assert(m);

        if (ifindex <= 0)
                return -EINVAL;

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (l->flags & IFF_LOOPBACK)
                return 1;

        return 0;
}

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr) {
        Link *l;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(l, m->links, i)
                if (link_find_address(l, family, in_addr))
                        return l->ifindex;

        return 0;
}

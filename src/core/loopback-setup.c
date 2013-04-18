/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "macro.h"
#include "loopback-setup.h"
#include "socket-util.h"

#define NLMSG_TAIL(nmsg)                                                \
        ((struct rtattr *) (((uint8_t*) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int add_rtattr(struct nlmsghdr *n, size_t max_length, int type, const void *data, size_t data_length) {
        size_t length;
        struct rtattr *rta;

        length = RTA_LENGTH(data_length);

        if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length) > max_length)
                return -E2BIG;

        rta = NLMSG_TAIL(n);
        rta->rta_type = type;
        rta->rta_len = length;
        memcpy(RTA_DATA(rta), data, data_length);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length);

        return 0;
}

static ssize_t sendto_loop(int fd, const void *buf, size_t buf_len, int flags, const struct sockaddr *sa, socklen_t sa_len) {

        for (;;) {
                ssize_t l;

                l = sendto(fd, buf, buf_len, flags, sa, sa_len);
                if (l >= 0)
                        return l;

                if (errno != EINTR)
                        return -errno;
        }
}

static ssize_t recvfrom_loop(int fd, void *buf, size_t buf_len, int flags, struct sockaddr *sa, socklen_t *sa_len) {

        for (;;) {
                ssize_t l;

                l = recvfrom(fd, buf, buf_len, flags, sa, sa_len);
                if (l >= 0)
                        return l;

                if (errno != EINTR)
                        return -errno;
        }
}

static int add_adresses(int fd, int if_loopback, unsigned *requests) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa = {
                .nl.nl_family = AF_NETLINK,
        };

        union {
                struct nlmsghdr header;
                uint8_t buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                            NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
                            RTA_LENGTH(sizeof(struct in6_addr))];
        } request = {
                .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                .header.nlmsg_type = RTM_NEWADDR,
                .header.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK,
                .header.nlmsg_seq = *requests + 1,
        };

        struct ifaddrmsg *ifaddrmsg;
        uint32_t ipv4_address = htonl(INADDR_LOOPBACK);
        int r;

        ifaddrmsg = NLMSG_DATA(&request.header);
        ifaddrmsg->ifa_family = AF_INET;
        ifaddrmsg->ifa_prefixlen = 8;
        ifaddrmsg->ifa_flags = IFA_F_PERMANENT;
        ifaddrmsg->ifa_scope = RT_SCOPE_HOST;
        ifaddrmsg->ifa_index = if_loopback;

        r = add_rtattr(&request.header, sizeof(request), IFA_LOCAL,
                       &ipv4_address, sizeof(ipv4_address));
        if (r < 0)
                return r;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;
        (*requests)++;

        if (!socket_ipv6_is_supported())
                return 0;

        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        request.header.nlmsg_seq = *requests + 1;

        ifaddrmsg->ifa_family = AF_INET6;
        ifaddrmsg->ifa_prefixlen = 128;

        r = add_rtattr(&request.header, sizeof(request), IFA_LOCAL,
                       &in6addr_loopback, sizeof(in6addr_loopback));
        if (r < 0)
                return r;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;
        (*requests)++;

        return 0;
}

static int start_interface(int fd, int if_loopback, unsigned *requests) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa = {
                .nl.nl_family = AF_NETLINK,
        };

        union {
                struct nlmsghdr header;
                uint8_t buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                            NLMSG_ALIGN(sizeof(struct ifinfomsg))];
        } request = {
                .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .header.nlmsg_type = RTM_NEWLINK,
                .header.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK,
                .header.nlmsg_seq = *requests + 1,
        };

        struct ifinfomsg *ifinfomsg;

        ifinfomsg = NLMSG_DATA(&request.header);
        ifinfomsg->ifi_family = AF_UNSPEC;
        ifinfomsg->ifi_index = if_loopback;
        ifinfomsg->ifi_flags = IFF_UP;
        ifinfomsg->ifi_change = IFF_UP;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;

        (*requests)++;

        return 0;
}

static int read_response(int fd, unsigned requests_max) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa;
        union {
                struct nlmsghdr header;
                uint8_t buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                            NLMSG_ALIGN(sizeof(struct nlmsgerr))];
        } response;

        ssize_t l;
        socklen_t sa_len = sizeof(sa);
        struct nlmsgerr *nlmsgerr;

        l = recvfrom_loop(fd, &response, sizeof(response), 0, &sa.sa, &sa_len);
        if (l < 0)
                return -errno;

        if (sa_len != sizeof(sa.nl) ||
            sa.nl.nl_family != AF_NETLINK)
                return -EIO;

        if (sa.nl.nl_pid != 0)
                return 0;

        if ((size_t) l < sizeof(struct nlmsghdr))
                return -EIO;

        if (response.header.nlmsg_type != NLMSG_ERROR ||
            (pid_t) response.header.nlmsg_pid != getpid() ||
            response.header.nlmsg_seq >= requests_max)
                return 0;

        if ((size_t) l < NLMSG_LENGTH(sizeof(struct nlmsgerr)) ||
            response.header.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                return -EIO;

        nlmsgerr = NLMSG_DATA(&response.header);

        if (nlmsgerr->error < 0 && nlmsgerr->error != -EEXIST)
                return nlmsgerr->error;

        return response.header.nlmsg_seq;
}

static int check_loopback(void) {
        int r;
        _cleanup_close_ int fd;
        union {
                struct sockaddr sa;
                struct sockaddr_in in;
        } sa = {
                .in.sin_family = AF_INET,
                .in.sin_addr.s_addr = INADDR_LOOPBACK,
        };

        /* If we failed to set up the loop back device, check whether
         * it might already be set up */

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (bind(fd, &sa.sa, sizeof(sa.in)) >= 0)
                r = 1;
        else
                r = errno == EADDRNOTAVAIL ? 0 : -errno;

        return r;
}

int loopback_setup(void) {
        int r, if_loopback;
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa = {
                .nl.nl_family = AF_NETLINK,
        };
        unsigned requests = 0, i;
        _cleanup_close_ int fd = -1;
        bool eperm = false;

        errno = 0;
        if_loopback = (int) if_nametoindex("lo");
        if (if_loopback <= 0)
                return errno ? -errno : -ENODEV;

        fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                goto error;
        }

        r = add_adresses(fd, if_loopback, &requests);
        if (r < 0)
                goto error;

        r = start_interface(fd, if_loopback, &requests);
        if (r < 0)
                goto error;

        for (i = 0; i < requests; i++) {
                r = read_response(fd, requests);

                if (r == -EPERM)
                        eperm = true;
                else if (r  < 0)
                        goto error;
        }

        if (eperm && check_loopback() < 0) {
                r = -EPERM;
                goto error;
        }

        return 0;

error:
        log_warning("Failed to configure loopback device: %s", strerror(-r));
        return r;
}

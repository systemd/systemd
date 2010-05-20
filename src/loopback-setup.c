/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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

enum {
        REQUEST_NONE = 0,
        REQUEST_ADDRESS_IPV4 = 1,
        REQUEST_ADDRESS_IPV6 = 2,
        REQUEST_FLAGS = 4,
        REQUEST_ALL = 7
};

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

                if ((l = sendto(fd, buf, buf_len, flags, sa, sa_len)) >= 0)
                        return l;

                if (errno != EINTR)
                        return -errno;
        }
}

static ssize_t recvfrom_loop(int fd, void *buf, size_t buf_len, int flags, struct sockaddr *sa, socklen_t *sa_len) {

        for (;;) {
                ssize_t l;

                if ((l = recvfrom(fd, buf, buf_len, flags, sa, sa_len)) >= 0)
                        return l;

                if (errno != EINTR)
                        return -errno;
        }
}

static int add_adresses(int fd, int if_loopback) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa;
        union {
                struct nlmsghdr header;
                uint8_t buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                            NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
                            RTA_LENGTH(sizeof(struct in6_addr))];
        } request;

        struct ifaddrmsg *ifaddrmsg;
        uint32_t ipv4_address = htonl(INADDR_LOOPBACK);
        int r;

        zero(request);

        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        request.header.nlmsg_type = RTM_NEWADDR;
        request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK;
        request.header.nlmsg_seq = REQUEST_ADDRESS_IPV4;

        ifaddrmsg = NLMSG_DATA(&request.header);
        ifaddrmsg->ifa_family = AF_INET;
        ifaddrmsg->ifa_prefixlen = 8;
        ifaddrmsg->ifa_flags = IFA_F_PERMANENT;
        ifaddrmsg->ifa_scope = RT_SCOPE_HOST;
        ifaddrmsg->ifa_index = if_loopback;

        if ((r = add_rtattr(&request.header, sizeof(request), IFA_LOCAL, &ipv4_address, sizeof(ipv4_address))) < 0)
                return r;

        zero(sa);
        sa.nl.nl_family = AF_NETLINK;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;

        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        request.header.nlmsg_seq = REQUEST_ADDRESS_IPV6;

        ifaddrmsg->ifa_family = AF_INET6;
        ifaddrmsg->ifa_prefixlen = 128;

        if ((r = add_rtattr(&request.header, sizeof(request), IFA_LOCAL, &in6addr_loopback, sizeof(in6addr_loopback))) < 0)
                return r;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;

        return 0;
}

static int start_interface(int fd, int if_loopback) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sa;
        union {
                struct nlmsghdr header;
                uint8_t buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                            NLMSG_ALIGN(sizeof(struct ifinfomsg))];
        } request;

        struct ifinfomsg *ifinfomsg;

        zero(request);

        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        request.header.nlmsg_type = RTM_NEWLINK;
        request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
        request.header.nlmsg_seq = REQUEST_FLAGS;

        ifinfomsg = NLMSG_DATA(&request.header);
        ifinfomsg->ifi_family = AF_UNSPEC;
        ifinfomsg->ifi_index = if_loopback;
        ifinfomsg->ifi_flags = IFF_UP;
        ifinfomsg->ifi_change = IFF_UP;

        zero(sa);
        sa.nl.nl_family = AF_NETLINK;

        if (sendto_loop(fd, &request, request.header.nlmsg_len, 0, &sa.sa, sizeof(sa)) < 0)
                return -errno;

        return 0;
}

static int read_response(int fd) {
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

        if ((l = recvfrom_loop(fd, &response, sizeof(response), 0, &sa.sa, &sa_len)) < 0)
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
            response.header.nlmsg_seq >= REQUEST_ALL)
                return 0;

        if ((size_t) l < NLMSG_LENGTH(sizeof(struct nlmsgerr)) ||
            response.header.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                return -EIO;

        nlmsgerr = NLMSG_DATA(&response.header);

        if (nlmsgerr->error < 0 && nlmsgerr->error != -EEXIST) {
                log_warning("Netlink failure for request %i: %s", response.header.nlmsg_seq, strerror(nlmsgerr->error));
                return nlmsgerr->error;
        }

        return response.header.nlmsg_seq;
}

int loopback_setup(void) {
        int r, if_loopback;
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
                struct sockaddr_storage storage;
        } sa;
        int requests = REQUEST_NONE;

        int fd;

        errno = 0;
        if ((if_loopback = (int) if_nametoindex("lo")) <= 0)
                return errno ? -errno : -ENODEV;

        if ((fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
                return -errno;

        zero(sa);
        sa.nl.nl_family = AF_NETLINK;

        if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                goto finish;
        }

        if ((r = add_adresses(fd, if_loopback)) < 0)
                goto finish;

        if ((r = start_interface(fd, if_loopback)) < 0)
                goto finish;

        do {
                if ((r = read_response(fd)) < 0)
                        goto finish;

                requests |= r;

        } while (requests != REQUEST_ALL);

        r = 0;

finish:
        if (r < 0)
                log_error("Failed to configure loopback device: %s", strerror(-r));

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

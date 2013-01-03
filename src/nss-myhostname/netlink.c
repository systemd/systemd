/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of nss-myhostname.

  Copyright 2008-2011 Lennart Poettering

  nss-myhostname is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  nss-myhostname is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-myhostname; If not, see
  <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <sys/un.h>
#include <asm/types.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>

#include "ifconf.h"

int ifconf_acquire_addresses(struct address **_list, unsigned *_n_list) {

        struct {
                struct nlmsghdr hdr;
                struct rtgenmsg gen;
        } req;
        struct rtgenmsg *gen;
        int fd, r, on = 1;
        uint32_t seq = 4711;
        struct address *list = NULL;
        unsigned n_list = 0;

        fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
                r = -errno;
                goto finish;
        }

        memset(&req, 0, sizeof(req));
        req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        req.hdr.nlmsg_type = RTM_GETADDR;
        req.hdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP|NLM_F_ACK;
        req.hdr.nlmsg_seq = seq;
        req.hdr.nlmsg_pid = 0;

        gen = NLMSG_DATA(&req.hdr);
        gen->rtgen_family = AF_UNSPEC;

        if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0) {
                r = -errno;
                goto finish;
        }

        for (;;) {
                ssize_t bytes;
                struct msghdr msg;
                struct cmsghdr *cmsg;
                struct ucred *ucred;
                struct iovec iov;
                struct nlmsghdr *p;
                uint8_t cred_buffer[CMSG_SPACE(sizeof(struct ucred))];
                struct {
                        struct nlmsghdr hdr;
                        struct ifaddrmsg ifaddrmsg;
                        uint8_t payload[16*1024];
                } resp;

                memset(&iov, 0, sizeof(iov));
                iov.iov_base = &resp;
                iov.iov_len = sizeof(resp);

                memset(&msg, 0, sizeof(msg));
                msg.msg_name = NULL;
                msg.msg_namelen = 0;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cred_buffer;
                msg.msg_controllen = sizeof(cred_buffer);
                msg.msg_flags = 0;

                bytes = recvmsg(fd, &msg, 0);
                if (bytes < 0) {
                        r = -errno;
                        goto finish;
                }

                cmsg = CMSG_FIRSTHDR(&msg);
                if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
                        r = -EIO;
                        goto finish;
                }

                ucred = (struct ucred*) CMSG_DATA(cmsg);
                if (ucred->uid != 0 || ucred->pid != 0)
                        continue;

                for (p = &resp.hdr; bytes > 0; p = NLMSG_NEXT(p, bytes)) {
                        struct ifaddrmsg *ifaddrmsg;
                        struct rtattr *a;
                        size_t l;
                        void *local = NULL, *address = NULL;

                        if (!NLMSG_OK(p, (size_t) bytes)) {
                                r = -EIO;
                                goto finish;
                        }

                        if (p->nlmsg_seq != seq)
                                continue;

                        if (p->nlmsg_type == NLMSG_DONE) {
                                r = 0;
                                goto finish;
                        }

                        if (p->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *nlmsgerr;

                                nlmsgerr = NLMSG_DATA(p);
                                r = -nlmsgerr->error;
                                goto finish;
                        }

                        if (p->nlmsg_type != RTM_NEWADDR)
                                continue;

                        ifaddrmsg = NLMSG_DATA(p);

                        if (ifaddrmsg->ifa_family != AF_INET &&
                            ifaddrmsg->ifa_family != AF_INET6)
                                continue;

                        if (ifaddrmsg->ifa_scope == RT_SCOPE_HOST ||
                            ifaddrmsg->ifa_scope == RT_SCOPE_NOWHERE)
                                continue;

                        if (ifaddrmsg->ifa_flags & IFA_F_DEPRECATED)
                                continue;

                        l = NLMSG_PAYLOAD(p, sizeof(struct ifaddrmsg));
                        a = IFA_RTA(ifaddrmsg);

                        while (RTA_OK(a, l)) {

                                if (a->rta_type == IFA_ADDRESS)
                                        address = RTA_DATA(a);
                                else if (a->rta_type == IFA_LOCAL)
                                        local = RTA_DATA(a);

                                a = RTA_NEXT(a, l);
                        }

                        if (local)
                                address = local;

                        if (!address)
                                continue;

                        list = realloc(list, (n_list+1) * sizeof(struct address));
                        if (!list) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        list[n_list].family = ifaddrmsg->ifa_family;
                        list[n_list].scope = ifaddrmsg->ifa_scope;
                        memcpy(list[n_list].address, address, ifaddrmsg->ifa_family == AF_INET ? 4 : 16);
                        list[n_list].ifindex = ifaddrmsg->ifa_index;

                        n_list++;
                }
        }

finish:
        close(fd);

        if (r < 0)
                free(list);
        else {
                qsort(list, n_list, sizeof(struct address), address_compare);

                *_list = list;
                *_n_list = n_list;
        }

        return r;
}

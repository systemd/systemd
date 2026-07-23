/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "alloc-util.h"
#include "dhcp6-address-registration.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"

int dhcp6_address_registration_open_socket(int ifindex) {
        union sockaddr_union source = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
        };
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(ifindex > 0);

        fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (fd < 0)
                return -errno;

        r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        r = socket_set_recvpktinfo(fd, AF_INET6, true);
        if (r < 0)
                return r;

        r = socket_bind_to_ifindex(fd, ifindex);
        if (r < 0)
                return r;

        if (bind(fd, &source.sa, sizeof(source.in6)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

int dhcp6_address_registration_send(
                int fd,
                const struct in6_addr *source,
                int ifindex,
                const struct sockaddr_in6 *destination,
                const void *packet,
                size_t len) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        struct iovec iov = IOVEC_MAKE((void*) packet, len);
        struct msghdr message = {
                .msg_name = (struct sockaddr_in6*) destination,
                .msg_namelen = sizeof(*destination),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        struct in6_pktinfo *pktinfo;
        ssize_t n;

        assert(fd >= 0);
        assert(source);
        assert(ifindex > 0);
        assert(destination);
        assert(packet);

        cmsg = CMSG_FIRSTHDR(&message);
        assert(cmsg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
        *pktinfo = (struct in6_pktinfo) {
                .ipi6_addr = *source,
                .ipi6_ifindex = ifindex,
        };

        n = sendmsg(fd, &message, MSG_NOSIGNAL);
        if (n < 0)
                return -errno;
        if ((size_t) n != len)
                return -EIO;

        return 0;
}

int dhcp6_address_registration_receive(
                int fd,
                void **ret_packet,
                size_t *ret_len,
                struct sockaddr_in6 *ret_sender,
                struct in6_addr *ret_destination,
                int *ret_ifindex,
                bool *ret_truncated) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        union sockaddr_union sender = {};
        _cleanup_free_ void *packet = NULL;
        struct iovec iov;
        struct msghdr message = {
                .msg_name = &sender.sa,
                .msg_namelen = sizeof(sender),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t buflen, len;

        assert(fd >= 0);
        assert(ret_packet);
        assert(ret_len);
        assert(ret_sender);
        assert(ret_destination);
        assert(ret_ifindex);
        assert(ret_truncated);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return (int) buflen;

        packet = malloc(MAX(buflen, (ssize_t) 1));
        if (!packet)
                return -ENOMEM;

        iov = IOVEC_MAKE(packet, buflen);
        len = recvmsg_safe(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (len < 0)
                return (int) len;

        struct in6_pktinfo *pktinfo =
                CMSG_FIND_DATA(&message, IPPROTO_IPV6, IPV6_PKTINFO, struct in6_pktinfo);

        *ret_packet = TAKE_PTR(packet);
        *ret_len = MIN((size_t) len, (size_t) buflen);
        *ret_sender = sender.in6;
        *ret_destination = pktinfo ? pktinfo->ipi6_addr : in6addr_any;
        *ret_ifindex = pktinfo ? pktinfo->ipi6_ifindex : 0;
        *ret_truncated = FLAGS_SET(message.msg_flags, MSG_TRUNC);
        return 0;
}

uint32_t dhcp6_address_registration_random_u32(void) {
        return random_u32();
}

uint64_t dhcp6_address_registration_random_u64_range(uint64_t upper_bound) {
        return random_u64_range(upper_bound);
}

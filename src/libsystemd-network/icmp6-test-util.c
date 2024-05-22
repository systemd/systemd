/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <unistd.h>

#include "fd-util.h"
#include "icmp6-test-util.h"

int test_fd[2] = EBADF_PAIR;

static struct in6_addr dummy_link_local = {
        .s6_addr = {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x12, 0x34, 0x56, 0xff, 0xfe, 0x78, 0x9a, 0xbc,
        },
};

int icmp6_bind(int ifindex, bool is_router) {
        if (!is_router && socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[is_router];
}

int icmp6_send(int fd, const struct in6_addr *dst, const struct iovec *iov, size_t n_iov) {
        return writev(fd, iov, n_iov);
}

int icmp6_receive(
                int fd,
                void *iov_base,
                size_t iov_len,
                struct in6_addr *ret_sender,
                triple_timestamp *ret_timestamp) {

        assert_se(read (fd, iov_base, iov_len) == (ssize_t) iov_len);

        if (ret_timestamp)
                triple_timestamp_now(ret_timestamp);

        if (ret_sender)
                *ret_sender = dummy_link_local;

        return 0;
}

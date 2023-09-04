/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip6.h>

#include "fd-util.h"
#include "icmp6-util-unix.h"

send_ra_t send_ra_function = NULL;
int test_fd[2] = PIPE_EBADF;

int icmp6_bind_router_solicitation(int ifindex) {
        if (test_fd[0] < 0 &&
            socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int icmp6_bind_router_advertisement(int ifindex) {
        if (test_fd[1] < 0 &&
            socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[1];
}

int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {
        if (!send_ra_function)
                return 0;

        return send_ra_function(0);
}

int icmp6_receive(
                int fd,
                void *iov_base,
                size_t iov_len,
                struct in6_addr *ret_sendor,
                triple_timestamp *ret_timestamp) {

        assert_se(read (fd, iov_base, iov_len) == (ssize_t) iov_len);

        if (ret_timestamp)
                triple_timestamp_get(ret_timestamp);

        return 0;
}

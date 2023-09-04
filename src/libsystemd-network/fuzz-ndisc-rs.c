/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <unistd.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "icmp6-util.h"
#include "ndisc-internal.h"
#include "socket-util.h"

static int test_fd[2] = PIPE_EBADF;

int icmp6_bind_router_solicitation(int index) {
        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);
        return test_fd[0];
}

int icmp6_bind_router_advertisement(int index) {
        return -ENOSYS;
}

static struct in6_addr dummy_link_local = {
        .s6_addr = {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x12, 0x34, 0x56, 0xff, 0xfe, 0x78, 0x9a, 0xbc,
        },
};

int icmp6_receive(
                int fd,
                void *iov_base,
                size_t iov_len,
                struct in6_addr *ret_sender,
                triple_timestamp *ret_timestamp) {

        assert_se(read(fd, iov_base, iov_len) == (ssize_t) iov_len);

        if (ret_timestamp)
                triple_timestamp_get(ret_timestamp);

        if (ret_sender)
                *ret_sender = dummy_link_local;

        return 0;
}

int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
        };
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        if (outside_size_range(size, 0, 2048))
                return 0;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);
        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(write(test_fd[1], data, size) == (ssize_t) size);
        (void) sd_event_run(e, UINT64_MAX);
        assert_se(sd_ndisc_stop(nd) >= 0);
        close(test_fd[1]);

        return 0;
}

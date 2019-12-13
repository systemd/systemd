/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <unistd.h>

#include "alloc-util.h"
#include "icmp6-util.h"
#include "fuzz.h"
#include "sd-ndisc.h"
#include "socket-util.h"
#include "ndisc-internal.h"

static int test_fd[2] = { -1, -1 };

int icmp6_bind_router_solicitation(int index) {
        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);
        return test_fd[0];
}

int icmp6_bind_router_advertisement(int index) {
        return -ENOSYS;
}

int icmp6_receive(int fd, void *iov_base, size_t iov_len,
                  struct in6_addr *dst, triple_timestamp *timestamp) {
        assert_se(read(fd, iov_base, iov_len) == (ssize_t) iov_len);

        if (timestamp)
                triple_timestamp_get(timestamp);

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

        if (size > 2048)
                return 0;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);
        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(write(test_fd[1], data, size) == (ssize_t) size);
        (void) sd_event_run(e, (uint64_t) -1);
        assert_se(sd_ndisc_stop(nd) >= 0);
        close(test_fd[1]);

        return 0;
}

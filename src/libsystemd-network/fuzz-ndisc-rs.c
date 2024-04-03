/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <unistd.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "icmp6-packet.h"
#include "icmp6-util-unix.h"
#include "ndisc-internal.h"
#include "ndisc-option.h"
#include "socket-util.h"

static void test_with_sd_ndisc(const uint8_t *data, size_t size) {
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
        };
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

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
}

static void test_with_icmp6_packet(const uint8_t *data, size_t size) {
        static const struct sockaddr_in6 dst = {
                .sin6_family = AF_INET6,
                .sin6_addr = IN6ADDR_ALL_ROUTERS_MULTICAST_INIT,
        };

        _cleanup_close_pair_ int fd_pair[2] = EBADF_PAIR;
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        _cleanup_set_free_ Set *options = NULL;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fd_pair) >= 0);
        assert_se(write(fd_pair[1], data, size) == (ssize_t) size);

        if (icmp6_packet_receive(fd_pair[0], &packet) < 0)
                return;

        if (ndisc_parse_options(packet, &options) < 0)
                return;

        if (ndisc_send(fd_pair[1], &dst, icmp6_packet_get_header(packet), options, /* timestamp = */ 0) < 0)
                return;

        packet = icmp6_packet_unref(packet);
        options = set_free(options);

        if (icmp6_packet_receive(fd_pair[0], &packet) < 0)
                return;

        assert_se(ndisc_parse_options(packet, &options) >= 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, 0, 2048))
                return 0;

        fuzz_setup_logging();

        test_with_sd_ndisc(data, size);
        test_with_icmp6_packet(data, size);
        return 0;
}

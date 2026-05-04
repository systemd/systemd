/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dhcp-relay-internal.h"
#include "fd-util.h"
#include "fuzz.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "tests.h"

static const struct hw_addr_data bcast_addr = {
        .length = ETH_ALEN,
        .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        union in_addr_union a;

        fuzz_setup_logging();

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_dhcp_relay_unrefp) sd_dhcp_relay *relay = NULL;
        ASSERT_OK(sd_dhcp_relay_new(&relay));
        ASSERT_OK(sd_dhcp_relay_attach_event(relay, e, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_OK(in_addr_from_string(AF_INET, "198.51.100.1", &a));
        ASSERT_OK(sd_dhcp_relay_set_server_address(relay, &a.in));
        ASSERT_OK(sd_dhcp_relay_set_remote_id(relay, &IOVEC_MAKE_STRING("test-remote-id")));
        ASSERT_OK(sd_dhcp_relay_set_server_identifier_override(relay, true));

        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *upstream = NULL;
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4242, /* is_upstream= */ true, &upstream));
        ASSERT_OK(sd_dhcp_relay_interface_set_ifname(upstream, "test-upstream"));
        ASSERT_OK(in_addr_from_string(AF_INET, "198.51.100.2", &a));
        ASSERT_OK(sd_dhcp_relay_interface_set_address(upstream, &a.in));

        _cleanup_close_pair_ int upstream_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, upstream_fd));
        upstream->socket_fd = TAKE_FD(upstream_fd[0]);
        ASSERT_OK(sd_dhcp_relay_interface_start(upstream));

        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *downstream = NULL;
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4343, /* is_upstream= */ false, &downstream));
        ASSERT_OK(sd_dhcp_relay_interface_set_ifname(downstream, "test-downstream"));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.1", &a));
        ASSERT_OK(sd_dhcp_relay_interface_set_address(downstream, &a.in));

        ASSERT_OK(sd_dhcp_relay_downstream_set_broadcast_address(downstream, ARPHRD_ETHER, bcast_addr.length, bcast_addr.bytes));
        ASSERT_OK(in_addr_from_string(AF_INET, "203.0.113.1", &a));
        ASSERT_OK(sd_dhcp_relay_downstream_set_gateway_address(downstream, &a.in));
        ASSERT_OK(sd_dhcp_relay_downstream_set_circuit_id(downstream, &IOVEC_MAKE_STRING("test-circuit-id")));
        ASSERT_OK(sd_dhcp_relay_downstream_set_virtual_subnet_selection(downstream, &IOVEC_MAKE_STRING("test-virtual-net")));

        _cleanup_close_pair_ int downstream_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, downstream_fd));
        downstream->socket_fd = TAKE_FD(downstream_fd[0]);
        ASSERT_OK(sd_dhcp_relay_interface_start(downstream));

        (void) downstream_process_message(downstream, &IOVEC_MAKE(data, size), /* pktinfo= */ NULL);
        (void) upstream_process_message(upstream, &IOVEC_MAKE(data, size), /* pktinfo= */ NULL);

        return 0;
}

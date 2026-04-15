/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "dhcp-client-internal.h"
#include "dhcp-lease-internal.h"
#include "dhcp-message.h"
#include "fd-util.h"
#include "fuzz.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "tests.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static const struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
                .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
        }, bcast_addr = {
                .length = ETH_ALEN,
                .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
        };

        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", /* overwrite= */ true));

        fuzz_setup_logging();

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client));
        ASSERT_NOT_NULL(client);

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));
        client->socket_fd = TAKE_FD(socket_fd[0]);

        /* Set a fake socket address, as the client will never call dhcp_network_bind_raw_socket() when
         * socket_fd is set. */
        client->link.ll = (struct sockaddr_ll) {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = 42,
                .sll_hatype = ARPHRD_ETHER,
                .sll_halen = bcast_addr.length,
        };
        memcpy(client->link.ll.sll_addr, bcast_addr.bytes, bcast_addr.length);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, /* priority= */ 0));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));

        ASSERT_OK(sd_dhcp_client_start(client));
        client->xid = 2;
        client->state = DHCP_STATE_SELECTING;

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        if (dhcp_client_parse_message(client, &IOVEC_MAKE(data, size), &lease) >= 0) {
                /* Build json variant and parse it. */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                ASSERT_OK(dhcp_message_build_json(lease->message, &v));

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
                ASSERT_OK(dhcp_message_parse_json(v, &m));

                /* Build UDP payload and parse it. */
                _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
                ASSERT_OK(dhcp_message_build(lease->message, &iovw));

                _cleanup_(iovec_done) struct iovec iov = {};
                ASSERT_OK(iovw_concat(&iovw, &iov));

                _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease2 = NULL;
                ASSERT_OK(dhcp_client_parse_message(client, &iov, &lease2));

                /* Build UDP payload again, and compare with the previous one. */
                _cleanup_(iovw_done_free) struct iovec_wrapper iovw2 = {};
                ASSERT_OK(dhcp_message_build(lease2->message, &iovw2));

                ASSERT_TRUE(iovw_equal(&iovw, &iovw2));
        }

        ASSERT_OK(sd_dhcp_client_stop(client));
        return 0;
}

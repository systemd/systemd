/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "event-util.h"
#include "fd-util.h"
#include "fuzz.h"

static int test_dhcp_fd[2] = { -1, -1 };

int dhcp6_network_send_udp_socket(int s, struct in6_addr *server_address, const void *packet, size_t len) {
        return len;
}

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *local_address) {
        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_dhcp_fd) >= 0);
        return TAKE_FD(test_dhcp_fd[0]);
}

static void fuzz_client(sd_dhcp6_client *client, const uint8_t *data, size_t size, DHCP6State state) {
        assert_se(sd_dhcp6_client_set_information_request(client, state == DHCP6_STATE_INFORMATION_REQUEST) >= 0);
        assert_se(sd_dhcp6_client_start(client) >= 0);

        client->state = state;

        if (size >= sizeof(DHCP6Message))
                assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message *) data)->transaction_id) == 0);

        assert_se(write(test_dhcp_fd[1], data, size) == (ssize_t) size);

        assert_se(sd_event_run(sd_dhcp6_client_get_event(client), UINT64_MAX) > 0);

        /* Check the state transition. */
        if (client->state != state)
                switch (state) {
                case DHCP6_STATE_INFORMATION_REQUEST:
                        assert_se(client->state == DHCP6_STATE_STOPPED);
                        break;
                case DHCP6_STATE_SOLICITATION:
                        assert_se(IN_SET(client->state, DHCP6_STATE_REQUEST, DHCP6_STATE_BOUND));
                        break;
                case DHCP6_STATE_REQUEST:
                        assert_se(client->state == DHCP6_STATE_BOUND);
                        break;
                default:
                        assert_not_reached();
                }

        assert_se(sd_dhcp6_client_stop(client) >= 0);

        test_dhcp_fd[1] = safe_close(test_dhcp_fd[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };

        if (size > 65536)
                return 0;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, 42) >= 0);
        assert_se(sd_dhcp6_client_set_local_address(client, &address) >= 0);
        dhcp6_client_set_test_mode(client, true);

        fuzz_client(client, data, size, DHCP6_STATE_INFORMATION_REQUEST);
        fuzz_client(client, data, size, DHCP6_STATE_SOLICITATION);

        /* If size is zero, then the resend timer will be triggered at first,
         * but in the REQUEST state the client must have a lease. */
        if (size == 0)
                return 0;

        fuzz_client(client, data, size, DHCP6_STATE_REQUEST);

        return 0;
}

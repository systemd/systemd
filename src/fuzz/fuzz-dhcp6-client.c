/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "fuzz.h"

static int test_dhcp_fd[2] = { -1, -1 };

int dhcp6_network_send_udp_socket(int s, struct in6_addr *server_address,
                                  const void *packet, size_t len) {
        return len;
}

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *local_address) {
        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_dhcp_fd) >= 0);
        return test_dhcp_fd[0];
}

static void fuzz_client(const uint8_t *data, size_t size, bool is_information_request_enabled) {
        _cleanup_(sd_event_unrefp) sd_event *e;
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, 42) == 0);
        assert_se(sd_dhcp6_client_set_local_address(client, &address) >= 0);
        assert_se(sd_dhcp6_client_set_information_request(client, is_information_request_enabled) == 0);

        assert_se(sd_dhcp6_client_start(client) >= 0);

        if (size >= sizeof(DHCP6Message))
                assert_se(sd_dhcp6_client_set_transaction_id(client, htobe32(0x00ffffff) & ((const DHCP6Message *) data)->transaction_id) == 0);

        assert_se(write(test_dhcp_fd[1], data, size) == (ssize_t) size);

        sd_event_run(e, (uint64_t) -1);

        assert_se(sd_dhcp6_client_stop(client) >= 0);

        test_dhcp_fd[1] = safe_close(test_dhcp_fd[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size > 65536)
                return 0;

        /* This triggers client_receive_advertise */
        fuzz_client(data, size, false);

        /* This triggers client_receive_reply */
        fuzz_client(data, size, true);

        return 0;
}

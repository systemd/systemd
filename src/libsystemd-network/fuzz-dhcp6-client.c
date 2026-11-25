/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "event-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "tests.h"

static int test_dhcp_fd[2] = EBADF_PAIR;

int dhcp6_network_send_udp_socket(int s, const struct in6_addr *server_address, const void *packet, size_t len) {
        return len;
}

int dhcp6_network_bind_udp_socket(int index, const struct in6_addr *local_address) {
        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_dhcp_fd));
        return TAKE_FD(test_dhcp_fd[0]);
}

static void fuzz_client(sd_dhcp6_client *client, const uint8_t *data, size_t size, DHCP6State state) {
        ASSERT_OK(sd_dhcp6_client_set_information_request(client, state == DHCP6_STATE_INFORMATION_REQUEST));
        ASSERT_OK(sd_dhcp6_client_start(client));

        client->state = state;

        if (size >= sizeof(DHCP6Message))
                ASSERT_OK_ZERO(dhcp6_client_set_transaction_id(client, ((const DHCP6Message *) data)->transaction_id));

        /* These states does not require lease to send message. */
        if (IN_SET(client->state, DHCP6_STATE_INFORMATION_REQUEST, DHCP6_STATE_SOLICITATION))
                ASSERT_OK(dhcp6_client_send_message(client));

        ASSERT_EQ(write(test_dhcp_fd[1], data, size), (ssize_t) size);

        ASSERT_OK_POSITIVE(sd_event_run(sd_dhcp6_client_get_event(client), UINT64_MAX));

        /* Check the state transition. */
        if (client->state != state)
                switch (state) {
                case DHCP6_STATE_INFORMATION_REQUEST:
                        ASSERT_EQ(client->state, DHCP6_STATE_STOPPED);
                        break;
                case DHCP6_STATE_SOLICITATION:
                        ASSERT_TRUE(IN_SET(client->state, DHCP6_STATE_REQUEST, DHCP6_STATE_BOUND));
                        break;
                case DHCP6_STATE_REQUEST:
                        ASSERT_TRUE(IN_SET(client->state, DHCP6_STATE_BOUND, DHCP6_STATE_SOLICITATION));
                        break;
                default:
                        assert_not_reached();
                }

        /* Send message if the client has a lease. */
        if (state != DHCP6_STATE_INFORMATION_REQUEST && sd_dhcp6_client_get_lease(client, /* ret= */ NULL) >= 0) {
                client->state = DHCP6_STATE_REQUEST;
                dhcp6_client_send_message(client);
        }

        ASSERT_OK(sd_dhcp6_client_stop(client));

        test_dhcp_fd[1] = safe_close(test_dhcp_fd[1]);
}

static void fuzz_reconfigure(sd_dhcp6_client *client, const uint8_t *data, size_t size, bool information_request) {
        static const uint8_t duid[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        static const uint8_t serverid[] = { 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;

        /* Fixed IDs and key, so that the corpus can contain valid Reconfigure messages. */
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(client, /* duid_type= */ 0xffff, duid, sizeof(duid)));
        ASSERT_OK(sd_dhcp6_client_set_information_request(client, information_request));
        ASSERT_OK(sd_dhcp6_client_start(client));

        /* Only Reconfigure messages are processed when bound, or when stopped with a lease in the
         * information request mode. */
        ASSERT_OK(dhcp6_lease_new(&lease));
        ASSERT_OK(dhcp6_lease_set_serverid(lease, serverid, sizeof(serverid)));
        sd_dhcp6_lease_unref(client->lease);
        client->lease = TAKE_PTR(lease);
        client->reconfigure_key = (DHCPRKAPKey) { .set = true, .key = { 1, 2, 3 } };
        client->state = information_request ? DHCP6_STATE_STOPPED : DHCP6_STATE_BOUND;
        (void) event_source_disable(client->timeout_resend);

        ASSERT_EQ(write(test_dhcp_fd[1], data, size), (ssize_t) size);

        ASSERT_OK_POSITIVE(sd_event_run(sd_dhcp6_client_get_event(client), UINT64_MAX));

        if (information_request)
                ASSERT_TRUE(IN_SET(client->state, DHCP6_STATE_STOPPED, DHCP6_STATE_INFORMATION_REQUEST));
        else
                ASSERT_TRUE(IN_SET(client->state, DHCP6_STATE_BOUND, DHCP6_STATE_RENEW, DHCP6_STATE_REBIND,
                                   DHCP6_STATE_INFORMATION_REQUEST));

        ASSERT_OK(sd_dhcp6_client_stop(client));

        test_dhcp_fd[1] = safe_close(test_dhcp_fd[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_dhcp6_option_unrefp) sd_dhcp6_option *v1 = NULL, *v2 = NULL;
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };
        struct in6_addr hint = { { { 0x3f, 0xfe, 0x05, 0x01, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } } };
        static const char *v1_data = "hogehoge", *v2_data = "foobar";

        ASSERT_OK(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", 1));

        fuzz_setup_logging();

        if (outside_size_range(size, /* lower= */ 0, 65536))
                return 0;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, e, /* priority= */ 0));
        ASSERT_OK(sd_dhcp6_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp6_client_set_local_address(client, &address));

        /* Used when sending message. */
        ASSERT_EQ(sd_dhcp6_client_set_fqdn(client, "example.com"), 1);
        ASSERT_OK(sd_dhcp6_client_set_request_mud_url(client, "https://www.example.com/mudfile.json"));
        ASSERT_OK(sd_dhcp6_client_set_request_user_class(client, STRV_MAKE("u1", "u2", "u3")));
        ASSERT_OK(sd_dhcp6_client_set_request_vendor_class(client, STRV_MAKE("v1", "v2", "v3")));
        ASSERT_OK(sd_dhcp6_client_set_prefix_delegation_hint(client, 48, &hint));
        ASSERT_OK(sd_dhcp6_option_new(123, v1_data, strlen(v1_data), 12345, &v1));
        ASSERT_OK(sd_dhcp6_option_new(456, v2_data, strlen(v2_data), 45678, &v2));
        ASSERT_OK(sd_dhcp6_client_add_vendor_option(client, v1));
        ASSERT_OK(sd_dhcp6_client_add_vendor_option(client, v2));
        ASSERT_OK(sd_dhcp6_client_set_accept_reconfigure(client, /* enable= */ true));

        fuzz_client(client, data, size, DHCP6_STATE_INFORMATION_REQUEST);
        fuzz_client(client, data, size, DHCP6_STATE_SOLICITATION);

        /* If size is zero, then the resend timer will be triggered at first,
         * but in the REQUEST state the client must have a lease. */
        if (size == 0)
                return 0;

        fuzz_client(client, data, size, DHCP6_STATE_REQUEST);

        /* These set a fixed DUID, hence run them last. */
        fuzz_reconfigure(client, data, size, /* information_request= */ false);
        fuzz_reconfigure(client, data, size, /* information_request= */ true);

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"

#include "sd-dhcp6-client.c"

int dhcp6_network_send_udp_socket(int s, struct in6_addr *server_address,
                                  const void *packet, size_t len) {
        return len;
}

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *local_address) {
        int fd;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        assert_se(fd >= 0);

        return fd;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };
        int r;

        if (size < sizeof(DHCP6Message))
                return 0;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, 42) == 0);
        assert_se(sd_dhcp6_client_set_fqdn(client, "example.com") == 1);
        assert_se(sd_dhcp6_client_set_request_mud_url(client, "https://www.example.com/mudfile.json") >= 0);
        assert_se(sd_dhcp6_client_set_request_user_class(client, STRV_MAKE("u1", "u2", "u3")) >= 0);
        assert_se(sd_dhcp6_client_set_request_vendor_class(client, STRV_MAKE("v1", "v2", "v3")) >= 0);
        assert_se(sd_dhcp6_client_set_local_address(client, &address) >= 0);
        assert_se(sd_dhcp6_client_set_information_request(client, false) == 0);
        dhcp6_client_set_test_mode(client, true);
        assert_se(sd_dhcp6_client_start(client) >= 0);
        assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message *) data)->transaction_id) == 0);

        r = client_process_advertise_or_rapid_commit_reply(client, (DHCP6Message *) data, size, NULL, NULL);
        if (r < 0)
                goto cleanup;

        if (client->state != DHCP6_STATE_REQUEST)
                client->state = DHCP6_STATE_SOLICITATION;
        (void) client_send_message(client);
cleanup:
        assert_se(sd_dhcp6_client_stop(client) >= 0);
        return 0;
}

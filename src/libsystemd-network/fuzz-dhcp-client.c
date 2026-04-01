/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "dhcp-client-internal.h"
#include "dhcp-lease-internal.h"
#include "dhcp-message.h"
#include "dhcp-network.h"
#include "fuzz.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "tests.h"

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t id,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *bcast_addr,
                uint16_t arp_type,
                uint16_t port,
                bool so_priority_set,
                int so_priority) {

        return ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
}

int dhcp_network_send_raw_socket(int fd, const union sockaddr_union *link, const struct iovec_wrapper *iovw) {
        return 0;
}

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type) {
        return ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
}

int dhcp_network_send_udp_socket(int fd, be32_t address, uint16_t port, const struct iovec_wrapper *iovw) {
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static const uint8_t mac_addr[] = {'A', 'B', 'C', '1', '2', '3'};
        static const uint8_t bcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", /* overwrite= */ true));

        fuzz_setup_logging();

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ false));
        ASSERT_NOT_NULL(client);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, /* priority= */ 0));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, mac_addr, bcast_addr, ETH_ALEN, ARPHRD_ETHER));

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

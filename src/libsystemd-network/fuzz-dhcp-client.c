/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dhcp-network.h"
#include "fd-util.h"
#include "fuzz.h"
#include "network-internal.h"
#include "sd-dhcp-client.c"
#include "tests.h"
#include "tmpfile-util.h"

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

        if (client_handle_offer_or_rapid_ack(client, (DHCPMessage*) data, size, NULL) >= 0) {
                _cleanup_(unlink_tempfilep) char lease_file[] = "/tmp/fuzz-dhcp-client.XXXXXX";
                _unused_ _cleanup_close_ int fd = ASSERT_OK(mkostemp_safe(lease_file));

                ASSERT_OK(dhcp_lease_save(client->lease, lease_file));

                _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
                ASSERT_OK(dhcp_lease_load(&lease, lease_file));
        }

        ASSERT_OK(sd_dhcp_client_stop(client));
        return 0;
}

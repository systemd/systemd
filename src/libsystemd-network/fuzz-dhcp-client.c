/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dhcp-network.h"
#include "fuzz.h"
#include "network-internal.h"
#include "sd-dhcp-client.c"
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

        int fd;
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        return fd;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link, const void *packet, size_t len) {
        return len;
}

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type) {
        int fd;

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        return fd;
}

int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port, const void *packet, size_t len) {
        return len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        uint8_t mac_addr[] = {'A', 'B', 'C', '1', '2', '3'};
        uint8_t bcast_addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_(unlink_tempfilep) char lease_file[] = "/tmp/fuzz-dhcp-client.XXXXXX";
        _cleanup_close_ int fd = -1;
        int res, r;

        assert_se(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", 1) >= 0);

        fuzz_setup_logging();

        r = sd_dhcp_client_new(&client, false);
        assert_se(r >= 0);
        assert_se(client);

        assert_se(sd_event_new(&e) >= 0);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_ifindex(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, mac_addr, bcast_addr, ETH_ALEN, ARPHRD_ETHER) >= 0);

        res = sd_dhcp_client_start(client);
        assert_se(IN_SET(res, 0, -EINPROGRESS));
        client->xid = 2;
        client->state = DHCP_STATE_SELECTING;

        if (client_handle_offer_or_rapid_ack(client, (DHCPMessage*) data, size, NULL) < 0)
                goto end;

        fd = mkostemp_safe(lease_file);
        assert_se(fd >= 0);

        r = dhcp_lease_save(client->lease, lease_file);
        assert_se(r >= 0);

        r = dhcp_lease_load(&lease, lease_file);
        assert_se(r >= 0);

end:
        assert_se(sd_dhcp_client_stop(client) >= 0);

        return 0;
}

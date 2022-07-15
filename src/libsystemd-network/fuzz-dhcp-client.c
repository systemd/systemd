/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fuzz.h"
#include "sd-event.h"

#include "sd-dhcp-client.c"

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t id,
                const uint8_t *addr, size_t addr_len,
                const uint8_t *bcaddr, size_t bcaddr_len,
                uint16_t arp_type, uint16_t port) {

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
        int res, r;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        r = sd_dhcp_client_new(&client, false);
        assert_se(r >= 0);
        assert_se(client);

        assert_se(sd_event_new(&e) >= 0);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_ifindex(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, mac_addr, bcast_addr, ETH_ALEN, ARPHRD_ETHER) >= 0);
        dhcp_client_set_test_mode(client, true);

        res = sd_dhcp_client_start(client);
        assert_se(IN_SET(res, 0, -EINPROGRESS));
        client->xid = 2;

        (void) client_handle_offer(client, (DHCPMessage*) data, size);

        assert_se(sd_dhcp_client_stop(client) >= 0);

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-dhcp-server.c"

#include "fuzz.h"

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
        return len;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        struct in_addr address = {.s_addr = htobe32(UINT32_C(10) << 24 | UINT32_C(1))};
        union in_addr_union relay_address;
        _cleanup_free_ uint8_t *message = NULL;

        if (size < sizeof(DHCPMessage))
                return 0;

        assert_se(sd_dhcp_server_new(&server, 1) >= 0);
        assert_se(sd_dhcp_server_attach_event(server, NULL, 0) >= 0);
        assert_se(sd_dhcp_server_configure_pool(server, &address, 24, 0, 0) >= 0);
        assert_se(in_addr_from_string(AF_INET, "192.168.5.1", &relay_address) >= 0);
        assert_se(sd_dhcp_server_set_relay_target(server, &relay_address.in) >= 0);
        assert_se(sd_dhcp_server_set_bind_to_interface(server, false) >= 0);
        assert_se(sd_dhcp_server_set_relay_agent_information(server, "string:sample_circuit_id", "string:sample_remote_id") >= 0);

        size_t buflen = size;
        buflen += relay_agent_information_length(server->agent_circuit_id, server->agent_remote_id) + 2;
        assert_se(message = malloc(buflen));
        memcpy(message, data, size);

        server->fd = open("/dev/null", O_RDWR|O_CLOEXEC|O_NOCTTY);
        assert_se(server->fd >= 0);

        (void) dhcp_server_relay_message(server, (DHCPMessage *) message, size - sizeof(DHCPMessage), buflen);
        return 0;
}

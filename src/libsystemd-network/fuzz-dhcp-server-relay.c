/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "dhcp-server-internal.h"
#include "dhcp-server-request.h"
#include "fuzz.h"
#include "in-addr-util.h"
#include "iovec-util.h"

ssize_t sendto(int __fd, const void *__buf, size_t __n, int flags, const struct sockaddr *__addr, socklen_t __addr_len) {
        return __n;
}

ssize_t sendmsg(int __fd, const struct msghdr *__message, int flags) {
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        struct in_addr address = {.s_addr = htobe32(UINT32_C(10) << 24 | UINT32_C(1))};
        union in_addr_union relay_address;

        fuzz_setup_logging();

        assert_se(sd_dhcp_server_new(&server, 1) >= 0);
        assert_se(sd_dhcp_server_attach_event(server, NULL, 0) >= 0);
        assert_se(sd_dhcp_server_configure_pool(server, &address, 24, 0, 0) >= 0);
        assert_se(in_addr_from_string(AF_INET, "192.168.5.1", &relay_address) >= 0);
        assert_se(sd_dhcp_server_set_relay_target(server, &relay_address.in) >= 0);
        assert_se(sd_dhcp_server_set_bind_to_interface(server, false) >= 0);
        assert_se(sd_dhcp_server_set_relay_agent_information(server, "string:sample_circuit_id", "string:sample_remote_id") >= 0);

        server->fd = open("/dev/null", O_RDWR|O_CLOEXEC|O_NOCTTY);
        assert_se(server->fd >= 0);

        (void) dhcp_server_relay_message(server, &IOVEC_MAKE(data, size));
        return 0;
}

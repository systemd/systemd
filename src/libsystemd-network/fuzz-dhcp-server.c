/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <net/if_arp.h>

#include "fuzz.h"
#include "rm-rf.h"
#include "sd-dhcp-server.c"
#include "tmpfile-util.h"

/* stub out network so that the server doesn't send */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
        return len;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
        return 0;
}

static int add_lease(sd_dhcp_server *server, const struct in_addr *server_address, uint8_t i) {
        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = NULL;
        int r;

        assert(server);

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
                .address = htobe32(UINT32_C(10) << 24 | i),
                .chaddr = { 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 },
                .expiration = usec_add(now(CLOCK_BOOTTIME), USEC_PER_DAY),
                .gateway = server_address->s_addr,
                .hlen = ETH_ALEN,
                .htype = ARPHRD_ETHER,

                .client_id.size = 2,
        };

        lease->client_id.raw[0] = 2;
        lease->client_id.raw[1] = i;

        r = dhcp_server_put_lease(server, lease, /* is_static = */ false);
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

static int add_static_lease(sd_dhcp_server *server, uint8_t i) {
        uint8_t id[2] = { 2, i };

        assert(server);

        return sd_dhcp_server_set_static_lease(
                                server,
                                &(struct in_addr) { .s_addr = htobe32(UINT32_C(10) << 24 | i)},
                                id, ELEMENTSOF(id));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        struct in_addr address = { .s_addr = htobe32(UINT32_C(10) << 24 | UINT32_C(1))};
        _cleanup_free_ uint8_t *duped = NULL;
        _cleanup_close_ int dir_fd = -EBADF;

        if (size < sizeof(DHCPMessage))
                return 0;

        fuzz_setup_logging();

        assert_se(duped = memdup(data, size));

        dir_fd = mkdtemp_open(NULL, 0, &tmpdir);
        assert_se(dir_fd >= 0);

        assert_se(sd_dhcp_server_new(&server, 1) >= 0);
        assert_se(sd_dhcp_server_attach_event(server, NULL, 0) >= 0);
        assert_se(sd_dhcp_server_set_lease_file(server, dir_fd, "leases") >= 0);
        server->fd = open("/dev/null", O_RDWR|O_CLOEXEC|O_NOCTTY);
        assert_se(server->fd >= 0);
        assert_se(sd_dhcp_server_configure_pool(server, &address, 24, 0, 0) >= 0);

        /* add leases to the pool to expose additional code paths */
        assert_se(add_lease(server, &address, 2) >= 0);
        assert_se(add_lease(server, &address, 3) >= 0);

        /* add static leases */
        assert_se(add_static_lease(server, 3) >= 0);
        assert_se(add_static_lease(server, 4) >= 0);

        (void) dhcp_server_handle_message(server, (DHCPMessage*) duped, size, NULL);

        assert_se(dhcp_server_save_leases(server) >= 0);
        server->bound_leases_by_address = hashmap_free(server->bound_leases_by_address);
        server->bound_leases_by_client_id = hashmap_free(server->bound_leases_by_client_id);
        assert_se(dhcp_server_load_leases(server) >= 0);

        return 0;
}

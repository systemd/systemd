/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "fd-util.h"
#include "fuzz.h"
#include "hashmap.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

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

        r = dhcp_server_put_lease(server, lease, /* is_static= */ false);
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
                        &(struct in_addr) { .s_addr = htobe32(UINT32_C(10) << 24 | i) },
                        id,
                        ELEMENTSOF(id),
                        /* hostname= */ NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        struct in_addr address = { .s_addr = htobe32(UINT32_C(10) << 24 | UINT32_C(1))};

        if (size < sizeof(DHCPMessage))
                return 0;

        fuzz_setup_logging();

        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(mkdtemp_open(NULL, 0, &tmpdir));

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 1));
        ASSERT_OK(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL));
        server->fd = ASSERT_OK_ERRNO(open("/dev/null", O_RDWR|O_CLOEXEC|O_NOCTTY));
        ASSERT_OK(sd_dhcp_server_set_lease_file(server, dir_fd, "leases"));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 24, 0, 0));

        /* add leases to the pool to expose additional code paths */
        ASSERT_OK(add_lease(server, &address, 2));
        ASSERT_OK(add_lease(server, &address, 3));

        /* add static leases */
        ASSERT_OK(add_static_lease(server, 3));
        ASSERT_OK(add_static_lease(server, 4));

        _cleanup_free_ uint8_t *duped = ASSERT_NOT_NULL(memdup(data, size));
        (void) dhcp_server_handle_message(server, (DHCPMessage*) duped, size, NULL);

        ASSERT_OK(dhcp_server_save_leases(server));
        server->bound_leases_by_address = hashmap_free(server->bound_leases_by_address);
        server->bound_leases_by_client_id = hashmap_free(server->bound_leases_by_client_id);
        ASSERT_OK(dhcp_server_load_leases(server));

        return 0;
}

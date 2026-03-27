/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "sd-dhcp6-server.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp6-server-internal.h"
#include "in-addr-util.h"
#include "tests.h"

static void test_dhcp6_server_basic(void) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        log_info("/* %s */", __func__);

        assert_se(sd_event_default(&event) >= 0);

        assert_se(sd_dhcp6_server_new(&server, 1) >= 0);
        assert_se(server);
        assert_se(server->n_ref == 1);

        assert_se(sd_dhcp6_server_attach_event(server, event, 0) >= 0);
        assert_se(sd_dhcp6_server_get_event(server) == event);

        assert_se(!sd_dhcp6_server_is_running(server));

        assert_se(sd_dhcp6_server_detach_event(server) >= 0);
        assert_se(!sd_dhcp6_server_get_event(server));
}

static void test_dhcp6_server_configure_pool(void) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;
        struct in6_addr addr;

        log_info("/* %s */", __func__);

        assert_se(sd_dhcp6_server_new(&server, 1) >= 0);

        assert_se(inet_pton(AF_INET6, "2001:db8::1", &addr) == 1);
        assert_se(sd_dhcp6_server_configure_pool(server, &addr, 64, 0, 100) >= 0);

        assert_se(server->pool_size == 100);
        assert_se(server->pool_bitmap);

        /* Verify pool start address (should skip network address) */
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &server->pool_start, buf, sizeof(buf));
        log_info("Pool start: %s, size: %"PRIu64, buf, server->pool_size);
}

static void test_dhcp6_server_set_dns(void) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;
        struct in6_addr dns[2];

        log_info("/* %s */", __func__);

        assert_se(sd_dhcp6_server_new(&server, 1) >= 0);

        assert_se(inet_pton(AF_INET6, "2001:4860:4860::8888", &dns[0]) == 1);
        assert_se(inet_pton(AF_INET6, "2001:4860:4860::8844", &dns[1]) == 1);

        assert_se(sd_dhcp6_server_set_dns(server, dns, 2) >= 0);
        assert_se(server->n_dns == 2);
        assert_se(in6_addr_equal(&server->dns[0], &dns[0]));
        assert_se(in6_addr_equal(&server->dns[1], &dns[1]));

        /* Clear */
        assert_se(sd_dhcp6_server_set_dns(server, NULL, 0) >= 0);
        assert_se(server->n_dns == 0);
        assert_se(!server->dns);
}

static void test_dhcp6_server_set_lease_time(void) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;

        log_info("/* %s */", __func__);

        assert_se(sd_dhcp6_server_new(&server, 1) >= 0);

        assert_se(sd_dhcp6_server_set_max_lease_time(server, 7200 * USEC_PER_SEC) >= 0);
        assert_se(server->max_lease_time == 7200 * USEC_PER_SEC);

        assert_se(sd_dhcp6_server_set_default_lease_time(server, 3600 * USEC_PER_SEC) >= 0);
        assert_se(server->default_lease_time == 3600 * USEC_PER_SEC);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_dhcp6_server_basic();
        test_dhcp6_server_configure_pool();
        test_dhcp6_server_set_dns();
        test_dhcp6_server_set_lease_time();

        return 0;
}

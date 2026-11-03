/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dns-packet.h"
#include "fd-util.h"
#include "hashmap.h"
#include "ordered-set.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "tests.h"

/* ================================================================
 * manager_recv()
 * ================================================================ */

TEST(manager_recv_nothing_to_read) {
        Manager manager = {};
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_close_ int fd = -EBADF;

        /* The event source may hand us a socket whose datagram is gone by the time we look at it: the
         * MSG_PEEK recv() in next_datagram_size_fd() verifies the UDP checksum and drops the datagram if it
         * is bad. That must be reported as "no packet", not as an error, as our callers pass an error on to
         * the event loop, which then turns the listening socket's event source off. An empty non-blocking
         * socket puts us in exactly that situation. */

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        ASSERT_OK_ERRNO(fd);

        ASSERT_OK_ZERO(manager_recv(&manager, fd, DNS_PROTOCOL_DNS, &p));
        ASSERT_NULL(p);
}

TEST(manager_compile_dns_servers_filters_before_deduplicating) {
        _cleanup_ordered_set_free_ OrderedSet *servers = NULL;
        Manager manager = {};
        Link *route_only_link, *default_route_link;
        DnsScope *route_only_scope, *default_route_scope;
        DnsServer *route_only_server, *default_route_server;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000235) };

        ASSERT_OK(link_new(&manager, &route_only_link, 1));
        route_only_link->default_route = false;
        ASSERT_OK(dns_scope_new(&manager, &route_only_scope, DNS_SCOPE_LINK, route_only_link, /* delegate= */ NULL,
                                DNS_PROTOCOL_DNS, AF_INET));
        route_only_link->unicast_scope = route_only_scope;
        ASSERT_OK(dns_server_new(&manager, &route_only_server, DNS_SERVER_LINK, route_only_link,
                                 /* delegate= */ NULL, AF_INET, &address, 53, /* ifindex= */ 0,
                                 /* server_name= */ NULL, RESOLVE_CONFIG_SOURCE_DBUS));

        ASSERT_OK(link_new(&manager, &default_route_link, 2));
        default_route_link->default_route = true;
        ASSERT_OK(dns_scope_new(&manager, &default_route_scope, DNS_SCOPE_LINK, default_route_link, /* delegate= */ NULL,
                                DNS_PROTOCOL_DNS, AF_INET));
        default_route_link->unicast_scope = default_route_scope;
        ASSERT_OK(dns_server_new(&manager, &default_route_server, DNS_SERVER_LINK, default_route_link,
                                 /* delegate= */ NULL, AF_INET, &address, 53, /* ifindex= */ 0,
                                 /* server_name= */ NULL, RESOLVE_CONFIG_SOURCE_DBUS));

        ASSERT_OK(manager_compile_dns_servers(&manager, &servers));
        ASSERT_EQ(ordered_set_size(servers), 1u);
        ASSERT_PTR_EQ(ordered_set_first(servers), default_route_server);

        /* Check both assignments so the test does not depend on link iteration order. */
        route_only_link->default_route = true;
        default_route_link->default_route = false;
        ordered_set_clear(servers);
        ASSERT_OK(manager_compile_dns_servers(&manager, &servers));
        ASSERT_EQ(ordered_set_size(servers), 1u);
        ASSERT_PTR_EQ(ordered_set_first(servers), route_only_server);

        manager.links = hashmap_free(manager.links);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

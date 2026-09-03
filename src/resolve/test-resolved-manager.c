/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dns-packet.h"
#include "fd-util.h"
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

DEFINE_TEST_MAIN(LOG_DEBUG);

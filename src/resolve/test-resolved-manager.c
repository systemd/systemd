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

/* ================================================================
 * manager_get_dnssec_mode()
 * ================================================================ */

TEST(manager_get_dnssec_mode_no_crypto) {
        Manager manager = {
                .dnssec_crypto = -EOPNOTSUPP,
        };

        /* Without libcrypto we can't validate, so allow-downgrade would always downgrade… */
        manager.dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        ASSERT_EQ(manager_get_dnssec_mode(&manager), DNSSEC_NO);
        ASSERT_FALSE(manager_dnssec_supported(&manager));

        /* … but DNSSEC=yes stays, so that lookups fail instead */
        manager.dnssec_mode = DNSSEC_YES;
        ASSERT_EQ(manager_get_dnssec_mode(&manager), DNSSEC_YES);

        manager.dnssec_mode = DNSSEC_NO;
        ASSERT_EQ(manager_get_dnssec_mode(&manager), DNSSEC_NO);

        manager.dnssec_crypto = 1;
        manager.dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        ASSERT_EQ(manager_get_dnssec_mode(&manager), DNSSEC_ALLOW_DOWNGRADE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

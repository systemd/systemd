/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "fd-util.h"
#include "resolved-dns-stream.h"
#include "resolved-manager.h"
#include "set.h"
#include "tests.h"

static int on_packet(DnsStream *s, DnsPacket *p) {
        assert_not_reached();
}

TEST(dns_stream_free_queries) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_stream_unrefp) DnsStream *stream = NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        Manager manager = {};
        int query;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair));
        ASSERT_OK(dns_stream_new(&manager, &stream, DNS_STREAM_STUB, DNS_PROTOCOL_DNS, pair[0],
                                 /* tfo_address= */ NULL, on_packet, /* complete= */ NULL,
                                 DNS_STREAM_STUB_TIMEOUT_USEC));
        TAKE_FD(pair[0]);

        /* Completed stub queries leave an allocated, empty set. LeakSanitizer checks that freeing the
         * stream also frees this set. */
        ASSERT_OK(set_ensure_put(&stream->queries, /* hash_ops= */ NULL, &query));
        ASSERT_PTR_EQ(set_remove(stream->queries, &query), &query);
        ASSERT_TRUE(set_isempty(stream->queries));
        ASSERT_NOT_NULL(stream->queries);

        stream = dns_stream_unref(stream);
        ASSERT_NULL(stream);
        ASSERT_NULL(manager.dns_streams);
        ASSERT_EQ(manager.n_dns_streams[DNS_STREAM_STUB], 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

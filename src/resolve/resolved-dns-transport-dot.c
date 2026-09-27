/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_TLS
#error This source file requires DNS-over-TLS to be enabled.
#endif

#include "sd-messages.h"

#include "log.h"
#include "resolve-util.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-transaction.h"
#include "resolved-dns-transport-dot.h"

static void dns_transport_dot_done(DnsServerTransport *tr) {
        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));

        dnstls_server_data_done(&d->tls_data);
}

static void dns_transport_dot_reset_counters(DnsServerTransport *tr) {
        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));

        d->n_failed = 0;
}

static void dns_transport_dot_packet_received(
                DnsServerTransport *tr,
                int protocol,
                DnsServerFeatureLevel *level,
                bool at_possible_level,
                size_t fragsize) {

        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));

        if (protocol == IPPROTO_TCP && at_possible_level)
                d->n_failed = 0;
}

static void dns_transport_dot_packet_lost(DnsServerTransport *tr, int protocol) {
        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));

        if (protocol == IPPROTO_TCP)
                d->n_failed++;
}

static bool dns_transport_dot_failed(DnsServerTransport *tr) {
        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));

        /* A single failure suffices to consider DNS-over-TLS broken for this server */
        return d->n_failed > 0;
}

static int dns_transport_dot_open_stream(DnsServerTransport *tr, DnsTransaction *t, DnsStream **ret) {
        _cleanup_(dns_stream_unrefp) DnsStream *s = NULL;
        DnsTransportDot *d = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(tr));
        DnsServer *server = ASSERT_PTR(tr->server);
        usec_t timeout_usec = DNS_STREAM_DEFAULT_TIMEOUT_USEC;
        int r;

        assert(ret);

        if (tr->stream) {
                *ret = dns_stream_ref(tr->stream);
                return 0;
        }

        /* Lower timeout in DNS-over-TLS opportunistic mode. In environments where DoT is blocked without
         * ICMP response overly long delays when contacting DoT servers are nasty, in particular if multiple
         * DNS servers are defined which we try in turn and all are blocked. Hence, substantially lower the
         * timeout in that case. */
        if (dns_server_get_dns_over_tls_mode(server) == DNS_OVER_TLS_OPPORTUNISTIC)
                timeout_usec = DNS_STREAM_OPPORTUNISTIC_TLS_TIMEOUT_USEC;

        r = dns_server_transport_stream_new(tr, t, timeout_usec, &s);
        if (r < 0)
                return r;

        r = dnstls_stream_connect_tls(
                        s,
                        server->server_name,
                        server->family,
                        &server->address,
                        /* verify= */ dns_server_get_dns_over_tls_mode(server) == DNS_OVER_TLS_YES,
                        &d->tls_data);
        if (r == -EOPNOTSUPP) {
                /* If libcrypto is not available treat this like a TLS connection loss, so that opportunistic
                 * DNS-over-TLS downgrades to plaintext instead of re-selecting a TLS feature level and failing
                 * on every attempt. */
                log_struct_once(LOG_WARNING,
                                LOG_MESSAGE_ID(SD_MESSAGE_MISSING_DEPENDENCY_STR),
                                LOG_ITEM("FEATURE=DNS-over-TLS"),
                                LOG_MESSAGE("DNS-over-TLS has been requested but the required TLS libraries (libssl/libcrypto) are not installed."));
                dns_server_packet_lost(server, IPPROTO_TCP, t->current_feature_level);
                return -ECONNREFUSED;
        }
        if (r < 0)
                return r;

        dns_server_transport_set_stream(tr, s);

        *ret = TAKE_PTR(s);
        return 0;
}

const DnsTransportVTable dns_transport_dot_vtable = {
        .object_size = sizeof(DnsTransportDot),
        .default_port = 853,
        .edns_min = DNS_SERVER_EDNS_LEVEL_EDNS0, /* Our DNS-over-TLS implementation always requires EDNS0 */
        .done = dns_transport_dot_done,
        .reset_counters = dns_transport_dot_reset_counters,
        .packet_received = dns_transport_dot_packet_received,
        .packet_lost = dns_transport_dot_packet_lost,
        .failed = dns_transport_dot_failed,
        .open_stream = dns_transport_dot_open_stream,
};

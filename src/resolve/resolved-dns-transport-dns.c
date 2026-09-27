/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "dns-packet.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-transport-dns.h"

static void dns_transport_dns_reset_counters(DnsServerTransport *tr) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        d->n_failed_udp = 0;
        d->n_failed_tcp = 0;
        d->packet_truncated = false;
}

static void dns_transport_dns_reset_features(DnsServerTransport *tr) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        d->received_udp_fragment_max = DNS_PACKET_UNICAST_SIZE_MAX;
}

static void dns_transport_dns_packet_received(
                DnsServerTransport *tr,
                int protocol,
                DnsServerFeatureLevel *level,
                bool at_possible_level,
                size_t fragsize) {

        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        assert(level);

        if (protocol == IPPROTO_UDP) {
                if (at_possible_level)
                        d->n_failed_udp = 0;

                /* Remember the size of the largest UDP packet fragment we received from a server, we know
                 * that we can always announce support for packets with at least this size. */
                if (d->received_udp_fragment_max < fragsize)
                        d->received_udp_fragment_max = fragsize;

        } else if (protocol == IPPROTO_TCP) {
                if (at_possible_level)
                        d->n_failed_tcp = 0;

                /* Successful TCP connections are only useful to verify the TCP feature level. */
                *level = DNS_SERVER_FEATURE_LEVEL_TCP;
        }
}

static void dns_transport_dns_packet_lost(DnsServerTransport *tr, int protocol) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        if (protocol == IPPROTO_UDP)
                d->n_failed_udp++;
        else if (protocol == IPPROTO_TCP)
                d->n_failed_tcp++;
}

static void dns_transport_dns_packet_truncated(DnsServerTransport *tr) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        d->packet_truncated = true;
}

void dns_transport_dns_packet_fragmented(DnsTransportDns *d, size_t fragsize) {
        assert(d);

        /* Invoked whenever we got a fragmented UDP packet. Let's do two things: keep track of the largest
         * fragment we ever received from the server, and remember this, so that we can use it to lower the
         * advertised packet size in EDNS0 */

        if (d->received_udp_fragment_max < fragsize)
                d->received_udp_fragment_max = fragsize;

        d->packet_fragmented = true;
}

static bool dns_transport_dns_degrade(DnsServerTransport *tr, DnsServerFeatureLevel *level) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));
        DnsServer *s = ASSERT_PTR(tr->server);

        assert(level);

        if (d->n_failed_tcp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
            dns_server_feature_level_equal(*level, DNS_SERVER_FEATURE_LEVEL_TCP)) {

                /* We are at the TCP (lowest) level, and we tried a couple of TCP connections, and it didn't
                 * work. Upgrade back to UDP again. */
                log_debug("Reached maximum number of failed TCP connection attempts, trying UDP again...");
                *level = DNS_SERVER_FEATURE_LEVEL_UDP;
                return true;
        }

        if (d->n_failed_udp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
            DNS_SERVER_FEATURE_LEVEL_IS_UDP(*level) &&
            (!DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(*level) || dns_server_get_dnssec_mode(s) != DNSSEC_YES)) {

                /* We lost too many UDP packets in a row, and are on a UDP feature level. If the packets are
                 * lost, maybe the server cannot parse them, hence downgrading sounds like a good idea. We first
                 * lower the EDNS level, and eventually switch from UDP to TCP this way.
                 *
                 * If strict DNSSEC mode is used we won't downgrade below DO level however, as packet loss
                 * might have many reasons, a broken DNSSEC implementation being only one reason. And if the
                 * user is strict on DNSSEC, then let's assume that DNSSEC is not the fault here. */

                log_debug("Lost too many UDP packets, downgrading feature level...");
                if (level->edns > DNS_SERVER_EDNS_LEVEL_NONE)
                        level->edns--;
                else
                        *level = DNS_SERVER_FEATURE_LEVEL_TCP;
                return true;
        }

        if (d->n_failed_tcp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
            d->packet_truncated &&
            DNS_SERVER_FEATURE_LEVEL_IS_UDP(*level) &&
            DNS_SERVER_FEATURE_LEVEL_IS_EDNS0(*level) &&
            (!DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(*level) || dns_server_get_dnssec_mode(s) != DNSSEC_YES)) {

                /* We got too many TCP connection failures in a row, we had at least one truncated packet, and
                 * are on feature level above UDP. By downgrading things and getting rid of DNSSEC or EDNS0 data
                 * we hope to make the packet smaller, so that it still works via UDP given that TCP appears not
                 * to be a fallback. Note that if we are already at the lowest UDP level, we don't go further
                 * down, since that's TCP, and TCP failed too often after all. */

                log_debug("Got too many failed TCP connection failures and truncated UDP packets, downgrading feature level...");
                level->edns--; /* Go DNSSEC → EDNS0, or EDNS0 → UDP */
                return true;
        }

        return false;
}

static bool dns_transport_dns_dnssec_supported(DnsServerTransport *tr) {
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(tr));

        /* DNSSEC servers need to support TCP properly (see RFC5966), if they don't, we assume DNSSEC is borked too */
        return d->n_failed_tcp < DNS_SERVER_FEATURE_RETRY_ATTEMPTS;
}

static int dns_transport_dns_open_datagram(DnsServerTransport *tr, DnsScope *scope) {
        assert(tr);

        return dns_scope_socket_udp(scope, tr->server);
}

static int dns_transport_dns_open_stream(DnsServerTransport *tr, DnsTransaction *t, DnsStream **ret) {
        _cleanup_(dns_stream_unrefp) DnsStream *s = NULL;
        int r;

        assert(tr);
        assert(ret);

        if (tr->stream) {
                *ret = dns_stream_ref(tr->stream);
                return 0;
        }

        r = dns_server_transport_stream_new(tr, t, DNS_STREAM_DEFAULT_TIMEOUT_USEC, &s);
        if (r < 0)
                return r;

        dns_server_transport_set_stream(tr, s);

        *ret = TAKE_PTR(s);
        return 0;
}

const DnsTransportVTable dns_transport_dns_vtable = {
        .object_size = sizeof(DnsTransportDns),
        .default_port = 53,
        .edns_min = DNS_SERVER_EDNS_LEVEL_NONE,
        .reset_counters = dns_transport_dns_reset_counters,
        .reset_features = dns_transport_dns_reset_features,
        .packet_received = dns_transport_dns_packet_received,
        .packet_lost = dns_transport_dns_packet_lost,
        .packet_truncated = dns_transport_dns_packet_truncated,
        .degrade = dns_transport_dns_degrade,
        .dnssec_supported = dns_transport_dns_dnssec_supported,
        .open_datagram = dns_transport_dns_open_datagram,
        .open_stream = dns_transport_dns_open_stream,
};

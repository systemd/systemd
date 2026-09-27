/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-transaction.h"
#include "resolved-dns-transport.h"
#include "resolved-dns-transport-dns.h"
#include "resolved-dns-transport-dot.h"
#include "string-table.h"

static const char* const dns_transport_kind_table[_DNS_TRANSPORT_KIND_MAX] = {
        [DNS_TRANSPORT_DNS] = "dns",
        [DNS_TRANSPORT_DOT] = "dot",
};
DEFINE_STRING_TABLE_LOOKUP(dns_transport_kind, DnsTransportKind);

static const char* const dns_server_edns_level_table[_DNS_SERVER_EDNS_LEVEL_MAX] = {
        [DNS_SERVER_EDNS_LEVEL_NONE]  = "none",
        [DNS_SERVER_EDNS_LEVEL_EDNS0] = "edns0",
        [DNS_SERVER_EDNS_LEVEL_DO]    = "do",
};
DEFINE_STRING_TABLE_LOOKUP(dns_server_edns_level, DnsServerEdnsLevel);

int dns_server_feature_level_compare(DnsServerFeatureLevel a, DnsServerFeatureLevel b) {
        int r;

        /* Invalid feature levels sort before all valid ones */
        r = CMP(dns_server_feature_level_is_valid(a), dns_server_feature_level_is_valid(b));
        if (r != 0)
                return r;
        if (!dns_server_feature_level_is_valid(a))
                return 0;

        r = CMP(a.edns, b.edns);
        if (r != 0)
                return r;

        r = CMP(a.transport, b.transport);
        if (r != 0)
                return r;

        return CMP(a.udp, b.udp);
}

const char* dns_server_feature_level_to_string(DnsServerFeatureLevel l) {
        static const char* const table[_DNS_TRANSPORT_KIND_MAX][2][_DNS_SERVER_EDNS_LEVEL_MAX] = {
                [DNS_TRANSPORT_DNS] = {
                        [false] = {
                                [DNS_SERVER_EDNS_LEVEL_NONE]  = "TCP",
                                [DNS_SERVER_EDNS_LEVEL_EDNS0] = "TCP+EDNS0",
                                [DNS_SERVER_EDNS_LEVEL_DO]    = "TCP+EDNS0+DO",
                        },
                        [true] = {
                                [DNS_SERVER_EDNS_LEVEL_NONE]  = "UDP",
                                [DNS_SERVER_EDNS_LEVEL_EDNS0] = "UDP+EDNS0",
                                [DNS_SERVER_EDNS_LEVEL_DO]    = "UDP+EDNS0+DO",
                        },
                },
                [DNS_TRANSPORT_DOT] = {
                        [false] = {
                                [DNS_SERVER_EDNS_LEVEL_NONE]  = "TLS",
                                [DNS_SERVER_EDNS_LEVEL_EDNS0] = "TLS+EDNS0",
                                [DNS_SERVER_EDNS_LEVEL_DO]    = "TLS+EDNS0+DO",
                        },
                },
        };

        if (!dns_server_feature_level_is_valid(l) ||
            l.transport >= _DNS_TRANSPORT_KIND_MAX ||
            l.edns >= _DNS_SERVER_EDNS_LEVEL_MAX)
                return NULL;

        return table[l.transport][l.udp][l.edns];
}

DnsServerFeatureLevel dns_server_feature_level_for_transport(DnsTransportKind kind, DnsServerEdnsLevel edns) {
        const DnsTransportVTable *vt;

        assert(kind >= 0 && kind < _DNS_TRANSPORT_KIND_MAX);
        vt = ASSERT_PTR(dns_transport_vtable[kind]);

        /* Returns the best feature level of the transport at the specified EDNS level, or at a higher one if
         * the transport requires that. */

        return (DnsServerFeatureLevel) {
                .transport = kind,
                .edns = MAX(edns, vt->edns_min),
                .udp = !!vt->open_datagram,
        };
}

const DnsTransportVTable * const dns_transport_vtable[_DNS_TRANSPORT_KIND_MAX] = {
        [DNS_TRANSPORT_DNS] = &dns_transport_dns_vtable,
#if ENABLE_DNS_OVER_TLS
        [DNS_TRANSPORT_DOT] = &dns_transport_dot_vtable,
#endif
};

DnsServerTransport* dns_server_transport_new(DnsServer *s, DnsTransportKind kind) {
        const DnsTransportVTable *vt;
        DnsServerTransport *tr;

        assert(s);
        assert(kind >= 0 && kind < _DNS_TRANSPORT_KIND_MAX);

        vt = dns_transport_vtable[kind];
        if (!vt)
                return NULL;

        assert(vt->object_size >= sizeof(DnsServerTransport));

        tr = malloc0(vt->object_size);
        if (!tr)
                return NULL;

        tr->server = s;
        tr->kind = kind;

        if (vt->reset_features)
                vt->reset_features(tr);
        vt->reset_counters(tr);

        return tr;
}

DnsServerTransport* dns_server_transport_free(DnsServerTransport *tr) {
        if (!tr)
                return NULL;

        dns_server_transport_unref_stream(tr);

        if (DNS_TRANSPORT_VTABLE(tr)->done)
                DNS_TRANSPORT_VTABLE(tr)->done(tr);

        return mfree(tr);
}

uint16_t dns_server_transport_port(DnsServerTransport *tr) {
        assert(tr);

        if (tr->server->port > 0)
                return tr->server->port;

        return DNS_TRANSPORT_VTABLE(tr)->default_port;
}

int dns_server_transport_stream_new(DnsServerTransport *tr, DnsTransaction *t, usec_t connect_timeout_usec, DnsStream **ret) {
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        int r;

        assert(tr);
        assert(t);
        assert(ret);

        /* Opens a new TCP connection to the server, and wraps it in a stream. The stream is not remembered
         * as the long-lived one yet, see dns_server_transport_set_stream() for that. */

        fd = dns_scope_socket_tcp(t->scope, AF_UNSPEC, NULL, tr->server, dns_server_transport_port(tr), &sa);
        if (fd < 0)
                return fd;

        r = dns_transaction_stream_new(t, DNS_STREAM_LOOKUP, fd, &sa, connect_timeout_usec, ret);
        if (r < 0)
                return r;

        TAKE_FD(fd);
        return 0;
}

void dns_server_transport_set_stream(DnsServerTransport *tr, DnsStream *stream) {
        assert(tr);
        assert(stream);

        dns_server_transport_unref_stream(tr);

        /* The stream and the server reference each other, dns_stream_detach() breaks the cycle again */
        unref_and_replace_new_ref(stream->server, tr->server, dns_server_ref, dns_server_unref);
        stream->transport = tr;

        tr->stream = dns_stream_ref(stream);
}

void dns_server_transport_unref_stream(DnsServerTransport *tr) {
        DnsStream *ref;

        assert(tr);

        /* Detaches the default stream of this transport. Some special care needs to be taken here, as that
         * stream and the server reference each other. First, take the stream out of the transport. Its
         * destructor will check if it is registered with us, hence let's invalidate this separately, so that
         * it is already unregistered. */
        ref = TAKE_PTR(tr->stream);

        /* And then, unref it */
        dns_stream_unref(ref);
}

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

static const char* const dns_encryption_mode_table[_DNS_ENCRYPTION_MODE_MAX] = {
        [DNS_ENCRYPTION_NO]            = "no",
        [DNS_ENCRYPTION_OPPORTUNISTIC] = "opportunistic",
        [DNS_ENCRYPTION_REQUIRED]      = "required",
};
DEFINE_STRING_TABLE_LOOKUP(dns_encryption_mode, DnsEncryptionMode);

DnsEncryptionMode dns_encryption_mode_from_dns_over_tls_mode(DnsOverTlsMode m) {
        switch (m) {
        case DNS_OVER_TLS_NO:
                return DNS_ENCRYPTION_NO;
        case DNS_OVER_TLS_OPPORTUNISTIC:
                return DNS_ENCRYPTION_OPPORTUNISTIC;
        case DNS_OVER_TLS_YES:
                return DNS_ENCRYPTION_REQUIRED;
        case _DNS_OVER_TLS_MODE_MAX:
        case _DNS_OVER_TLS_MODE_INVALID:
                break;
        }

        assert_not_reached();
}

void dns_transport_policy_init(DnsEncryptionMode mode, DnsTransportPolicy *ret) {
        assert(ret);

        /* Derives the transports permitted for a server, from the most to the least preferred one. For now
         * servers are always configured by address, which leaves DNS-over-TLS as the only encrypted
         * transport. */

        switch (mode) {

        case DNS_ENCRYPTION_NO:
                *ret = (DnsTransportPolicy) {
                        .transports = { DNS_TRANSPORT_DNS },
                        .n_transports = 1,
                };
                break;

        case DNS_ENCRYPTION_OPPORTUNISTIC:
                *ret = (DnsTransportPolicy) {
                        .transports = { DNS_TRANSPORT_DOT, DNS_TRANSPORT_DNS },
                        .n_transports = 2,
                };
                break;

        case DNS_ENCRYPTION_REQUIRED:
                *ret = (DnsTransportPolicy) {
                        .transports = { DNS_TRANSPORT_DOT },
                        .n_transports = 1,
                };
                break;

        case _DNS_ENCRYPTION_MODE_MAX:
        case _DNS_ENCRYPTION_MODE_INVALID:
                assert_not_reached();
        }
}

bool dns_transport_policy_contains(const DnsTransportPolicy *p, DnsTransportKind kind) {
        assert(p);
        assert(p->n_transports <= ELEMENTSOF(p->transports));

        FOREACH_ARRAY(k, p->transports, p->n_transports)
                if (*k == kind)
                        return true;

        return false;
}

DnsTransportKind dns_transport_policy_next(const DnsTransportPolicy *p, DnsTransportKind kind) {
        assert(p);
        assert(p->n_transports <= ELEMENTSOF(p->transports));

        /* Returns the transport to fall back to after 'kind', if any */

        for (size_t i = 0; i + 1 < p->n_transports; i++)
                if (p->transports[i] == kind)
                        return p->transports[i + 1];

        return _DNS_TRANSPORT_KIND_INVALID;
}

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

DnsServerFeatureLevel dns_server_feature_level_best(void) {
        /* Returns the best feature level of the best transport this build supports */

        for (DnsTransportKind k = _DNS_TRANSPORT_KIND_MAX - 1; k >= 0; k--)
                if (dns_transport_vtable[k])
                        return dns_server_feature_level_for_transport(k, _DNS_SERVER_EDNS_LEVEL_MAX - 1);

        assert_not_reached();
}

const DnsTransportVTable * const dns_transport_vtable[_DNS_TRANSPORT_KIND_MAX] = {
        [DNS_TRANSPORT_DNS] = &dns_transport_dns_vtable,
#if ENABLE_DNS_OVER_TLS
        [DNS_TRANSPORT_DOT] = &dns_transport_dot_vtable,
#endif
};

int dns_server_transport_new(DnsServer *s, DnsTransportKind kind, DnsServerTransport **ret) {
        const DnsTransportVTable *vt;
        DnsServerTransport *tr;

        assert(s);
        assert(kind >= 0 && kind < _DNS_TRANSPORT_KIND_MAX);
        assert(ret);

        /* Returns -EOPNOTSUPP if the transport is not supported by this build */

        vt = dns_transport_vtable[kind];
        if (!vt)
                return -EOPNOTSUPP;

        assert(vt->object_size >= sizeof(DnsServerTransport));
        assert(vt->packet_received);
        assert(vt->packet_lost);
        assert(vt->open_stream);

        tr = malloc0(vt->object_size);
        if (!tr)
                return -ENOMEM;

        tr->server = s;
        tr->kind = kind;

        *ret = tr;
        return 0;
}

DnsServerTransport* dns_server_transport_free(DnsServerTransport *tr) {
        if (!tr)
                return NULL;

        dns_server_transport_unref_stream(tr);

        const DnsTransportVTable *vt = DNS_TRANSPORT_VTABLE(tr);
        if (vt->done)
                vt->done(tr);

        return mfree(tr);
}

uint16_t dns_server_transport_port(const DnsServerTransport *tr) {
        assert(tr);

        if (tr->server->port > 0)
                return tr->server->port;

        return DNS_TRANSPORT_VTABLE(tr)->default_port;
}

int dns_server_transport_stream_new(
                DnsServerTransport *tr,
                DnsTransaction *t,
                usec_t connect_timeout_usec,
                DnsStream **ret) {

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
        assert(!stream->transport); /* A stream belongs to a single transport for its whole lifetime */

        /* The stream keeps the server, and hence the transport, alive via a reference. The stream and the
         * server reference each other, dns_stream_detach() breaks the cycle again. Take that reference
         * before dropping the previous stream, which might hold the last one otherwise. */
        dns_server_ref(tr->server);
        stream->transport = tr;

        dns_server_transport_unref_stream(tr);
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

int dns_server_transport_open_datagram(DnsServerTransport *tr, DnsScope *scope) {
        assert(tr);

        /* Only feature levels of transports doing datagrams are UDP levels, see
         * dns_server_feature_level_for_transport(), hence callers check for that first */
        const DnsTransportVTable *vt = DNS_TRANSPORT_VTABLE(tr);
        assert(vt->open_datagram);

        return vt->open_datagram(tr, scope);
}

DnsStream* dns_server_transport_reusable_stream(DnsServerTransport *tr) {
        const DnsTransportVTable *vt;

        assert(tr);

        /* Returns the long-lived stream, if there is one and the transport still considers it fit for use.
         * If it doesn't, the stream is dropped. */

        if (!tr->stream)
                return NULL;

        vt = DNS_TRANSPORT_VTABLE(tr);
        if (!vt->stream_reusable || vt->stream_reusable(tr, tr->stream))
                return tr->stream;

        dns_server_transport_unref_stream(tr);
        return NULL;
}

int dns_server_transport_open_stream(DnsServerTransport *tr, DnsTransaction *t, DnsStream **ret) {
        _cleanup_(dns_stream_unrefp) DnsStream *s = NULL;
        DnsStream *reusable;
        int r;

        assert(tr);
        assert(ret);

        /* Reuse the long-lived stream if possible. Otherwise open a new one, which becomes the long-lived
         * one. */

        reusable = dns_server_transport_reusable_stream(tr);
        if (reusable) {
                *ret = dns_stream_ref(reusable);
                return 0;
        }

        r = DNS_TRANSPORT_VTABLE(tr)->open_stream(tr, t, &s);
        if (r < 0)
                return r;

        dns_server_transport_set_stream(tr, s);

        *ret = TAKE_PTR(s);
        return 0;
}

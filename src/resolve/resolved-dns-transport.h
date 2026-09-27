/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolve-util.h"
#include "resolved-forward.h"

/* The wire transports used to talk to unicast DNS servers. The enum order is significant: when comparing
 * feature levels, a later transport ranks higher than an earlier one. */
typedef enum DnsTransportKind {
        DNS_TRANSPORT_DNS,       /* RFC 1035: UDP with TCP fallback */
        DNS_TRANSPORT_DOT,       /* RFC 7858: DNS over TLS */
        _DNS_TRANSPORT_KIND_MAX,
        _DNS_TRANSPORT_KIND_INVALID = -EINVAL,
} DnsTransportKind;

DECLARE_STRING_TABLE_LOOKUP(dns_transport_kind, DnsTransportKind);

/* Whether traffic to a server has to be encrypted. Derived from the DNSOverTLS= setting. */
typedef enum DnsEncryptionMode {
        DNS_ENCRYPTION_NO,             /* Classic DNS only */
        DNS_ENCRYPTION_OPPORTUNISTIC,  /* Encrypted if that works, classic DNS otherwise */
        DNS_ENCRYPTION_REQUIRED,       /* Encrypted, or not at all */
        _DNS_ENCRYPTION_MODE_MAX,
        _DNS_ENCRYPTION_MODE_INVALID = -EINVAL,
} DnsEncryptionMode;

DECLARE_STRING_TABLE_LOOKUP(dns_encryption_mode, DnsEncryptionMode);

DnsEncryptionMode dns_encryption_mode_from_dns_over_tls_mode(DnsOverTlsMode m) _const_;

/* The transports that may be used to talk to a server, in order of preference */
typedef struct DnsTransportPolicy {
        DnsTransportKind transports[_DNS_TRANSPORT_KIND_MAX];
        size_t n_transports;
} DnsTransportPolicy;

void dns_transport_policy_init(DnsEncryptionMode mode, DnsTransportPolicy *ret);
bool dns_transport_policy_contains(const DnsTransportPolicy *p, DnsTransportKind kind) _pure_;
DnsTransportKind dns_transport_policy_next(const DnsTransportPolicy *p, DnsTransportKind kind) _pure_;

/* What the server understands at the DNS message layer, independently of the transport carrying it */
typedef enum DnsServerEdnsLevel {
        DNS_SERVER_EDNS_LEVEL_NONE,   /* No OPT RR */
        DNS_SERVER_EDNS_LEVEL_EDNS0,  /* OPT RR */
        DNS_SERVER_EDNS_LEVEL_DO,     /* OPT RR with the DNSSEC OK bit set */
        _DNS_SERVER_EDNS_LEVEL_MAX,
        _DNS_SERVER_EDNS_LEVEL_INVALID = -EINVAL,
} DnsServerEdnsLevel;

/* A feature level combines two independent axes: the transport used to reach the server, and the EDNS level
 * spoken over it. Classic DNS additionally distinguishes whether UDP may be used, or only TCP.
 *
 * Feature levels are totally ordered, first by EDNS level, then by transport, then by UDP over TCP. This
 * yields, from worst to best: TCP < UDP < UDP+EDNS0 < TLS+EDNS0 < UDP+EDNS0+DO < TLS+EDNS0+DO. */
typedef struct DnsServerFeatureLevel {
        DnsTransportKind transport;
        DnsServerEdnsLevel edns;
        bool udp;                     /* Whether datagrams may be used, or only a stream. Only classic DNS does
                                       * datagrams. */
} DnsServerFeatureLevel;

#define _DNS_SERVER_FEATURE_LEVEL_INVALID                               \
        ((const DnsServerFeatureLevel) {                                \
                .transport = _DNS_TRANSPORT_KIND_INVALID,               \
                .edns = _DNS_SERVER_EDNS_LEVEL_INVALID,                 \
        })

/* Plain DNS, no EDNS0, via TCP only */
#define DNS_SERVER_FEATURE_LEVEL_TCP                                    \
        ((const DnsServerFeatureLevel) {                                \
                .transport = DNS_TRANSPORT_DNS,                         \
                .edns = DNS_SERVER_EDNS_LEVEL_NONE,                     \
        })

/* Plain DNS, no EDNS0, via UDP */
#define DNS_SERVER_FEATURE_LEVEL_UDP                                    \
        ((const DnsServerFeatureLevel) {                                \
                .transport = DNS_TRANSPORT_DNS,                         \
                .edns = DNS_SERVER_EDNS_LEVEL_NONE,                     \
                .udp = true,                                            \
        })

static inline bool dns_server_feature_level_is_valid(DnsServerFeatureLevel l) {
        return l.transport >= 0 && l.edns >= 0;
}

static inline bool DNS_SERVER_FEATURE_LEVEL_IS_EDNS0(DnsServerFeatureLevel l) {
        return l.edns >= DNS_SERVER_EDNS_LEVEL_EDNS0;
}

static inline bool DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(DnsServerFeatureLevel l) {
        return l.edns >= DNS_SERVER_EDNS_LEVEL_DO;
}

static inline bool DNS_SERVER_FEATURE_LEVEL_IS_UDP(DnsServerFeatureLevel l) {
        return l.udp;
}

int dns_server_feature_level_compare(DnsServerFeatureLevel a, DnsServerFeatureLevel b) _const_;

static inline bool dns_server_feature_level_equal(DnsServerFeatureLevel a, DnsServerFeatureLevel b) {
        return dns_server_feature_level_compare(a, b) == 0;
}

const char* dns_server_feature_level_to_string(DnsServerFeatureLevel l) _const_;

DnsServerFeatureLevel dns_server_feature_level_for_transport(DnsTransportKind kind, DnsServerEdnsLevel edns);
DnsServerFeatureLevel dns_server_feature_level_best(void) _pure_;

/* Per-server state for one transport. Each transport implementation embeds this as the first member of its
 * own object, see DnsTransportVTable.object_size. Transports are owned by their DnsServer, and live as long
 * as it does, so that objects holding a reference to the server may also point to its transports. */
typedef struct DnsServerTransport {
        DnsServer *server;                     /* The server owning us, not a reference */
        DnsTransportKind kind;

        /* The long-lived stream towards the server via this transport, if any */
        DnsStream *stream;
} DnsServerTransport;

typedef struct DnsTransportVTable {
        /* Size of the transport specific object, which embeds DnsServerTransport as its first member */
        size_t object_size;

        /* Port to use if the server has none configured */
        uint16_t default_port;

        /* The lowest EDNS level this transport can be used with */
        DnsServerEdnsLevel edns_min;

        /* Frees transport specific resources, but not the object itself. Optional. */
        void (*done)(DnsServerTransport *tr);

        /* Forgets the failure counters, invoked whenever the possible feature level of the server changes.
         * Optional. */
        void (*reset_counters)(DnsServerTransport *tr);

        /* Forgets everything learnt about the server. Also sets up features with non-zero defaults, as
         * dns_server_new() resets the features of a new server. Optional. */
        void (*reset_features)(DnsServerTransport *tr);

        /* Feedback from transactions. packet_lost() and packet_truncated() are only invoked if the feature
         * level used matches the possible feature level of the server, packet_received() is told so via
         * 'at_possible_level'. It may lower 'level' to what the reply actually verifies. */
        void (*packet_received)(
                        DnsServerTransport *tr,
                        int protocol,
                        DnsServerFeatureLevel *level,
                        bool at_possible_level,
                        size_t fragsize);
        void (*packet_lost)(DnsServerTransport *tr, int protocol);
        void (*packet_truncated)(DnsServerTransport *tr);

        /* Returns true if the transport stopped working at the current feature level, and the server shall
         * fall back to the next transport, if the policy permits one. Optional. */
        bool (*failed)(DnsServerTransport *tr);

        /* Transport specific feature level changes, evaluated after the transport independent EDNS related
         * ones. Lowers 'level' if the transport's failures call for it. Optional. */
        void (*degrade)(DnsServerTransport *tr, DnsServerFeatureLevel *level);

        /* Returns false if what we know about the transport rules out DNSSEC. Optional. */
        bool (*dnssec_supported)(DnsServerTransport *tr);

        /* Returns a connected datagram socket towards the server. NULL if the transport doesn't do
         * datagrams. */
        int (*open_datagram)(DnsServerTransport *tr, DnsScope *scope);

        /* Returns a stream towards the server for the transaction, either the existing long-lived one, or a
         * new one which is then remembered as the long-lived one. */
        int (*open_stream)(DnsServerTransport *tr, DnsTransaction *t, DnsStream **ret);
} DnsTransportVTable;

/* NULL for transports not supported by this build */
extern const DnsTransportVTable * const dns_transport_vtable[_DNS_TRANSPORT_KIND_MAX];

static inline const DnsTransportVTable* DNS_TRANSPORT_VTABLE(const DnsServerTransport *tr) {
        return dns_transport_vtable[tr->kind];
}

int dns_server_transport_new(DnsServer *s, DnsTransportKind kind, DnsServerTransport **ret);
DnsServerTransport* dns_server_transport_free(DnsServerTransport *tr);

int dns_server_transport_stream_new(
                DnsServerTransport *tr,
                DnsTransaction *t,
                usec_t connect_timeout_usec,
                DnsStream **ret);
void dns_server_transport_set_stream(DnsServerTransport *tr, DnsStream *stream);
void dns_server_transport_unref_stream(DnsServerTransport *tr);

/* For casting a transport into the various transport kinds */
#define DEFINE_DNS_TRANSPORT_CAST(UPPERCASE, MixedCase)                                   \
        static inline MixedCase* DNS_TRANSPORT_TO_##UPPERCASE(DnsServerTransport *tr) {   \
                if (_unlikely_(!tr || tr->kind != DNS_TRANSPORT_##UPPERCASE))             \
                        return NULL;                                                      \
                                                                                          \
                return (MixedCase*) tr;                                                   \
        }

/* For casting the various transport kinds into a transport */
#define DNS_TRANSPORT(t)                                                \
        ({                                                              \
                typeof(t) _t_ = (t);                                    \
                DnsServerTransport *_w_ = _t_ ? &(_t_)->meta : NULL;    \
                _w_;                                                    \
        })

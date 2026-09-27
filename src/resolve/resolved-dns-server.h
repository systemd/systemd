/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "list.h"
#include "resolved-conf.h"
#include "resolved-dns-transport.h"
#include "resolved-dnstls.h"
#include "resolved-forward.h"

typedef enum DnsServerType {
        DNS_SERVER_SYSTEM,
        DNS_SERVER_FALLBACK,
        DNS_SERVER_LINK,
        DNS_SERVER_DELEGATE,
        _DNS_SERVER_TYPE_MAX,
        _DNS_SERVER_TYPE_INVALID = -EINVAL,
} DnsServerType;

DECLARE_STRING_TABLE_LOOKUP(dns_server_type, DnsServerType);

/* What the server understands at the DNS message layer, independently of the transport carrying it */
typedef enum DnsServerEdnsLevel {
        DNS_SERVER_EDNS_LEVEL_NONE,   /* No OPT RR */
        DNS_SERVER_EDNS_LEVEL_EDNS0,  /* OPT RR */
        DNS_SERVER_EDNS_LEVEL_DO,     /* OPT RR with the DNSSEC OK bit set */
        _DNS_SERVER_EDNS_LEVEL_MAX,
        _DNS_SERVER_EDNS_LEVEL_INVALID = -EINVAL,
} DnsServerEdnsLevel;

DECLARE_STRING_TABLE_LOOKUP(dns_server_edns_level, DnsServerEdnsLevel);

/* A feature level combines two independent axes: the transport used to reach the server, and the EDNS level
 * spoken over it. Classic DNS additionally distinguishes whether UDP may be used, or only TCP.
 *
 * Feature levels are totally ordered, first by EDNS level, then by transport, then by UDP over TCP. This
 * yields, from worst to best: TCP < UDP < UDP+EDNS0 < TLS+EDNS0 < UDP+EDNS0+DO < TLS+EDNS0+DO. */
typedef struct DnsServerFeatureLevel {
        DnsTransportKind transport;
        DnsServerEdnsLevel edns;
        bool udp;                     /* DNS_TRANSPORT_DNS only: false if only TCP may be used */
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

#define DNS_SERVER_FEATURE_LEVEL_BEST                                   \
        ((const DnsServerFeatureLevel) {                                \
                .transport = _DNS_TRANSPORT_KIND_MAX - 1,               \
                .edns = _DNS_SERVER_EDNS_LEVEL_MAX - 1,                 \
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

static inline bool DNS_SERVER_FEATURE_LEVEL_IS_TLS(DnsServerFeatureLevel l) {
        return l.transport == DNS_TRANSPORT_DOT;
}

static inline bool DNS_SERVER_FEATURE_LEVEL_IS_UDP(DnsServerFeatureLevel l) {
        return l.transport == DNS_TRANSPORT_DNS && l.udp;
}

int dns_server_feature_level_compare(DnsServerFeatureLevel a, DnsServerFeatureLevel b) _const_;

static inline bool dns_server_feature_level_equal(DnsServerFeatureLevel a, DnsServerFeatureLevel b) {
        return dns_server_feature_level_compare(a, b) == 0;
}

const char* dns_server_feature_level_to_string(DnsServerFeatureLevel l) _const_;

typedef struct DnsServer {
        Manager *manager;

        unsigned n_ref;

        DnsServerType type;
        Link *link;
        DnsDelegate *delegate;

        int family;
        union in_addr_union address;
        int ifindex; /* for IPv6 link-local DNS servers */
        uint16_t port;
        char *server_name;

        char *server_string;
        char *server_string_full;

        /* The long-lived stream towards this server. */
        DnsStream *stream;

#if ENABLE_DNS_OVER_TLS
        DnsTlsServerData dnstls_data;
#endif

        DnsServerFeatureLevel verified_feature_level;
        DnsServerFeatureLevel possible_feature_level;

        size_t received_udp_fragment_max;   /* largest packet or fragment (without IP/UDP header) we saw so far */

        unsigned n_failed_udp;
        unsigned n_failed_tcp;
        unsigned n_failed_tls;

        bool packet_truncated:1;        /* Set when TC bit was set on reply */
        bool packet_bad_opt:1;          /* Set when OPT was missing or otherwise bad on reply */
        bool packet_rrsig_missing:1;    /* Set when RRSIG was missing */
        bool packet_invalid:1;          /* Set when we failed to parse a reply */
        bool packet_do_off:1;           /* Set when the server didn't copy DNSSEC DO flag from request to response */
        bool packet_fragmented:1;       /* Set when we ever saw a fragmented packet */

        usec_t verified_usec;
        usec_t features_grace_period_usec;

        /* Whether we already warned about downgrading to non-DNSSEC mode for this server */
        bool warned_downgrade:1;

        /* Used when GC'ing old DNS servers when configuration changes. */
        bool marked:1;

        /* If linked is set, then this server appears in the servers linked list */
        bool linked:1;
        LIST_FIELDS(DnsServer, servers);

        /* Servers registered via D-Bus are not removed on reload */
        ResolveConfigSource config_source;

        /* Tri-state to indicate if the DNS server is accessible. */
        int accessible;
} DnsServer;

int dns_server_new(
                Manager *m,
                DnsServer **ret,
                DnsServerType type,
                Link *link,
                DnsDelegate *delegate,
                int family,
                const union in_addr_union *in_addr,
                uint16_t port,
                int ifindex,
                const char *server_name,
                ResolveConfigSource config_source);

DECLARE_TRIVIAL_REF_UNREF_FUNC(DnsServer, dns_server);

void dns_server_unlink(DnsServer *s);
void dns_server_move_back_and_unmark(DnsServer *s);

void dns_server_packet_received(DnsServer *s, int protocol, DnsServerFeatureLevel level, size_t fragsize);
void dns_server_packet_lost(DnsServer *s, int protocol, DnsServerFeatureLevel level);
void dns_server_packet_truncated(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_rrsig_missing(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_bad_opt(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_rcode_downgrade(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_invalid(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_do_off(DnsServer *s, DnsServerFeatureLevel level);
void dns_server_packet_udp_fragmented(DnsServer *s, size_t fragsize);

DnsServerFeatureLevel dns_server_possible_feature_level(DnsServer *s);

int dns_server_adjust_opt(DnsServer *server, DnsPacket *packet, DnsServerFeatureLevel level);

const char* dns_server_string(DnsServer *server);
const char* dns_server_string_full(DnsServer *server);
int dns_server_ifindex(const DnsServer *s);
uint16_t dns_server_port(const DnsServer *s);

bool dns_server_dnssec_supported(DnsServer *server);

void dns_server_warn_downgrade(DnsServer *server);

DnsServer *dns_server_find(DnsServer *first, int family, const union in_addr_union *in_addr, uint16_t port, int ifindex, const char *name);

void dns_server_unlink_all(DnsServer *first);
void dns_server_unlink_on_reload(DnsServer *server);
bool dns_server_unlink_marked(DnsServer *first);
void dns_server_mark_all(DnsServer *server);

int manager_parse_search_domains_and_warn(Manager *m, const char *string);
int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string);

DnsServer *manager_get_first_dns_server(Manager *m, DnsServerType t);

DnsServer *manager_set_dns_server(Manager *m, DnsServer *s);
DnsServer *manager_get_dns_server(Manager *m);
void manager_next_dns_server(Manager *m, DnsServer *if_current);

DnssecMode dns_server_get_dnssec_mode(DnsServer *s);
DnsOverTlsMode dns_server_get_dns_over_tls_mode(DnsServer *s);

size_t dns_server_get_mtu(DnsServer *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServer*, dns_server_unref);

extern const struct hash_ops dns_server_hash_ops;

void dns_server_flush_cache(DnsServer *s);

void dns_server_reset_features(DnsServer *s);
void dns_server_reset_features_all(DnsServer *s);

void dns_server_dump(DnsServer *s, FILE *f);

void dns_server_unref_stream(DnsServer *s);

DnsScope *dns_server_scope(DnsServer *s);

static inline bool dns_server_is_fallback(DnsServer *s) {
        return s && s->type == DNS_SERVER_FALLBACK;
}

int dns_server_dump_state_to_json(DnsServer *server, sd_json_variant **ret);
int dns_server_dump_configuration_to_json(DnsServer *server, sd_json_variant **ret);

int dns_server_is_accessible(DnsServer *s);
static inline void dns_server_reset_accessible(DnsServer *s) {
        s->accessible = -1;
}
void dns_server_reset_accessible_all(DnsServer *first);

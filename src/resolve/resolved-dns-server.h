/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "list.h"
#include "resolve-util.h"
#include "time-util.h"

typedef struct DnsScope DnsScope;
typedef struct DnsServer DnsServer;
typedef struct DnsStream DnsStream;
typedef struct DnsPacket DnsPacket;
typedef struct Link Link;
typedef struct Manager Manager;

#include "resolved-dnstls.h"

typedef enum DnsServerType {
        DNS_SERVER_SYSTEM,
        DNS_SERVER_FALLBACK,
        DNS_SERVER_LINK,
        _DNS_SERVER_TYPE_MAX,
        _DNS_SERVER_TYPE_INVALID = -EINVAL,
} DnsServerType;

const char* dns_server_type_to_string(DnsServerType i) _const_;
DnsServerType dns_server_type_from_string(const char *s) _pure_;

typedef enum DnsServerFeatureLevel {
        DNS_SERVER_FEATURE_LEVEL_TCP,
        DNS_SERVER_FEATURE_LEVEL_UDP,
        DNS_SERVER_FEATURE_LEVEL_EDNS0,
        DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN,
        DNS_SERVER_FEATURE_LEVEL_DO,
        DNS_SERVER_FEATURE_LEVEL_TLS_DO,
        _DNS_SERVER_FEATURE_LEVEL_MAX,
        _DNS_SERVER_FEATURE_LEVEL_INVALID = -EINVAL,
} DnsServerFeatureLevel;

#define DNS_SERVER_FEATURE_LEVEL_WORST 0
#define DNS_SERVER_FEATURE_LEVEL_BEST (_DNS_SERVER_FEATURE_LEVEL_MAX - 1)
#define DNS_SERVER_FEATURE_LEVEL_IS_EDNS0(x) ((x) >= DNS_SERVER_FEATURE_LEVEL_EDNS0)
#define DNS_SERVER_FEATURE_LEVEL_IS_TLS(x) IN_SET(x, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN, DNS_SERVER_FEATURE_LEVEL_TLS_DO)
#define DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(x) ((x) >= DNS_SERVER_FEATURE_LEVEL_DO)
#define DNS_SERVER_FEATURE_LEVEL_IS_UDP(x) IN_SET(x, DNS_SERVER_FEATURE_LEVEL_UDP, DNS_SERVER_FEATURE_LEVEL_EDNS0, DNS_SERVER_FEATURE_LEVEL_DO)

const char* dns_server_feature_level_to_string(DnsServerFeatureLevel i) _const_;
DnsServerFeatureLevel dns_server_feature_level_from_string(const char *s) _pure_;

struct DnsServer {
        Manager *manager;

        unsigned n_ref;

        DnsServerType type;
        Link *link;

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
};

int dns_server_new(
                Manager *m,
                DnsServer **ret,
                DnsServerType type,
                Link *link,
                int family,
                const union in_addr_union *address,
                uint16_t port,
                int ifindex,
                const char *server_string);

DnsServer* dns_server_ref(DnsServer *s);
DnsServer* dns_server_unref(DnsServer *s);

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

const char *dns_server_string(DnsServer *server);
const char *dns_server_string_full(DnsServer *server);
int dns_server_ifindex(const DnsServer *s);
uint16_t dns_server_port(const DnsServer *s);

bool dns_server_dnssec_supported(DnsServer *server);

void dns_server_warn_downgrade(DnsServer *server);

DnsServer *dns_server_find(DnsServer *first, int family, const union in_addr_union *in_addr, uint16_t port, int ifindex, const char *name);

void dns_server_unlink_all(DnsServer *first);
bool dns_server_unlink_marked(DnsServer *first);
void dns_server_mark_all(DnsServer *first);

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

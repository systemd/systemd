/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "list.h"
#include "resolved-conf.h"
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

typedef enum DnsServerTransport {
        DNS_SERVER_TRANSPORT_TCP,
        DNS_SERVER_TRANSPORT_UDP,
        DNS_SERVER_TRANSPORT_TLS,
        _DNS_SERVER_TRANSPORT_MAX,
        _DNS_SERVER_TRANSPORT_INVALID = -EINVAL,
} DnsServerTransport;

typedef enum DnsServerCapabilityLevel {
        DNS_SERVER_CAPABILITY_LEVEL_PLAIN,
        DNS_SERVER_CAPABILITY_LEVEL_EDNS0,
        DNS_SERVER_CAPABILITY_LEVEL_DO,
        _DNS_SERVER_CAPABILITY_LEVEL_MAX,
        _DNS_SERVER_CAPABILITY_LEVEL_INVALID = -EINVAL,
} DnsServerCapabilityLevel;

typedef enum DnsTransactionTransport {
        DNS_TRANSACTION_TRANSPORT_UDP,
        DNS_TRANSACTION_TRANSPORT_TCP,
        DNS_TRANSACTION_TRANSPORT_TLS,
        DNS_TRANSACTION_TRANSPORT_HTTPS,
        _DNS_TRANSACTION_TRANSPORT_MAX,
        _DNS_TRANSACTION_TRANSPORT_INVALID = -EINVAL,
} DnsTransactionTransport;

typedef enum DnsServerProtocol {
        DNS_SERVER_PROTOCOL_DNS,
        DNS_SERVER_PROTOCOL_HTTPS,
        _DNS_SERVER_PROTOCOL_MAX,
        _DNS_SERVER_PROTOCOL_INVALID = -EINVAL,
} DnsServerProtocol;

#define DNS_SERVER_TRANSPORT_WORST DNS_SERVER_TRANSPORT_TCP
#define DNS_SERVER_TRANSPORT_BEST DNS_SERVER_TRANSPORT_TLS

DECLARE_STRING_TABLE_LOOKUP(dns_server_protocol, DnsServerProtocol);

DECLARE_STRING_TABLE_LOOKUP(dns_server_transport, DnsServerTransport);
DECLARE_STRING_TABLE_LOOKUP(dns_server_capability_level, DnsServerCapabilityLevel);

#define DNS_SERVER_CAPABILITY_LEVEL_WORST DNS_SERVER_CAPABILITY_LEVEL_PLAIN
#define DNS_SERVER_CAPABILITY_LEVEL_BEST DNS_SERVER_CAPABILITY_LEVEL_DO
#define DNS_SERVER_CAPABILITY_LEVEL_IS_EDNS0(x) ((x) >= DNS_SERVER_CAPABILITY_LEVEL_EDNS0)
#define DNS_SERVER_CAPABILITY_LEVEL_IS_DNSSEC(x) ((x) >= DNS_SERVER_CAPABILITY_LEVEL_DO)

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

        DnsServerProtocol protocol;
        char *doh_uri;
        char *doh_uri_template;

        char *server_string;
        char *server_string_full;

        /* The long-lived stream towards this server. */
        DnsStream *stream;

#if HAVE_LIBCURL_HEADER && HAVE_LIBCURL_URL
        /* The long-lived HTTP connection pool towards this server. */
        CurlGlue *doh_curl;
#endif

#if ENABLE_DNS_OVER_TLS
        DnsTlsServerData dnstls_data;
#endif

        DnsServerTransport verified_transport;
        DnsServerTransport possible_transport;
        DnsServerCapabilityLevel verified_capability_level;
        DnsServerCapabilityLevel possible_capability_level;

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

        usec_t transport_verified_usec;
        usec_t transports_grace_period_usec;
        usec_t capability_verified_usec;
        usec_t capabilities_grace_period_usec;

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

void dns_server_packet_received(
                DnsServer *s,
                DnsTransactionTransport received_transport,
                DnsServerTransport selected_transport,
                size_t fragsize);
void dns_server_packet_lost(
                DnsServer *s,
                DnsTransactionTransport transport,
                DnsServerTransport selected_transport);
void dns_server_packet_truncated(DnsServer *s, DnsServerTransport selected_transport);
void dns_server_capability_received(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_rrsig_missing(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_bad_opt(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_rcode_downgrade(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_invalid(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_do_off(DnsServer *s, DnsServerCapabilityLevel level);
void dns_server_packet_udp_fragmented(DnsServer *s, size_t fragsize);

DnsServerTransport dns_server_possible_transport(DnsServer *s);
DnsServerCapabilityLevel dns_server_possible_capability_level(DnsServer *s);

int dns_server_adjust_opt(DnsServer *server, DnsPacket *packet, DnsServerCapabilityLevel level);

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

static inline bool dns_server_is_doh(const DnsServer *s) {
        return s && s->protocol == DNS_SERVER_PROTOCOL_HTTPS;
}

int dns_server_dump_state_to_json(DnsServer *server, sd_json_variant **ret);
int dns_server_dump_configuration_to_json(DnsServer *server, sd_json_variant **ret);

int dns_server_is_accessible(DnsServer *s);
static inline void dns_server_reset_accessible(DnsServer *s) {
        s->accessible = -1;
}
void dns_server_reset_accessible_all(DnsServer *first);

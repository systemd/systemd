/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "common-signal.h"
#include "list.h"
#include "resolve-util.h"
#include "resolved-dns-browse-services.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-stub.h"
#include "resolved-dns-trust-anchor.h"
#include "resolved-etc-hosts.h"
#include "resolved-forward.h"

#define MANAGER_SEARCH_DOMAINS_MAX 1024
#define MANAGER_DNS_SERVERS_MAX 256

typedef struct Manager {
#if ENABLE_DNS_OVER_TLS
        DnsTlsManagerData dnstls_data;
#endif

        /* Network */
        Hashmap *links;

        /* Pointers */
        sd_event *event;
        sd_netlink *rtnl;
        sd_event_source *rtnl_event_source;
        sd_network_monitor *network_monitor;
        sd_event_source *network_event_source;
        Hashmap *dns_transactions;
        Hashmap *stub_queries_by_packet;
        DnsServer *current_dns_server;
        DnsScope *unicast_scope;
        Hashmap *delegates; /* id string → DnsDelegate objects */
        sd_event_source *llmnr_ipv4_udp_event_source;
        sd_event_source *llmnr_ipv6_udp_event_source;
        sd_event_source *llmnr_ipv4_tcp_event_source;
        sd_event_source *llmnr_ipv6_tcp_event_source;
        sd_event_source *mdns_ipv4_event_source;
        sd_event_source *mdns_ipv6_event_source;
        Hashmap *dnssd_registered_services;
        sd_bus *bus;
        char *full_hostname;
        char *llmnr_hostname;
        char *mdns_hostname;
        DnsResourceKey *llmnr_host_ipv4_key;
        DnsResourceKey *llmnr_host_ipv6_key;
        DnsResourceKey *mdns_host_ipv4_key;
        DnsResourceKey *mdns_host_ipv6_key;
        sd_event_source *hostname_event_source;
        Set *refuse_record_types;
        OrderedSet *dns_extra_stub_listeners;
        sd_event_source *dns_stub_udp_event_source;
        sd_event_source *dns_stub_tcp_event_source;
        sd_event_source *dns_proxy_stub_udp_event_source;
        sd_event_source *dns_proxy_stub_tcp_event_source;
        Hashmap *polkit_registry;
        sd_varlink_server *varlink_server;
        sd_varlink_server *varlink_monitor_server;
        Set *varlink_query_results_subscription;
        Set *varlink_dns_configuration_subscription;
        sd_json_variant *dns_configuration_json;
        sd_netlink_slot *netlink_new_route_slot;
        sd_netlink_slot *netlink_del_route_slot;
        sd_event_source *clock_change_event_source;
        SocketGraveyard *socket_graveyard_oldest;
        Hashmap *dns_service_browsers;

        /* Large structs and lists */
        struct stat resolv_conf_stat;
        DnsTrustAnchor trust_anchor;
        EtcHosts etc_hosts;
        struct stat etc_hosts_stat;
        struct sigrtmin18_info sigrtmin18_info;
        LIST_HEAD(DnsQuery, dns_queries);
        LIST_HEAD(DnsStream, dns_streams);
        LIST_HEAD(DnsServer, dns_servers);
        LIST_HEAD(DnsServer, fallback_dns_servers);
        LIST_HEAD(DnsSearchDomain, search_domains);
        LIST_HEAD(DnsScope, dns_scopes);
        LIST_HEAD(SocketGraveyard, socket_graveyard);

        /* 64-bit types */
        usec_t stale_retention_usec;
        usec_t etc_hosts_last;
        size_t n_socket_graveyard;

        /* Enums and 32-bit integers */
        ResolveSupport llmnr_support;
        ResolveSupport mdns_support;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;
        DnsCacheMode enable_cache;
        DnsStubListenerMode dns_stub_listener_mode;
        unsigned n_dns_queries;
        unsigned n_dns_streams[_DNS_STREAM_TYPE_MAX];
        unsigned n_dns_servers; /* counts both main and fallback */
        unsigned n_search_domains;
        int llmnr_ipv4_udp_fd;
        int llmnr_ipv6_udp_fd;
        int llmnr_ipv4_tcp_fd;
        int llmnr_ipv6_tcp_fd;
        int mdns_ipv4_fd;
        int mdns_ipv6_fd;
        int hostname_fd;
        unsigned n_transactions_total;
        unsigned n_timeouts_total;
        unsigned n_timeouts_served_stale_total;
        unsigned n_failure_responses_total;
        unsigned n_failure_responses_served_stale_total;
        unsigned n_dnssec_verdict[_DNSSEC_VERDICT_MAX];

        /* Booleans */
        bool cache_from_localhost;
        bool need_builtin_fallbacks;
        bool read_resolv_conf;
        bool resolve_unicast_single_label;
        bool read_etc_hosts;
} Manager;

/* Manager */

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_start(Manager *m);

uint32_t manager_find_mtu(Manager *m);

int manager_monitor_send(Manager *m, DnsQuery *q);

int sendmsg_loop(int fd, struct msghdr *mh, int flags);
int manager_write(Manager *m, int fd, DnsPacket *p);
int manager_send(Manager *m, int fd, int ifindex, int family, const union in_addr_union *destination, uint16_t port, const union in_addr_union *source, DnsPacket *p);
int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret);

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr);
LinkAddress* manager_find_link_address(Manager *m, int family, const union in_addr_union *in_addr);

void manager_refresh_rrs(Manager *m);
int manager_next_hostname(Manager *m);

bool manager_packet_from_local_address(Manager *m, DnsPacket *p);
bool manager_packet_from_our_transaction(Manager *m, DnsPacket *p);

DnsScope* manager_find_scope_from_protocol(Manager *m, int ifindex, DnsProtocol protocol, int family);

static inline DnsScope* manager_find_scope(Manager *m, DnsPacket *p) {
        assert(m);
        assert(p);
        return manager_find_scope_from_protocol(m, p->ifindex, p->protocol, p->family);
}

void manager_verify_all(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

/* For some reason we need some extra cmsg space on some kernels/archs. One of those days we need to figure out why */
#define EXTRA_CMSG_SPACE 1024

int manager_is_own_hostname(Manager *m, const char *name);

int manager_compile_dns_servers(Manager *m, OrderedSet **servers);
int manager_compile_search_domains(Manager *m, OrderedSet **domains, int filter_route);

DnssecMode manager_get_dnssec_mode(Manager *m);
bool manager_dnssec_supported(Manager *m);

DnsOverTlsMode manager_get_dns_over_tls_mode(Manager *m);

void manager_dnssec_verdict(Manager *m, DnssecVerdict verdict, const DnsResourceKey *key);

bool manager_routable(Manager *m);

void manager_flush_caches(Manager *m, int log_level);
void manager_reset_server_features(Manager *m);

void manager_cleanup_saved_user(Manager *m);

bool manager_next_dnssd_names(Manager *m);

bool manager_server_is_stub(Manager *m, DnsServer *s);

int socket_disable_pmtud(int fd, int af);

int dns_manager_dump_statistics_json(Manager *m, sd_json_variant **ret);

void dns_manager_reset_statistics(Manager *m);

int manager_dump_dns_configuration_json(Manager *m, sd_json_variant **ret);
int manager_send_dns_configuration_changed(Manager *m, Link *l, bool reset);

int manager_start_dns_configuration_monitor(Manager *m);
void manager_stop_dns_configuration_monitor(Manager *m);

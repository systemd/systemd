/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Resolve.Monitor.h"

/* We want to reuse the ResourceKey and ResourceRecord structures from the io.systemd.Resolve interface,
 * hence import them here. */
#include "varlink-io.systemd.Resolve.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecordArray,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(raw, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Answer,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(raw, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeQueryResults,
                SD_VARLINK_REQUIRES_MORE,
                VARLINK_DEFINE_POLKIT_INPUT,
                /* First reply */
                SD_VARLINK_DEFINE_OUTPUT(ready, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                /* Subsequent replies */
                SD_VARLINK_DEFINE_OUTPUT(state, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(result, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(rcode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(errno, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(extendedDNSErrorCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(extendedDNSErrorMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(question, ResourceKey, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(collectedQuestions, ResourceKey, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(answer, Answer, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CacheEntry,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rrs, ResourceRecordArray, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(until, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ScopeCache,
                SD_VARLINK_DEFINE_FIELD(protocol, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(ifname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(cache, CacheEntry, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                DumpCache,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(dump, ScopeCache, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ServerState,
                SD_VARLINK_DEFINE_FIELD(Server, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(Type, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(Interface, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(InterfaceIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(VerifiedFeatureLevel, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(PossibleFeatureLevel, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(DNSSECMode, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(DNSSECSupported, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(ReceivedUDPFragmentMax, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(FailedUDPAttempts, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(FailedTCPAttempts, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(PacketTruncated, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(PacketBadOpt, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(PacketRRSIGMissing, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(PacketInvalid, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(PacketDoOff, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                DumpServerState,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(dump, ServerState, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TransactionStatistics,
                SD_VARLINK_DEFINE_FIELD(currentTransactions, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(totalTransactions, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(totalTimeouts, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(totalTimeoutsServedStale, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(totalFailedResponses, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(totalFailedResponsesServedStale, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CacheStatistics,
                SD_VARLINK_DEFINE_FIELD(size, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(hits, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(misses, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                DnssecStatistics,
                SD_VARLINK_DEFINE_FIELD(secure, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(insecure, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(bogus, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(indeterminate, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                DumpStatistics,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(transactions, TransactionStatistics, 0),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(cache, CacheStatistics, 0),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(dnssec, DnssecStatistics, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResetStatistics,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSServer,
                SD_VARLINK_FIELD_COMMENT("IPv4 or IPv6 address of the server."),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Address family of the server, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Port number of the server."),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Interface index for which this server is configured."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Server Name Indication (SNI) of the server."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates if the DNS server is accessible or not."),
                SD_VARLINK_DEFINE_FIELD(accessible, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SearchDomain,
                SD_VARLINK_FIELD_COMMENT("Domain name."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates whether or not this is a routing-only domain."),
                SD_VARLINK_DEFINE_FIELD(routeOnly, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Interface index for which this search domain is configured."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSConfiguration,
                SD_VARLINK_FIELD_COMMENT("Interface name, if any, associated with this configuration. Empty for global configuration."),
                SD_VARLINK_DEFINE_FIELD(ifname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Interface index, if any, associated with this configuration. Empty for global configuration."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates whether or not this link's DNS servers will be used for resolving domain names that do not match any link's configured domains."),
                SD_VARLINK_DEFINE_FIELD(defaultRoute, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNS server currently selected to use for lookups."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(currentServer, DNSServer, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured DNS servers."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(servers, DNSServer, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured search domains."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(searchDomains, SearchDomain, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeDNSConfiguration,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The current global and per-interface DNS configurations"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(configuration, DNSConfiguration, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve_Monitor,
                "io.systemd.Resolve.Monitor",
                &vl_method_SubscribeQueryResults,
                &vl_method_DumpCache,
                &vl_method_DumpServerState,
                &vl_method_DumpStatistics,
                &vl_method_ResetStatistics,
                &vl_type_ResourceKey,
                &vl_type_ResourceRecord,
                &vl_type_ResourceRecordArray,
                &vl_type_Answer,
                &vl_type_CacheEntry,
                &vl_type_ScopeCache,
                &vl_type_TransactionStatistics,
                &vl_type_CacheStatistics,
                &vl_type_DnssecStatistics,
                &vl_type_ServerState,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a DNS server address specification."),
                &vl_type_DNSServer,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a search domain specification."),
                &vl_type_SearchDomain,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a global or per-link DNS configuration, including configured DNS servers, search domains, and more."),
                &vl_type_DNSConfiguration,
                SD_VARLINK_SYMBOL_COMMENT("Sends the complete global and per-link DNS configurations when any changes are made to them. The current configurations are given immediately when this method is invoked."),
                &vl_method_SubscribeDNSConfiguration);

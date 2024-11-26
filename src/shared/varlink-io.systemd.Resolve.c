/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Resolve.h"

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceKey,
                SD_VARLINK_FIELD_COMMENT("The RR class, almost always IN, i.e 0x01."),
                SD_VARLINK_DEFINE_FIELD(class, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The RR types, one of A, AAAA, PTR, …"),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The domain name."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecord,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                SD_VARLINK_DEFINE_FIELD(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(weight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(cpu, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(os, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(items, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(mname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(rname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(serial, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(refresh, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(expire, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(minimum, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(exchange, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(size, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(horiz_pre, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(vert_pre, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(latitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(longitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(altitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(keyTag, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(algorithm, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(digestType, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(digest, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fptype, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fingerprint, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(protocol, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(dnskey, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(signer, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(typeCovered, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(labels, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(originalTtl, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(expiration, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(inception, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(signature, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(nextDomain, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(types, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(iterations, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(salt, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(hash, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(certUsage, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(selector, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(matchingType, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(tag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(target, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                /* This field is retired */
                /* SD_VARLINK_DEFINE_FIELD(params, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY), */
                SD_VARLINK_DEFINE_FIELD(svcparams, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(order, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(preference, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(naptrFlags, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(services, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(regexp, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(replacement, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedAddress,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                ResolveHostname,
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface to search on. Typically left unspecified, in order to search on all interfaces."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The host name to resolve."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The address family to search for, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Various search flags."),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of resolved IP addresses"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(addresses, ResolvedAddress, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Canonical name of the host."),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Various flags indicating details on discovered data."),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedName,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResolveAddress,
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface to search on. Typically left unspecified, in order to search on all interfaces."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The address family of the specified address, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The IP address to look up, either 4 or 16 integers (depending if an AF_INET or AF_INET6 address shall be resolved)."),
                SD_VARLINK_DEFINE_INPUT(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(names, ResolvedName, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedService,
                SD_VARLINK_DEFINE_FIELD(priority, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(weight, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(hostname, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(canonicalName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(addresses, ResolvedAddress, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedCanonical,
                SD_VARLINK_FIELD_COMMENT("The DNS-SD name of the service. For simple SRV services this field is absent or null."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(domain, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResolveService,
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(domain, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(services, ResolvedService, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(txt, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(canonical, ResolvedCanonical, 0),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedRecord,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(raw, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResolveRecord,
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(class, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(type, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(rrs, ResolvedRecord, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(NoNameServers);
static SD_VARLINK_DEFINE_ERROR(NoSuchResourceRecord);
static SD_VARLINK_DEFINE_ERROR(QueryTimedOut);
static SD_VARLINK_DEFINE_ERROR(MaxAttemptsReached);
static SD_VARLINK_DEFINE_ERROR(InvalidReply);
static SD_VARLINK_DEFINE_ERROR(QueryAborted);
static SD_VARLINK_DEFINE_ERROR(
                DNSSECValidationFailed,
                SD_VARLINK_DEFINE_FIELD(result, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(NoTrustAnchor);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeUnsupported);
static SD_VARLINK_DEFINE_ERROR(NetworkDown);
static SD_VARLINK_DEFINE_ERROR(NoSource);
static SD_VARLINK_DEFINE_ERROR(StubLoop);
static SD_VARLINK_DEFINE_ERROR(
                DNSError,
                SD_VARLINK_DEFINE_FIELD(rcode, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(CNAMELoop);
static SD_VARLINK_DEFINE_ERROR(BadAddressSize);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeInvalidForQuery);
static SD_VARLINK_DEFINE_ERROR(ZoneTransfersNotPermitted);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeObsolete);
static SD_VARLINK_DEFINE_ERROR(InconsistentServiceRecords);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve,
                "io.systemd.Resolve",
                SD_VARLINK_SYMBOL_COMMENT("Resolves a hostname to one or more IP addresses."),
                &vl_method_ResolveHostname,
                SD_VARLINK_SYMBOL_COMMENT("Resolves an IP address to a hostname."),
                &vl_method_ResolveAddress,
                SD_VARLINK_SYMBOL_COMMENT("Resolves a named DNS-SD or unnamed simple SRV service."),
                &vl_method_ResolveService,
                SD_VARLINK_SYMBOL_COMMENT("Resolves a domain name to one or more DNS resource records."),
                &vl_method_ResolveRecord,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a resolved address."),
                &vl_type_ResolvedAddress,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a resolved host name."),
                &vl_type_ResolvedName,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates resolved service information."),
                &vl_type_ResolvedService,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates the canonical name, type and domain of a DNS-SD or simple SRV service. Note that due to CNAME redirections and similar, a named DNS-SD service might resolve to a canonical service that is an unnamed simple SRV service. Or in other words: resolving a named service might return an unnamed canonical service."),
                &vl_type_ResolvedCanonical,
                SD_VARLINK_SYMBOL_COMMENT("The 'key' part of a DNS resource record."),
                &vl_type_ResourceKey,
                SD_VARLINK_SYMBOL_COMMENT("A full DNS resource record.."),
                &vl_type_ResourceRecord,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates information about a resolved DNS resource record "),
                &vl_type_ResolvedRecord,
                &vl_error_NoNameServers,
                &vl_error_NoSuchResourceRecord,
                &vl_error_QueryTimedOut,
                &vl_error_MaxAttemptsReached,
                &vl_error_InvalidReply,
                &vl_error_QueryAborted,
                &vl_error_DNSSECValidationFailed,
                &vl_error_NoTrustAnchor,
                &vl_error_ResourceRecordTypeUnsupported,
                &vl_error_NetworkDown,
                &vl_error_NoSource,
                &vl_error_StubLoop,
                &vl_error_DNSError,
                &vl_error_CNAMELoop,
                &vl_error_BadAddressSize,
                &vl_error_ResourceRecordTypeInvalidForQuery,
                &vl_error_ZoneTransfersNotPermitted,
                &vl_error_ResourceRecordTypeObsolete,
                SD_VARLINK_SYMBOL_COMMENT("The DNS resource records of the specified service are not consistent (e.g. lacks a DNS-SD service type when resolved)."),
                &vl_error_InconsistentServiceRecords);

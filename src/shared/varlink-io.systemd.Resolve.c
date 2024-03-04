/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Resolve.h"

VARLINK_DEFINE_STRUCT_TYPE(
                ResourceKey,
                VARLINK_DEFINE_FIELD(class, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(type, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecord,
                VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                VARLINK_DEFINE_FIELD(priority, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(weight, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(port, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(cpu, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(os, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(items, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(address, VARLINK_INT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(mname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(rname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(serial, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(refresh, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(expire, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(minimum, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(exchange, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(version, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(size, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(horiz_pre, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(vert_pre, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(latitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(longitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(altitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(keyTag, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(algorithm, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(digestType, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(digest, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fptype, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fingerprint, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(protocol, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(dnskey, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(signer, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(typeCovered, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(labels, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(originalTtl, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(expiration, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(inception, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(signature, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(nextDomain, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(types, VARLINK_INT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(iterations, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(salt, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(hash, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(certUsage, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(selector, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(matchingType, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(data, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(tag, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(value, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(target, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(params, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(order, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(preference, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(naptrFlags, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(services, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(regexp, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(replacement, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedAddress,
                VARLINK_DEFINE_FIELD(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(family, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(address, VARLINK_INT, VARLINK_ARRAY));

static VARLINK_DEFINE_METHOD(
                ResolveHostname,
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(family, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(addresses, ResolvedAddress, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(flags, VARLINK_INT, 0));

static VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedName,
                VARLINK_DEFINE_FIELD(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                ResolveAddress,
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(family, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(address, VARLINK_INT, VARLINK_ARRAY),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(names, ResolvedName, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(flags, VARLINK_INT, 0));

static VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedService,
                VARLINK_DEFINE_FIELD(priority, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(weight, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(port, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(hostname, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(canonicalName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD_BY_TYPE(addresses, ResolvedAddress, VARLINK_ARRAY|VARLINK_NULLABLE));

static VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedCanonical,
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(type, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(domain, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                ResolveService,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(type, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(domain, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(family, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(services, ResolvedService, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(txt, VARLINK_STRING, VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(canonical, ResolvedCanonical, 0),
                VARLINK_DEFINE_OUTPUT(flags, VARLINK_INT, 0));

static VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedRecord,
                VARLINK_DEFINE_FIELD(ifindex, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(raw, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                ResolveRecord,
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(class, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(type, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(rrs, ResolvedRecord, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(flags, VARLINK_INT, 0));

static VARLINK_DEFINE_ERROR(NoNameServers);
static VARLINK_DEFINE_ERROR(NoSuchResourceRecord);
static VARLINK_DEFINE_ERROR(QueryTimedOut);
static VARLINK_DEFINE_ERROR(MaxAttemptsReached);
static VARLINK_DEFINE_ERROR(InvalidReply);
static VARLINK_DEFINE_ERROR(QueryAborted);
static VARLINK_DEFINE_ERROR(
                DNSSECValidationFailed,
                VARLINK_DEFINE_FIELD(result, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(extendedDNSErrorCode, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, VARLINK_STRING, VARLINK_NULLABLE));
static VARLINK_DEFINE_ERROR(NoTrustAnchor);
static VARLINK_DEFINE_ERROR(ResourceRecordTypeUnsupported);
static VARLINK_DEFINE_ERROR(NetworkDown);
static VARLINK_DEFINE_ERROR(NoSource);
static VARLINK_DEFINE_ERROR(StubLoop);
static VARLINK_DEFINE_ERROR(
                DNSError,
                VARLINK_DEFINE_FIELD(rcode, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(extendedDNSErrorCode, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, VARLINK_STRING, VARLINK_NULLABLE));
static VARLINK_DEFINE_ERROR(CNAMELoop);
static VARLINK_DEFINE_ERROR(BadAddressSize);
static VARLINK_DEFINE_ERROR(ResourceRecordTypeInvalidForQuery);
static VARLINK_DEFINE_ERROR(ZoneTransfersNotPermitted);
static VARLINK_DEFINE_ERROR(ResourceRecordTypeObsolete);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve,
                "io.systemd.Resolve",
                &vl_method_ResolveHostname,
                &vl_method_ResolveAddress,
                &vl_method_ResolveService,
                &vl_method_ResolveRecord,
                &vl_type_ResolvedAddress,
                &vl_type_ResolvedName,
                &vl_type_ResolvedService,
                &vl_type_ResolvedCanonical,
                &vl_type_ResourceKey,
                &vl_type_ResourceRecord,
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
                &vl_error_ResourceRecordTypeObsolete);

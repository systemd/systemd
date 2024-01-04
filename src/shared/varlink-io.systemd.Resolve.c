/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Resolve.h"

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

static VARLINK_DEFINE_STRUCT_TYPE(
                ServiceData,
                VARLINK_DEFINE_FIELD(add_flag, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(family, VARLINK_INT, 0),
                 VARLINK_DEFINE_FIELD(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(type, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(domain, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(interface, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                ResolveAddress,
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(family, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(address, VARLINK_INT, VARLINK_ARRAY),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(names, ResolvedName, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(flags, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                StartBrowse,
                VARLINK_DEFINE_INPUT(domainName, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(type, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(ifindex, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(flags, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(browser_service_data, ServiceData, VARLINK_ARRAY));

static VARLINK_DEFINE_ERROR(NoNameServers);
static VARLINK_DEFINE_ERROR(NoSuchResourceRecord);
static VARLINK_DEFINE_ERROR(QueryTimedOut);
static VARLINK_DEFINE_ERROR(MaxAttemptsReached);
static VARLINK_DEFINE_ERROR(InvalidReply);
static VARLINK_DEFINE_ERROR(QueryAborted);
static VARLINK_DEFINE_ERROR(
                DNSSECValidationFailed,
                VARLINK_DEFINE_FIELD(result, VARLINK_STRING, 0));
static VARLINK_DEFINE_ERROR(NoTrustAnchor);
static VARLINK_DEFINE_ERROR(ResourceRecordTypeUnsupported);
static VARLINK_DEFINE_ERROR(NetworkDown);
static VARLINK_DEFINE_ERROR(NoSource);
static VARLINK_DEFINE_ERROR(StubLoop);
static VARLINK_DEFINE_ERROR(
                DNSError,
                VARLINK_DEFINE_FIELD(rcode, VARLINK_INT, 0));
static VARLINK_DEFINE_ERROR(CNAMELoop);
static VARLINK_DEFINE_ERROR(BadAddressSize);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve,
                "io.systemd.Resolve",
                &vl_method_ResolveHostname,
                &vl_method_ResolveAddress,
                &vl_method_StartBrowse,
                &vl_type_ResolvedAddress,
                &vl_type_ResolvedName,
                &vl_type_ServiceData,
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
                &vl_error_BadAddressSize);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Resolve.Hook.h"

/* We want to reuse the ResourceKey structure from the io.systemd.Resolve interface, hence import it here */
#include "varlink-io.systemd.Resolve.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Answer,
                SD_VARLINK_FIELD_COMMENT("A resource record that shall be looked up. Note that this field is (currently) mostly "
                                         "decoration, useful for debugging, and may be omitted. The data actually used is encoded in the "
                                         "'raw' field."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A resource record encoded in DNS wire format, in turn encoded in Base64. This is the actual data "
                                         "returned to the application, and should carry the same information as the 'rr' field, just in a "
                                         "different encoding."),
                SD_VARLINK_DEFINE_FIELD(raw, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Question,
                SD_VARLINK_FIELD_COMMENT("A resource record key that shall be looked up."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                QueryFilter,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("A list of domains this hook is interested in. Lookups for domains not listed here will not be "
                                         "passed to the Hook via ResolveRecord(). If this field is not set, requests for all domains "
                                         "will be passed to the hook. Note that this applies recursively, i.e. a domain of a lookup is "
                                         "considered matching the listed domains both if it exactly matches it, and in case only a suffix "
                                         "of it matches it. If this is set to an empty array the hook is disabled."),
                SD_VARLINK_DEFINE_OUTPUT(filterDomains, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Require the specified number of labels or more in a domain for the hook to be considered."),
                SD_VARLINK_DEFINE_OUTPUT(filterLabelsMin, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Require the specified number of labels or less in a domain for the hook to be considered."),
                SD_VARLINK_DEFINE_OUTPUT(filterLabelsMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ResolveRecord,
                SD_VARLINK_FIELD_COMMENT("The question being looked up, i.e. a combination of resource record keys. Note that unlike DNS "
                                         "queries on the wire these lookups can carry multiple key requests, albeit closely related ones. "
                                         "Specifically, lookups for A+AAAA for the the same hostname are submitted as one question, as "
                                         "are lookups for TXT+SRV when doing DNS-SD resolution. Moreover, when looking up resources with "
                                         "non-ASCII characters, they are placed together in a single question, once with labels encoded in "
                                         "UTF-8, and once in IDNA. Hook implementations must be able to deal with these and other similar "
                                         "combinations of resource key requests, and reply with all matching answers at once, or fail them "
                                         "as one. Partial success/failure combinations are not supported."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(question, Question, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("A DNS response code. If a hook sets this return parameter further processing of the lookup via "
                                         "regular protocols such as DNS, LLMNR, mDNS is skipped, and the return code returned immediately. "
                                         "In other words, if a hook intends to let the request pass to normal resolution, it should not "
                                         "set this return parameter."),
                SD_VARLINK_DEFINE_OUTPUT(rcode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An answer for a lookup, i.e. a combination of resource records, matching the request. This "
                                         "should only be set when the 'rcode' parameter is returned as 0 (SUCCESS)."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(answer, Answer, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve_Hook,
                "io.systemd.Resolve.Hook",
                SD_VARLINK_INTERFACE_COMMENT("Generic interface for implementing a domain name resolution hook."),
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a positive lookup answer"),
                &vl_type_Answer,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a lookup question"),
                &vl_type_Question,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates the class/type/name part of a DNS resource record."),
                &vl_type_ResourceKey,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a DNS resource record."),
                &vl_type_ResourceRecord,
                SD_VARLINK_SYMBOL_COMMENT("Returns filter parameters for this hook. A hook service can implement this to reduce lookup "
                                          "requests, by enabling itself only for certain domains or certain numbers of labels in the name. "
                                          "It's recommended to implement this to reduce the number of redundant calls to each hook. Note "
                                          "that this is advisory only, and implementing services must be able to gracefully handle lookup "
                                          "requests that do not match this filter. This call is usually made with the 'more' flag set, in "
                                          "which case the connection is left open after the first reply, and the implementing hook "
                                          "services can send updates to the filter at any time. Whenever a further reply is sent the "
                                          "filter configured therein fully replaces any previously communicated filter."),
                &vl_method_QueryFilter,
                SD_VARLINK_SYMBOL_COMMENT("Sent whenever a resolution request is made. This typically takes the filter parameters returned "
                                          "by QueryFilter() into account, but this is not guaranteed."),
                &vl_method_ResolveRecord);

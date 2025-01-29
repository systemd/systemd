/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "json-util.h"
#include "resolved-dns-synthesize.h"
#include "resolved-varlink.h"
#include "socket-netlink.h"
#include "varlink-io.systemd.Resolve.h"
#include "varlink-io.systemd.Resolve.Monitor.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

typedef struct LookupParameters {
        int ifindex;
        uint64_t flags;
        int family;
        union in_addr_union address;
        size_t address_size;
        char *name;
        uint16_t class;
        uint16_t type;
} LookupParameters;

typedef struct LookupParametersResolveService {
        const char *name;
        const char *type;
        const char *domain;
        int family;
        int ifindex;
        uint64_t flags;
} LookupParametersResolveService;

static void lookup_parameters_destroy(LookupParameters *p) {
        assert(p);
        free(p->name);
}

static int reply_query_state(DnsQuery *q) {

        assert(q);
        assert(q->varlink_request);

        switch (q->state) {

        case DNS_TRANSACTION_NO_SERVERS:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoNameServers", NULL);

        case DNS_TRANSACTION_TIMEOUT:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.QueryTimedOut", NULL);

        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.MaxAttemptsReached", NULL);

        case DNS_TRANSACTION_INVALID_REPLY:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.InvalidReply", NULL);

        case DNS_TRANSACTION_ERRNO:
                return sd_varlink_error_errno(q->varlink_request, q->answer_errno);

        case DNS_TRANSACTION_ABORTED:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.QueryAborted", NULL);

        case DNS_TRANSACTION_DNSSEC_FAILED:
                return sd_varlink_errorbo(q->varlink_request, "io.systemd.Resolve.DNSSECValidationFailed",
                                       SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(dnssec_result_to_string(q->answer_dnssec_result))),
                                       SD_JSON_BUILD_PAIR_CONDITION(q->answer_ede_rcode >= 0,
                                                                    "extendedDNSErrorCode", SD_JSON_BUILD_INTEGER(q->answer_ede_rcode)),
                                       SD_JSON_BUILD_PAIR_CONDITION(q->answer_ede_rcode >= 0 && !isempty(q->answer_ede_msg),
                                                                    "extendedDNSErrorMessage", SD_JSON_BUILD_STRING(q->answer_ede_msg)));

        case DNS_TRANSACTION_NO_TRUST_ANCHOR:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoTrustAnchor", NULL);

        case DNS_TRANSACTION_RR_TYPE_UNSUPPORTED:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.ResourceRecordTypeUnsupported", NULL);

        case DNS_TRANSACTION_NETWORK_DOWN:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NetworkDown", NULL);

        case DNS_TRANSACTION_NO_SOURCE:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoSource", NULL);

        case DNS_TRANSACTION_STUB_LOOP:
                return sd_varlink_error(q->varlink_request, "io.systemd.Resolve.StubLoop", NULL);

        case DNS_TRANSACTION_NOT_FOUND:
                /* We return this as NXDOMAIN. This is only generated when a host doesn't implement LLMNR/TCP, and we
                 * thus quickly know that we cannot resolve an in-addr.arpa or ip6.arpa address. */
                return sd_varlink_errorbo(q->varlink_request, "io.systemd.Resolve.DNSError",
                                       SD_JSON_BUILD_PAIR("rcode", SD_JSON_BUILD_INTEGER(DNS_RCODE_NXDOMAIN)));

        case DNS_TRANSACTION_RCODE_FAILURE:
                return sd_varlink_errorbo(q->varlink_request, "io.systemd.Resolve.DNSError",
                                       SD_JSON_BUILD_PAIR("rcode", SD_JSON_BUILD_INTEGER(q->answer_rcode)),
                                       SD_JSON_BUILD_PAIR_CONDITION(q->answer_ede_rcode >= 0,
                                                                    "extendedDNSErrorCode", SD_JSON_BUILD_INTEGER(q->answer_ede_rcode)),
                                       SD_JSON_BUILD_PAIR_CONDITION(q->answer_ede_rcode >= 0 && !isempty(q->answer_ede_msg),
                                                                    "extendedDNSErrorMessage", SD_JSON_BUILD_STRING(q->answer_ede_msg)));

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
        case DNS_TRANSACTION_VALIDATING:
        case DNS_TRANSACTION_SUCCESS:
        default:
                assert_not_reached();
        }
}

static void vl_on_disconnect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        DnsQuery *q;

        assert(s);
        assert(link);

        q = sd_varlink_get_userdata(link);
        if (!q)
                return;

        if (!DNS_TRANSACTION_IS_LIVE(q->state))
                return;

        log_debug("Client of active query vanished, aborting query.");
        dns_query_complete(q, DNS_TRANSACTION_ABORTED);
}

static void vl_on_notification_disconnect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_varlink *removed_link = NULL;

        assert(s);
        assert(link);

        removed_link = set_remove(m->varlink_query_results_subscription, link);
        if (removed_link) {
                sd_varlink_unref(removed_link);
                log_debug("%u query result monitor clients remain active", set_size(m->varlink_query_results_subscription));
        }

        removed_link = set_remove(m->varlink_dns_configuration_subscription, link);
        if (removed_link) {
                sd_varlink_unref(removed_link);
                log_debug("%u DNS monitor clients remain active", set_size(m->varlink_dns_configuration_subscription));

                if (set_isempty(m->varlink_dns_configuration_subscription))
                        manager_stop_dns_configuration_monitor(m);
        }
}

static bool validate_and_mangle_flags(
                const char *name,
                uint64_t *flags,
                uint64_t ok) {

        assert(flags);

        /* This checks that the specified client-provided flags parameter actually makes sense, and mangles
         * it slightly. Specifically:
         *
         * 1. We check that only the protocol flags and a bunch of NO_XYZ flags are on at most, plus the
         *    method-specific flags specified in 'ok'.
         *
         * 2. If no protocols are enabled we automatically convert that to "all protocols are enabled".
         *
         * The second rule means that clients can just pass 0 as flags for the common case, and all supported
         * protocols are enabled. Moreover it's useful so that client's do not have to be aware of all
         * protocols implemented in resolved, but can use 0 as protocols flags set as indicator for
         * "everything".
         */

        if (*flags & ~(SD_RESOLVED_PROTOCOLS_ALL|
                       SD_RESOLVED_NO_CNAME|
                       SD_RESOLVED_NO_VALIDATE|
                       SD_RESOLVED_NO_SYNTHESIZE|
                       SD_RESOLVED_NO_CACHE|
                       SD_RESOLVED_NO_ZONE|
                       SD_RESOLVED_NO_TRUST_ANCHOR|
                       SD_RESOLVED_NO_NETWORK|
                       SD_RESOLVED_NO_STALE|
                       SD_RESOLVED_RELAX_SINGLE_LABEL|
                       ok))
                return false;

        if ((*flags & SD_RESOLVED_PROTOCOLS_ALL) == 0) /* If no protocol is enabled, enable all */
                *flags |= SD_RESOLVED_PROTOCOLS_ALL;

        /* If the SD_RESOLVED_NO_SEARCH flag is acceptable, and the query name is dot-suffixed, turn off
         * search domains. Note that DNS name normalization drops the dot suffix, hence we propagate this
         * into the flags field as early as we can. */
        if (name && FLAGS_SET(ok, SD_RESOLVED_NO_SEARCH) && dns_name_dot_suffixed(name) > 0)
                *flags |= SD_RESOLVED_NO_SEARCH;

        return true;
}

static int find_addr_records(
                sd_json_variant **array,
                DnsQuestion *question,
                DnsQuery *q,
                DnsResourceRecord **canonical,
                const char *search_domain) {
        DnsResourceRecord *rr;
        int ifindex, r;

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
                int family;
                const void *p;

                r = dns_question_matches_rr(question, rr, search_domain);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (rr->key->type == DNS_TYPE_A) {
                        family = AF_INET;
                        p = &rr->a.in_addr;
                } else if (rr->key->type == DNS_TYPE_AAAA) {
                        family = AF_INET6;
                        p = &rr->aaaa.in6_addr;
                } else {
                        return -EAFNOSUPPORT;
                }

                r = sd_json_buildo(
                                &entry,
                                SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_INTEGER(ifindex)),
                                SD_JSON_BUILD_PAIR("family", SD_JSON_BUILD_INTEGER(family)),
                                SD_JSON_BUILD_PAIR("address", SD_JSON_BUILD_BYTE_ARRAY(p, FAMILY_ADDRESS_SIZE(family))));
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(array, entry);
                if (r < 0)
                        return r;

                if (canonical && !*canonical)
                        *canonical = dns_resource_record_ref(rr);
        }

        return 0;
}

static void vl_method_resolve_hostname_complete(DnsQuery *query) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        _cleanup_free_ char *normalized = NULL;
        DnsQuestion *question;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS)
                return (void) reply_query_state(q);

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        r = find_addr_records(&array, question, q, &canonical, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
        if (r < 0)
                goto finish;

        if (sd_json_variant_is_blank_object(array))
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        assert(canonical);
        r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
        if (r < 0)
                goto finish;

        r = sd_varlink_replybo(
                        q->varlink_request,
                        SD_JSON_BUILD_PAIR("addresses", SD_JSON_BUILD_VARIANT(array)),
                        SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(normalized)),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(dns_query_reply_flags_make(q))));
finish:
        if (r < 0) {
                log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_ERR, r, "Failed to send hostname reply: %m");
                (void) sd_varlink_error_errno(q->varlink_request, r);
        }
}

static int parse_as_address(sd_varlink *link, LookupParameters *p) {
        _cleanup_free_ char *canonical = NULL;
        int r, ff, parsed_ifindex, ifindex;
        union in_addr_union parsed;

        assert(link);
        assert(p);

        /* Check if this parses as literal address. If so, just parse it and return that, do not involve networking */
        r = in_addr_ifindex_from_string_auto(p->name, &ff, &parsed, &parsed_ifindex);
        if (r < 0)
                return 0; /* not a literal address */

        /* Make sure the data we parsed matches what is requested */
        if ((p->family != AF_UNSPEC && ff != p->family) ||
            (p->ifindex > 0 && parsed_ifindex > 0 && parsed_ifindex != p->ifindex))
                return sd_varlink_error(link, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        ifindex = parsed_ifindex > 0 ? parsed_ifindex : p->ifindex;

        /* Reformat the address as string, to return as canonicalized name */
        r = in_addr_ifindex_to_string(ff, &parsed, ifindex, &canonical);
        if (r < 0)
                return r;

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR("addresses",
                                           SD_JSON_BUILD_ARRAY(
                                                           SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_INTEGER(ifindex)),
                                                                           SD_JSON_BUILD_PAIR("family", SD_JSON_BUILD_INTEGER(ff)),
                                                                           SD_JSON_BUILD_PAIR("address", SD_JSON_BUILD_BYTE_ARRAY(&parsed, FAMILY_ADDRESS_SIZE(ff)))))),
                        SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(canonical)),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(SD_RESOLVED_FLAGS_MAKE(dns_synthesize_protocol(p->flags), ff, true, true)|
                                                                          SD_RESOLVED_SYNTHETIC)));
}

static int vl_method_resolve_hostname(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(LookupParameters, ifindex), SD_JSON_RELAX     },
                { "name",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(LookupParameters, name),    SD_JSON_MANDATORY },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(LookupParameters, family),  0                 },
                { "flags",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LookupParameters, flags),   0                 },
                {}
        };

        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        _cleanup_(lookup_parameters_destroy) LookupParameters p = {
                .family = AF_UNSPEC,
        };
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m;
        int r;

        assert(link);

        m = sd_varlink_server_get_userdata(sd_varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = dns_name_is_valid(p.name);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("name"));

        if (!IN_SET(p.family, AF_UNSPEC, AF_INET, AF_INET6))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("family"));

        if (!validate_and_mangle_flags(p.name, &p.flags, SD_RESOLVED_NO_SEARCH))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

        r = parse_as_address(link, &p);
        if (r != 0)
                return r;

        r = dns_question_new_address(&question_utf8, p.family, p.name, false);
        if (r < 0)
                return r;

        r = dns_question_new_address(&question_idna, p.family, p.name, true);
        if (r < 0 && r != -EALREADY)
                return r;

        r = dns_query_new(m, &q, question_utf8, question_idna ?: question_utf8, NULL, p.ifindex, p.flags);
        if (r < 0)
                return r;

        q->varlink_request = sd_varlink_ref(link);
        sd_varlink_set_userdata(link, q);
        q->request_family = p.family;
        q->complete = vl_method_resolve_hostname_complete;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int json_dispatch_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        LookupParameters *p = ASSERT_PTR(userdata);
        union in_addr_union buf = {};
        sd_json_variant *i;
        size_t n, k = 0;

        assert(variant);

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        n = sd_json_variant_elements(variant);
        if (!IN_SET(n, 4, 16))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is array of unexpected size.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                int64_t b;

                if (!sd_json_variant_is_integer(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an integer.", k, strna(name));

                b = sd_json_variant_integer(i);
                if (b < 0 || b > 0xff)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Element %zu of JSON field '%s' is out of range 0%s255.",
                                        k, strna(name), special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                buf.bytes[k++] = (uint8_t) b;
        }

        p->address = buf;
        p->address_size = k;

        return 0;
}

static void vl_method_resolve_address_complete(DnsQuery *query) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS)
                return (void) reply_query_state(q);

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                _cleanup_free_ char *normalized = NULL;

                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = dns_name_normalize(rr->ptr.name, 0, &normalized);
                if (r < 0)
                        goto finish;

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_INTEGER(ifindex)),
                                SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(normalized)));
                if (r < 0)
                        goto finish;
        }

        if (sd_json_variant_is_blank_object(array))
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        r = sd_varlink_replybo(
                        q->varlink_request,
                        SD_JSON_BUILD_PAIR("names", SD_JSON_BUILD_VARIANT(array)),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(dns_query_reply_flags_make(q))));
finish:
        if (r < 0) {
                log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_ERR, r, "Failed to send address reply: %m");
                (void) sd_varlink_error_errno(q->varlink_request, r);
        }
}

static int vl_method_resolve_address(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(LookupParameters, ifindex), SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(LookupParameters, family),  SD_JSON_MANDATORY },
                { "address", SD_JSON_VARIANT_ARRAY,         json_dispatch_address,   0,                                   SD_JSON_MANDATORY },
                { "flags",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LookupParameters, flags),   0                 },
                {}
        };

        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(lookup_parameters_destroy) LookupParameters p = {
                .family = AF_UNSPEC,
        };
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m;
        int r;

        assert(link);

        m = sd_varlink_server_get_userdata(sd_varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!IN_SET(p.family, AF_INET, AF_INET6))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("family"));

        if (FAMILY_ADDRESS_SIZE(p.family) != p.address_size)
                return sd_varlink_error(link, "io.systemd.Resolve.BadAddressSize", NULL);

        if (!validate_and_mangle_flags(NULL, &p.flags, 0))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

        r = dns_question_new_reverse(&question, p.family, &p.address);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, question, NULL, p.ifindex, p.flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->varlink_request = sd_varlink_ref(link);
        sd_varlink_set_userdata(link, q);

        q->request_family = p.family;
        q->request_address = p.address;
        q->complete = vl_method_resolve_address_complete;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int append_txt(sd_json_variant **txt, DnsResourceRecord *rr) {
        int r;

        assert(txt);
        assert(rr);
        assert(rr->key);

        if (rr->key->type != DNS_TYPE_TXT)
                return 0;

        LIST_FOREACH(items, i, rr->txt.items) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                if (i->length <= 0)
                        continue;

                r = sd_json_variant_new_octescape(&entry, i->data, i->length);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(txt, entry);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int append_srv(
                DnsQuery *q,
                DnsResourceRecord *rr,
                sd_json_variant **array) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *normalized = NULL;
        int r;

        assert(q);
        assert(rr);
        assert(rr->key);
        assert(array);

        if (rr->key->type != DNS_TYPE_SRV)
                return 0;

        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                /* First, let's see if we could find an appropriate A or AAAA
                 * record for the SRV record */
                LIST_FOREACH(auxiliary_queries, aux, q->auxiliary_queries) {
                        DnsResourceRecord *zz;
                        DnsQuestion *question;

                        if (aux->state != DNS_TRANSACTION_SUCCESS)
                                continue;
                        if (aux->auxiliary_result != 0)
                                continue;

                        question = dns_query_question_for_protocol(aux, aux->answer_protocol);

                        r = dns_name_equal(dns_question_first_name(question), rr->srv.name);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        DNS_ANSWER_FOREACH(zz, aux->answer) {
                                r = dns_question_matches_rr(question, zz, NULL);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                canonical = dns_resource_record_ref(zz);
                                break;
                        }

                        if (canonical)
                                break;
                }

                /* Is there are successful A/AAAA lookup for this SRV RR? If not, don't add it */
                if (!canonical)
                        return 0;
        }

        r = dns_name_normalize(rr->srv.name, 0, &normalized);
        if (r < 0)
                return r;

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("priority", SD_JSON_BUILD_UNSIGNED(rr->srv.priority)),
                        SD_JSON_BUILD_PAIR("weight", SD_JSON_BUILD_UNSIGNED(rr->srv.weight)),
                        SD_JSON_BUILD_PAIR("port", SD_JSON_BUILD_UNSIGNED(rr->srv.port)),
                        SD_JSON_BUILD_PAIR("hostname", SD_JSON_BUILD_STRING(normalized)));
        if (r < 0)
                return r;

        if (canonical) {
                normalized = mfree(normalized);

                r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_string(&v, "canonicalName", normalized);
                if (r < 0)
                        return r;
        }

        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *addresses = NULL;

                LIST_FOREACH(auxiliary_queries, aux, q->auxiliary_queries) {
                        DnsQuestion *question;

                        if (aux->state != DNS_TRANSACTION_SUCCESS)
                                continue;
                        if (aux->auxiliary_result != 0)
                                continue;

                        question = dns_query_question_for_protocol(aux, aux->answer_protocol);

                        r = dns_name_equal(dns_question_first_name(question), rr->srv.name);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = find_addr_records(&addresses, question, aux, NULL, NULL);
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_set_field(&v, "addresses", addresses);
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_append_array(array, v);
        if (r < 0)
                return r;

        return 1; /* added */
}

static sd_varlink* take_vl_link_aux_query(DnsQuery *aux) {
        assert(aux);

        /* Find the main query */
        while (aux->auxiliary_for)
                aux = aux->auxiliary_for;

        return TAKE_PTR(aux->varlink_request);
}

static void resolve_service_all_complete(DnsQuery *query) {
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *srv = NULL, *txt = NULL;
        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        int r;

        assert(q);

        if (q->block_all_complete > 0) {
                TAKE_PTR(q);
                return;
        }

        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                DnsQuery *bad = NULL;
                bool have_success = false;

                LIST_FOREACH(auxiliary_queries, aux, q->auxiliary_queries) {
                        switch (aux->state) {

                        case DNS_TRANSACTION_PENDING:
                                /* If an auxiliary query is still pending, let's wait */
                                TAKE_PTR(q);
                                return;

                        case DNS_TRANSACTION_SUCCESS:
                                if (aux->auxiliary_result == 0)
                                        have_success = true;
                                else
                                        bad = aux;
                                break;

                        default:
                                bad = aux;
                                break;
                        }
                }
                if (!have_success) {
                        /* We can only return one error, hence pick the last error we encountered */

                        assert(bad);
                        if (bad->state == DNS_TRANSACTION_SUCCESS) {
                                assert(bad->auxiliary_result != 0);

                                if (bad->auxiliary_result == -ELOOP)
                                        return (void) sd_varlink_error(query->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);

                                assert(bad->auxiliary_result < 0);
                                r = bad->auxiliary_result;
                                goto finish;
                        }

                        bad->varlink_request = take_vl_link_aux_query(bad);
                        return (void) reply_query_state(bad);
                }
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = append_srv(q, rr, &srv);
                if (r < 0)
                        goto finish;
                if (r == 0) /* not an SRV record */
                        continue;

                if (!canonical)
                        canonical = dns_resource_record_ref(rr);
        }

        if (sd_json_variant_is_blank_object(srv))
                return (void) sd_varlink_error(query->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                if (rr->key->type != DNS_TYPE_TXT)
                        continue;

                r = append_txt(&txt, rr);
                if (r < 0)
                        goto finish;
        }

        assert(canonical);
        r = dns_service_split(dns_resource_key_name(canonical->key), &name, &type, &domain);
        if (r < 0)
                goto finish;

        if (isempty(type))
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.InconsistentServiceRecords", NULL);

        r = sd_varlink_replybo(
                        query->varlink_request,
                        SD_JSON_BUILD_PAIR("services", SD_JSON_BUILD_VARIANT(srv)),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_json_variant_is_blank_object(txt), "txt", SD_JSON_BUILD_VARIANT(txt)),
                        SD_JSON_BUILD_PAIR("canonical", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(name)),
                                                           SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(type)),
                                                           SD_JSON_BUILD_PAIR("domain", SD_JSON_BUILD_STRING(domain)))),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_UNSIGNED(dns_query_reply_flags_make(query))));

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to resolve service: %m");
                (void) sd_varlink_error_errno(q->varlink_request, r);
        }
}

static void resolve_service_hostname_complete(DnsQuery *q) {
        int r;

        assert(q);
        assert(q->auxiliary_for);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                resolve_service_all_complete(q->auxiliary_for);
                return;
        }

        r = dns_query_process_cname_many(q);
        if (r == DNS_QUERY_CNAME) /* This was a cname, and the query was restarted. */
                return;

        /* This auxiliary lookup is finished or failed, let's see if all are finished now. */
        q->auxiliary_result = r < 0 ? r : 0;
        resolve_service_all_complete(q->auxiliary_for);
}

static int resolve_service_hostname(DnsQuery *q, DnsResourceRecord *rr, int ifindex) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *aux = NULL;
        int r;

        assert(q);
        assert(rr);
        assert(rr->key);
        assert(rr->key->type == DNS_TYPE_SRV);

        /* OK, we found an SRV record for the service. Let's resolve
         * the hostname included in it */

        r = dns_question_new_address(&question, q->request_family, rr->srv.name, false);
        if (r < 0)
                return r;

        r = dns_query_new(q->manager, &aux, question, question, NULL, ifindex, q->flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        aux->request_family = q->request_family;
        aux->complete = resolve_service_hostname_complete;

        r = dns_query_make_auxiliary(aux, q);
        if (r == -EAGAIN)
                /* Too many auxiliary lookups? If so, don't complain,
                 * let's just not add this one, we already have more
                 * than enough */
                return 0;
        if (r < 0)
                return r;

        /* Note that auxiliary queries do not track the original
         * client, only the primary request does that. */

        r = dns_query_go(aux);
        if (r < 0)
                return r;

        TAKE_PTR(aux);
        return 1;
}

static void vl_method_resolve_service_complete(DnsQuery *query) {
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        bool has_root_domain = false;
        DnsResourceRecord *rr;
        DnsQuestion *question;
        unsigned found = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS)
                return (void) reply_query_state(q);

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
        if (r < 0)
                goto fail;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        continue;

                if (rr->key->type != DNS_TYPE_SRV)
                        continue;

                if (dns_name_is_root(rr->srv.name)) {
                        has_root_domain = true;
                        continue;
                }

                if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                        q->block_all_complete++;
                        r = resolve_service_hostname(q, rr, ifindex);
                        q->block_all_complete--;

                        if (r < 0)
                                goto fail;
                }

                found++;
        }

        if (has_root_domain && found <= 0)
                /* If there's exactly one SRV RR and it uses the root domain as hostname, then the service is
                 * explicitly not offered on the domain. Report this as a recognizable error. See RFC 2782,
                 * Section "Usage Rules". */
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.ServiceNotProvided", NULL);

        if (found <= 0)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        /* Maybe we are already finished? check now... */
        resolve_service_all_complete(TAKE_PTR(q));
        return;

fail:
        log_error_errno(r, "Failed to send address reply: %m");
        (void) sd_varlink_error_errno(q->varlink_request, r);
}

static int vl_method_resolve_service(sd_varlink* link, sd_json_variant* parameters, sd_varlink_method_flags_t flags, void* userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(LookupParametersResolveService, name),    0                 },
                { "type",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(LookupParametersResolveService, type),    0                 },
                { "domain",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(LookupParametersResolveService, domain),  SD_JSON_MANDATORY },
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,         offsetof(LookupParametersResolveService, ifindex), SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(LookupParametersResolveService, family),  0                 },
                { "flags",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(LookupParametersResolveService, flags),   0                 },
                {}
        };

        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        LookupParametersResolveService p = {
                .family = AF_UNSPEC,
        };

        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m;
        int r;

        assert(link);

        m = sd_varlink_server_get_userdata(sd_varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!IN_SET(p.family, AF_INET, AF_INET6, AF_UNSPEC))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("family"));

        if (isempty(p.name))
                p.name = NULL;
        else if (!dns_service_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("name"));

        if (isempty(p.type))
                p.type = NULL;
        else if (!dns_srv_type_is_valid(p.type))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("type"));

        r = dns_name_is_valid(p.domain);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("domain"));

        if (p.name && !p.type) /* Service name cannot be specified without service type. */
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("type"));

        if (!validate_and_mangle_flags(p.name, &p.flags, SD_RESOLVED_NO_TXT|SD_RESOLVED_NO_ADDRESS))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

        r = dns_question_new_service(&question_utf8, p.name, p.type, p.domain, !(p.flags & SD_RESOLVED_NO_TXT), false);
        if (r < 0)
                return r;

        r = dns_question_new_service(&question_idna, p.name, p.type, p.domain, !(p.flags & SD_RESOLVED_NO_TXT), true);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question_utf8, question_idna, NULL, p.ifindex, p.flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->varlink_request = sd_varlink_ref(link);
        q->request_family = p.family;
        q->complete = vl_method_resolve_service_complete;

        sd_varlink_set_userdata(link, q);

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static void vl_method_resolve_record_complete(DnsQuery *query) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsQuestion *question;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS)
                return (void) reply_query_state(q);

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        unsigned added = 0;
        int ifindex;
        DnsResourceRecord *rr;
        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = dns_resource_record_to_json(rr, &v);
                if (r < 0)
                        goto finish;

                r = dns_resource_record_to_wire_format(rr, /* canonical= */ false); /* don't use DNSSEC canonical format, since it removes casing, but we want that for DNS_SD compat */
                if (r < 0)
                        goto finish;

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_INTEGER(ifindex)),
                                SD_JSON_BUILD_PAIR_CONDITION(!!v, "rr", SD_JSON_BUILD_VARIANT(v)),
                                SD_JSON_BUILD_PAIR("raw", SD_JSON_BUILD_BASE64(rr->wire_format, rr->wire_format_size)));
                if (r < 0)
                        goto finish;

                added++;
        }

        if (added <= 0)
                return (void) sd_varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        r = sd_varlink_replybo(
                        q->varlink_request,
                        SD_JSON_BUILD_PAIR("rrs", SD_JSON_BUILD_VARIANT(array)),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(dns_query_reply_flags_make(q))));
finish:
        if (r < 0) {
                log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_ERR, r, "Failed to send record reply: %m");
                (void) sd_varlink_error_errno(q->varlink_request, r);
        }
}

static int vl_method_resolve_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(LookupParameters, ifindex), SD_JSON_RELAX     },
                { "name",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(LookupParameters, name),    SD_JSON_MANDATORY },
                { "class",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(LookupParameters, class),   0                 },
                { "type",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(LookupParameters, type),    SD_JSON_MANDATORY },
                { "flags",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LookupParameters, flags),   0                 },
                {}
        };

        _cleanup_(lookup_parameters_destroy) LookupParameters p = {
                .class = DNS_CLASS_IN,
                .type = _DNS_TYPE_INVALID,
        };
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m;
        int r;

        assert(link);

        m = ASSERT_PTR(sd_varlink_server_get_userdata(sd_varlink_get_server(link)));

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = dns_name_is_valid(p.name);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("name"));

        if (!dns_type_is_valid_query(p.type))
                return sd_varlink_error(link, "io.systemd.Resolve.ResourceRecordTypeInvalidForQuery", NULL);
        if (dns_type_is_zone_transfer(p.type))
                return sd_varlink_error(link, "io.systemd.Resolve.ZoneTransfersNotPermitted", NULL);
        if (dns_type_is_obsolete(p.type))
                return sd_varlink_error(link, "io.systemd.Resolve.ResourceRecordTypeObsolete", NULL);

        if (!validate_and_mangle_flags(p.name, &p.flags, SD_RESOLVED_NO_SEARCH))
                return sd_varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

        _cleanup_(dns_question_unrefp) DnsQuestion *question = dns_question_new(1);
        if (!question)
                return -ENOMEM;

        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        key = dns_resource_key_new(p.class, p.type, p.name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(question, key, /* flags= */ 0);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, question, NULL, p.ifindex, p.flags|SD_RESOLVED_NO_SEARCH|SD_RESOLVED_CLAMP_TTL);
        if (r < 0)
                return r;

        q->varlink_request = sd_varlink_ref(link);
        sd_varlink_set_userdata(link, q);
        q->complete = vl_method_resolve_record_complete;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int verify_polkit(sd_varlink *link, sd_json_variant *parameters, const char *action) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        int r;
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));

        assert(action);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata = */ NULL);
        if (r != 0)
                return r;

        return varlink_verify_polkit_async(
                                link,
                                m->bus,
                                action,
                                /* details= */ NULL,
                                &m->polkit_registry);
}

static int vl_method_subscribe_query_results(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        int r;

        /* if the client didn't set the more flag, it is using us incorrectly */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.subscribe-query-results");
        if (r <= 0)
                return r;

        /* Send a ready message to the connecting client, to indicate that we are now listinening, and all
         * queries issued after the point the client sees this will also be reported to the client. */
        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR("ready", SD_JSON_BUILD_BOOLEAN(true)));
        if (r < 0)
                return log_error_errno(r, "Failed to report monitor to be established: %m");

        r = set_ensure_put(&m->varlink_query_results_subscription, NULL, link);
        if (r < 0)
                return log_error_errno(r, "Failed to add subscription to set: %m");
        sd_varlink_ref(link);

        log_debug("%u clients now attached for query result varlink notifications", set_size(m->varlink_query_results_subscription));

        return 1;
}

static int vl_method_dump_cache(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *list = NULL;
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        int r;

        assert(link);

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.dump-cache");
        if (r <= 0)
                return r;

        LIST_FOREACH(scopes, s, m->dns_scopes) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

                r = dns_scope_dump_cache_to_json(s, &j);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&list, j);
                if (r < 0)
                        return r;
        }

        if (!list) {
                r = sd_json_variant_new_array(&list, NULL, 0);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR("dump", SD_JSON_BUILD_VARIANT(list)));
}

static int dns_server_dump_state_to_json_list(DnsServer *server, sd_json_variant **list) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        int r;

        assert(list);
        assert(server);

        r = dns_server_dump_state_to_json(server, &j);
        if (r < 0)
                return r;

        return sd_json_variant_append_array(list, j);
}

static int vl_method_dump_server_state(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *list = NULL;
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        Link *l;
        int r;

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.dump-server-state");
        if (r <= 0)
                return r;

        LIST_FOREACH(servers, server, m->dns_servers) {
                r = dns_server_dump_state_to_json_list(server, &list);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(servers, server, m->fallback_dns_servers) {
                r = dns_server_dump_state_to_json_list(server, &list);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links)
                LIST_FOREACH(servers, server, l->dns_servers) {
                        r = dns_server_dump_state_to_json_list(server, &list);
                        if (r < 0)
                                return r;
                }

        if (!list) {
                r = sd_json_variant_new_array(&list, NULL, 0);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR("dump", SD_JSON_BUILD_VARIANT(list)));
}

static int vl_method_dump_statistics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        int r;

        assert(link);

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.dump-statistics");
        if (r <= 0)
                return r;

        r = dns_manager_dump_statistics_json(m, &j);
        if (r < 0)
                return r;

        return sd_varlink_replyb(link, SD_JSON_BUILD_VARIANT(j));
}

static int vl_method_reset_statistics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        int r;

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.reset-statistics");
        if (r <= 0)
                return r;

        dns_manager_reset_statistics(m);

        return sd_varlink_replyb(link, SD_JSON_BUILD_EMPTY_OBJECT);
}

static int vl_method_subscribe_dns_configuration(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));
        int r;

        /* if the client didn't set the more flag, it is using us incorrectly */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = verify_polkit(link, parameters, "org.freedesktop.resolve1.subscribe-dns-configuration");
        if (r <= 0)
                return r;

        if (set_isempty(m->varlink_dns_configuration_subscription)) {
                r = manager_start_dns_configuration_monitor(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to start DNS configuration monitor: %m");
        }

        r = sd_varlink_notify(link, m->dns_configuration_json);
        if (r < 0)
                goto fail;

        r = set_ensure_put(&m->varlink_dns_configuration_subscription, NULL, link);
        if (r < 0)
                goto fail;
        sd_varlink_ref(link);

        log_debug("%u clients now attached for link configuration varlink notifications",
                  set_size(m->varlink_dns_configuration_subscription));

        return 1;
fail:
        if (set_isempty(m->varlink_dns_configuration_subscription))
                manager_stop_dns_configuration_monitor(m);

        return log_debug_errno(r, "Failed to subscribe client to DNS configuration monitor: %m");
}

static int varlink_monitor_server_init(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        int r;

        assert(m);

        if (m->varlink_monitor_server)
                return 0;

        r = varlink_server_new(&server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Resolve_Monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to add Resolve.Monitor interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.Resolve.Monitor.SubscribeQueryResults", vl_method_subscribe_query_results,
                        "io.systemd.Resolve.Monitor.DumpCache", vl_method_dump_cache,
                        "io.systemd.Resolve.Monitor.DumpServerState", vl_method_dump_server_state,
                        "io.systemd.Resolve.Monitor.DumpStatistics", vl_method_dump_statistics,
                        "io.systemd.Resolve.Monitor.ResetStatistics", vl_method_reset_statistics,
                        "io.systemd.Resolve.Monitor.SubscribeDNSConfiguration", vl_method_subscribe_dns_configuration);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(server, vl_on_notification_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink disconnect handler: %m");

        r = sd_varlink_server_listen_address(server, "/run/systemd/resolve/io.systemd.Resolve.Monitor", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = sd_varlink_server_attach_event(server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_monitor_server = TAKE_PTR(server);

        return 0;
}

static int varlink_main_server_init(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Resolve,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Resolve interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Resolve.ResolveHostname", vl_method_resolve_hostname,
                        "io.systemd.Resolve.ResolveAddress",  vl_method_resolve_address,
                        "io.systemd.Resolve.ResolveService",  vl_method_resolve_service,
                        "io.systemd.Resolve.ResolveRecord",   vl_method_resolve_record,
                        "io.systemd.service.Ping",            varlink_method_ping,
                        "io.systemd.service.SetLogLevel",     varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment",  varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(s, vl_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink disconnect handler: %m");

        r = sd_varlink_server_listen_address(s, "/run/systemd/resolve/io.systemd.Resolve", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

int manager_varlink_init(Manager *m) {
        int r;

        r = varlink_main_server_init(m);
        if (r < 0)
                return r;

        r = varlink_monitor_server_init(m);
        if (r < 0)
                return r;

        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_server = sd_varlink_server_unref(m->varlink_server);
        m->varlink_monitor_server = sd_varlink_server_unref(m->varlink_monitor_server);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "glyph-util.h"
#include "in-addr-util.h"
#include "resolved-dns-synthesize.h"
#include "resolved-varlink.h"
#include "socket-netlink.h"

typedef struct LookupParameters {
        int ifindex;
        uint64_t flags;
        int family;
        union in_addr_union address;
        size_t address_size;
        char *name;
} LookupParameters;

static void lookup_parameters_destroy(LookupParameters *p) {
        assert(p);
        free(p->name);
}

static int reply_query_state(DnsQuery *q) {

        assert(q);
        assert(q->varlink_request);

        switch (q->state) {

        case DNS_TRANSACTION_NO_SERVERS:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.NoNameServers", NULL);

        case DNS_TRANSACTION_TIMEOUT:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.QueryTimedOut", NULL);

        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.MaxAttemptsReached", NULL);

        case DNS_TRANSACTION_INVALID_REPLY:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.InvalidReply", NULL);

        case DNS_TRANSACTION_ERRNO:
                return varlink_error_errno(q->varlink_request, q->answer_errno);

        case DNS_TRANSACTION_ABORTED:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.QueryAborted", NULL);

        case DNS_TRANSACTION_DNSSEC_FAILED:
                return varlink_errorb(q->varlink_request, "io.systemd.Resolve.DNSSECValidationFailed",
                                      JSON_BUILD_OBJECT(JSON_BUILD_PAIR("result", JSON_BUILD_STRING(dnssec_result_to_string(q->answer_dnssec_result)))));

        case DNS_TRANSACTION_NO_TRUST_ANCHOR:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.NoTrustAnchor", NULL);

        case DNS_TRANSACTION_RR_TYPE_UNSUPPORTED:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.ResourceRecordTypeUnsupported", NULL);

        case DNS_TRANSACTION_NETWORK_DOWN:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.NetworkDown", NULL);

        case DNS_TRANSACTION_NO_SOURCE:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.NoSource", NULL);

        case DNS_TRANSACTION_STUB_LOOP:
                return varlink_error(q->varlink_request, "io.systemd.Resolve.StubLoop", NULL);

        case DNS_TRANSACTION_NOT_FOUND:
                /* We return this as NXDOMAIN. This is only generated when a host doesn't implement LLMNR/TCP, and we
                 * thus quickly know that we cannot resolve an in-addr.arpa or ip6.arpa address. */
                return varlink_errorb(q->varlink_request, "io.systemd.Resolve.DNSError",
                                      JSON_BUILD_OBJECT(JSON_BUILD_PAIR("rcode", JSON_BUILD_INTEGER(DNS_RCODE_NXDOMAIN))));

        case DNS_TRANSACTION_RCODE_FAILURE:
                return varlink_errorb(q->varlink_request, "io.systemd.Resolve.DNSError",
                                      JSON_BUILD_OBJECT(JSON_BUILD_PAIR("rcode", JSON_BUILD_INTEGER(q->answer_rcode))));

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
        case DNS_TRANSACTION_VALIDATING:
        case DNS_TRANSACTION_SUCCESS:
        default:
                assert_not_reached();
        }
}

static void vl_on_disconnect(VarlinkServer *s, Varlink *link, void *userdata) {
        DnsQuery *q;

        assert(s);
        assert(link);

        q = varlink_get_userdata(link);
        if (!q)
                return;

        if (!DNS_TRANSACTION_IS_LIVE(q->state))
                return;

        log_debug("Client of active query vanished, aborting query.");
        dns_query_complete(q, DNS_TRANSACTION_ABORTED);
}

static void vl_on_notification_disconnect(VarlinkServer *s, Varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);
        assert(link);

        Varlink *removed_link = set_remove(m->varlink_subscription, link);
        if (removed_link) {
                varlink_unref(removed_link);
                log_debug("%u monitor clients remain active", set_size(m->varlink_subscription));
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

static void vl_method_resolve_hostname_complete(DnsQuery *query) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        _cleanup_free_ char *normalized = NULL;
        DnsResourceRecord *rr;
        DnsQuestion *question;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                _cleanup_(json_variant_unrefp) JsonVariant *entry = NULL;
                int family;
                const void *p;

                r = dns_question_matches_rr(question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                if (rr->key->type == DNS_TYPE_A) {
                        family = AF_INET;
                        p = &rr->a.in_addr;
                } else if (rr->key->type == DNS_TYPE_AAAA) {
                        family = AF_INET6;
                        p = &rr->aaaa.in6_addr;
                } else {
                        r = -EAFNOSUPPORT;
                        goto finish;
                }

                r = json_build(&entry,
                               JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", JSON_BUILD_INTEGER(ifindex)),
                                               JSON_BUILD_PAIR("family", JSON_BUILD_INTEGER(family)),
                                               JSON_BUILD_PAIR("address", JSON_BUILD_BYTE_ARRAY(p, FAMILY_ADDRESS_SIZE(family)))));
                if (r < 0)
                        goto finish;

                if (!canonical)
                        canonical = dns_resource_record_ref(rr);

                r = json_variant_append_array(&array, entry);
                if (r < 0)
                        goto finish;
        }

        if (json_variant_is_blank_object(array)) {
                r = varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);
                goto finish;
        }

        assert(canonical);
        r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
        if (r < 0)
                goto finish;

        r = varlink_replyb(q->varlink_request,
                           JSON_BUILD_OBJECT(
                                           JSON_BUILD_PAIR("addresses", JSON_BUILD_VARIANT(array)),
                                           JSON_BUILD_PAIR("name", JSON_BUILD_STRING(normalized)),
                                           JSON_BUILD_PAIR("flags", JSON_BUILD_INTEGER(dns_query_reply_flags_make(q)))));
finish:
        if (r < 0) {
                log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_ERR, r, "Failed to send hostname reply: %m");
                r = varlink_error_errno(q->varlink_request, r);
        }
}

static int parse_as_address(Varlink *link, LookupParameters *p) {
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
                return varlink_error(link, "io.systemd.Resolve.NoSuchResourceRecord", NULL);

        ifindex = parsed_ifindex > 0 ? parsed_ifindex : p->ifindex;

        /* Reformat the address as string, to return as canonicalized name */
        r = in_addr_ifindex_to_string(ff, &parsed, ifindex, &canonical);
        if (r < 0)
                return r;

        return varlink_replyb(
                        link,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("addresses",
                                        JSON_BUILD_ARRAY(
                                                JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", JSON_BUILD_INTEGER(ifindex)),
                                                        JSON_BUILD_PAIR("family", JSON_BUILD_INTEGER(ff)),
                                                        JSON_BUILD_PAIR("address", JSON_BUILD_BYTE_ARRAY(&parsed, FAMILY_ADDRESS_SIZE(ff)))))),
                                JSON_BUILD_PAIR("name", JSON_BUILD_STRING(canonical)),
                                JSON_BUILD_PAIR("flags", JSON_BUILD_INTEGER(SD_RESOLVED_FLAGS_MAKE(dns_synthesize_protocol(p->flags), ff, true, true)|
                                                                            SD_RESOLVED_SYNTHETIC))));
}

static int vl_method_resolve_hostname(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "ifindex", JSON_VARIANT_UNSIGNED, json_dispatch_int,    offsetof(LookupParameters, ifindex), 0              },
                { "name",    JSON_VARIANT_STRING,   json_dispatch_string, offsetof(LookupParameters, name),    JSON_MANDATORY },
                { "family",  JSON_VARIANT_UNSIGNED, json_dispatch_int,    offsetof(LookupParameters, family),  0              },
                { "flags",   JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(LookupParameters, flags),   0              },
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

        m = varlink_server_get_userdata(varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.ifindex < 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));

        r = dns_name_is_valid(p.name);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("name"));

        if (!IN_SET(p.family, AF_UNSPEC, AF_INET, AF_INET6))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("family"));

        if (!validate_and_mangle_flags(p.name, &p.flags, SD_RESOLVED_NO_SEARCH))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

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

        q->varlink_request = varlink_ref(link);
        varlink_set_userdata(link, q);
        q->request_family = p.family;
        q->complete = vl_method_resolve_hostname_complete;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int json_dispatch_address(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        LookupParameters *p = ASSERT_PTR(userdata);
        union in_addr_union buf = {};
        JsonVariant *i;
        size_t n, k = 0;

        assert(variant);

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        n = json_variant_elements(variant);
        if (!IN_SET(n, 4, 16))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is array of unexpected size.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                int64_t b;

                if (!json_variant_is_integer(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an integer.", k, strna(name));

                b = json_variant_integer(i);
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
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = varlink_error(q->varlink_request, "io.systemd.Resolve.CNAMELoop", NULL);
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                _cleanup_(json_variant_unrefp) JsonVariant *entry = NULL;
                _cleanup_free_ char *normalized = NULL;

                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = dns_name_normalize(rr->ptr.name, 0, &normalized);
                if (r < 0)
                        goto finish;

                r = json_build(&entry,
                               JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", JSON_BUILD_INTEGER(ifindex)),
                                               JSON_BUILD_PAIR("name", JSON_BUILD_STRING(normalized))));
                if (r < 0)
                        goto finish;

                r = json_variant_append_array(&array, entry);
                if (r < 0)
                        goto finish;
        }

        if (json_variant_is_blank_object(array)) {
                r = varlink_error(q->varlink_request, "io.systemd.Resolve.NoSuchResourceRecord", NULL);
                goto finish;
        }

        r = varlink_replyb(q->varlink_request,
                           JSON_BUILD_OBJECT(
                                           JSON_BUILD_PAIR("names", JSON_BUILD_VARIANT(array)),
                                           JSON_BUILD_PAIR("flags", JSON_BUILD_INTEGER(dns_query_reply_flags_make(q)))));
finish:
        if (r < 0) {
                log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_ERR, r, "Failed to send address reply: %m");
                r = varlink_error_errno(q->varlink_request, r);
        }
}

static int vl_method_resolve_address(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "ifindex", JSON_VARIANT_UNSIGNED, json_dispatch_int,     offsetof(LookupParameters, ifindex), 0              },
                { "family",  JSON_VARIANT_UNSIGNED, json_dispatch_int,     offsetof(LookupParameters, family),  JSON_MANDATORY },
                { "address", JSON_VARIANT_ARRAY,    json_dispatch_address, 0,                                   JSON_MANDATORY },
                { "flags",   JSON_VARIANT_UNSIGNED, json_dispatch_uint64,  offsetof(LookupParameters, flags),   0              },
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

        m = varlink_server_get_userdata(varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.ifindex < 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));

        if (!IN_SET(p.family, AF_INET, AF_INET6))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("family"));

        if (FAMILY_ADDRESS_SIZE(p.family) != p.address_size)
                return varlink_error(link, "io.systemd.Resolve.BadAddressSize", NULL);

        if (!validate_and_mangle_flags(NULL, &p.flags, 0))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("flags"));

        r = dns_question_new_reverse(&question, p.family, &p.address);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, question, NULL, p.ifindex, p.flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->varlink_request = varlink_ref(link);
        varlink_set_userdata(link, q);

        q->request_family = p.family;
        q->request_address = p.address;
        q->complete = vl_method_resolve_address_complete;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int vl_method_subscribe_dns_resolves(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m;
        int r;

        assert(link);

        m = ASSERT_PTR(varlink_server_get_userdata(varlink_get_server(link)));

        /* if the client didn't set the more flag, it is using us incorrectly */
        if (!FLAGS_SET(flags, VARLINK_METHOD_MORE))
                return varlink_error_invalid_parameter(link, NULL);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        /* Send a ready message to the connecting client, to indicate that we are now listinening, and all
         * queries issued after the point the client sees this will also be reported to the client. */
        r = varlink_notifyb(link,
                            JSON_BUILD_OBJECT(JSON_BUILD_PAIR("ready", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return log_error_errno(r, "Failed to report monitor to be established: %m");

        r = set_ensure_put(&m->varlink_subscription, NULL, link);
        if (r < 0)
                return log_error_errno(r, "Failed to add subscription to set: %m");
        varlink_ref(link);

        log_debug("%u clients now attached for varlink notifications", set_size(m->varlink_subscription));

        return 1;
}

static int varlink_monitor_server_init(Manager *m) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *server = NULL;
        int r;

        assert(m);

        if (m->varlink_monitor_server)
                return 0;

        r = varlink_server_new(&server, VARLINK_SERVER_ROOT_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(server, m);

        r = varlink_server_bind_method(
                        server,
                        "io.systemd.Resolve.Monitor.SubscribeQueryResults",
                        vl_method_subscribe_dns_resolves);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = varlink_server_bind_disconnect(server, vl_on_notification_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink disconnect handler: %m");

        r = varlink_server_listen_address(server, "/run/systemd/resolve/io.systemd.Resolve.Monitor", 0600);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_monitor_server = TAKE_PTR(server);

        return 0;
}

static int varlink_main_server_init(Manager *m) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(&s, VARLINK_SERVER_ACCOUNT_UID);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(s, m);

        r = varlink_server_bind_method_many(
                        s,
                        "io.systemd.Resolve.ResolveHostname",  vl_method_resolve_hostname,
                        "io.systemd.Resolve.ResolveAddress", vl_method_resolve_address);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = varlink_server_bind_disconnect(s, vl_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink disconnect handler: %m");

        r = varlink_server_listen_address(s, "/run/systemd/resolve/io.systemd.Resolve", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
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

        m->varlink_server = varlink_server_unref(m->varlink_server);
        m->varlink_monitor_server = varlink_server_unref(m->varlink_monitor_server);
}

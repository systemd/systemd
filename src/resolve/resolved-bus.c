/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-message-util.h"
#include "bus-polkit.h"
#include "dns-domain.h"
#include "format-util.h"
#include "memory-util.h"
#include "missing_capability.h"
#include "resolved-bus.h"
#include "resolved-def.h"
#include "resolved-dns-synthesize.h"
#include "resolved-dnssd-bus.h"
#include "resolved-dnssd.h"
#include "resolved-link-bus.h"
#include "resolved-resolv-conf.h"
#include "socket-netlink.h"
#include "stdio-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "user-util.h"
#include "utf8.h"

BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_resolve_support, resolve_support, ResolveSupport);

static int query_on_bus_track(sd_bus_track *t, void *userdata) {
        DnsQuery *q = ASSERT_PTR(userdata);

        assert(t);

        if (!DNS_TRANSACTION_IS_LIVE(q->state))
                return 0;

        log_debug("Client of active query vanished, aborting query.");
        dns_query_complete(q, DNS_TRANSACTION_ABORTED);
        return 0;
}

static int dns_query_bus_track(DnsQuery *q, sd_bus_message *m) {
        int r;

        assert(q);
        assert(m);

        if (!q->bus_track) {
                r = sd_bus_track_new(sd_bus_message_get_bus(m), &q->bus_track, query_on_bus_track, q);
                if (r < 0)
                        return r;
        }

        r = sd_bus_track_add_sender(q->bus_track, m);
        if (r < 0)
                return r;

        return 0;
}

static sd_bus_message *dns_query_steal_request(DnsQuery *q) {
        assert(q);

        /* Find the main query, it's the one that owns the message */
        while (q->auxiliary_for)
                q = q->auxiliary_for;

        /* Let's take the request message out of the DnsQuery object, so that we never send requests twice */
        return TAKE_PTR(q->bus_request);
}

_sd_printf_(3, 4) static int reply_method_errorf(
                DnsQuery *query,
                const char *error_name,
                const char *format,
                ...) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        va_list ap;
        int r;

        assert(query);
        assert(format);

        req = dns_query_steal_request(query);
        if (!req) /* No bus message set anymore? then we already replied already, let's not answer a second time */
                return 0;

        va_start(ap, format);
        r = sd_bus_reply_method_errorfv(req, error_name, format, ap);
        va_end(ap);

        return r;
}

_sd_printf_(3, 4) static int reply_method_errnof(
                DnsQuery *query,
                int err,
                const char *format,
                ...) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        int r;

        assert(query);

        req = dns_query_steal_request(query);
        if (!req) /* No bus message set anymore? then we already replied already, let's not answer a second time */
                return 0;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = sd_bus_reply_method_errnofv(req, err, format, ap);
                va_end(ap);
        } else
                r = sd_bus_reply_method_errno(req, err, NULL);

        return r;
}

static int reply_query_state(DnsQuery *q) {
        assert(q);

        switch (q->state) {

        case DNS_TRANSACTION_NO_SERVERS:
                return reply_method_errorf(q, BUS_ERROR_NO_NAME_SERVERS, "No appropriate name servers or networks for name found");

        case DNS_TRANSACTION_TIMEOUT:
                return reply_method_errorf(q, SD_BUS_ERROR_TIMEOUT, "Query timed out");

        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                return reply_method_errorf(q, SD_BUS_ERROR_TIMEOUT, "All attempts to contact name servers or networks failed");

        case DNS_TRANSACTION_INVALID_REPLY:
                return reply_method_errorf(q, BUS_ERROR_INVALID_REPLY, "Received invalid reply");

        case DNS_TRANSACTION_ERRNO:
                return reply_method_errnof(q, q->answer_errno, "Lookup failed due to system error: %m");

        case DNS_TRANSACTION_ABORTED:
                return reply_method_errorf(q, BUS_ERROR_ABORTED, "Query aborted");

        case DNS_TRANSACTION_DNSSEC_FAILED:
                return reply_method_errorf(q, BUS_ERROR_DNSSEC_FAILED, "DNSSEC validation failed: %s",
                                           dnssec_result_to_string(q->answer_dnssec_result));

        case DNS_TRANSACTION_NO_TRUST_ANCHOR:
                return reply_method_errorf(q, BUS_ERROR_NO_TRUST_ANCHOR, "No suitable trust anchor known");

        case DNS_TRANSACTION_RR_TYPE_UNSUPPORTED:
                return reply_method_errorf(q, BUS_ERROR_RR_TYPE_UNSUPPORTED, "Server does not support requested resource record type");

        case DNS_TRANSACTION_NETWORK_DOWN:
                return reply_method_errorf(q, BUS_ERROR_NETWORK_DOWN, "Network is down");

        case DNS_TRANSACTION_NOT_FOUND:
                /* We return this as NXDOMAIN. This is only generated when a host doesn't implement LLMNR/TCP, and we
                 * thus quickly know that we cannot resolve an in-addr.arpa or ip6.arpa address. */
                return reply_method_errorf(q, BUS_ERROR_DNS_NXDOMAIN, "'%s' not found", dns_query_string(q));

        case DNS_TRANSACTION_NO_SOURCE:
                return reply_method_errorf(q, BUS_ERROR_NO_SOURCE, "All suitable resolution sources turned off");

        case DNS_TRANSACTION_STUB_LOOP:
                return reply_method_errorf(q, BUS_ERROR_STUB_LOOP, "Configured DNS server loops back to us");

        case DNS_TRANSACTION_RCODE_FAILURE: {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;

                req = dns_query_steal_request(q);
                if (!req) /* No bus message set anymore? then we already replied already, let's not answer a second time */
                        return 0;

                if (q->answer_rcode == DNS_RCODE_NXDOMAIN)
                        sd_bus_error_setf(&error, BUS_ERROR_DNS_NXDOMAIN, "Name '%s' not found", dns_query_string(q));
                else {
                        const char *rc, *n;

                        rc = FORMAT_DNS_RCODE(q->answer_rcode);
                        n = strjoina(_BUS_ERROR_DNS, rc);
                        sd_bus_error_setf(&error, n, "Could not resolve '%s', server or network returned error %s", dns_query_string(q), rc);
                }

                return sd_bus_reply_method_error(req, &error);
        }

        case DNS_TRANSACTION_EDE_RCODE_FAILURE:
                return reply_method_errorf(q, BUS_ERROR_DNSSEC_FAILED, "DNSSEC validation failed upstream: %s%s%s",
                                           dns_ede_rcode_to_string(q->answer_ede_rcode),
                                           isempty(q->answer_ede_msg) ? "" : ": ", q->answer_ede_msg);

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
        case DNS_TRANSACTION_VALIDATING:
        case DNS_TRANSACTION_SUCCESS:
        default:
                assert_not_reached();
        }
}

static int append_address(sd_bus_message *reply, DnsResourceRecord *rr, int ifindex) {
        int r;

        assert(reply);
        assert(rr);

        r = sd_bus_message_open_container(reply, 'r', "iiay");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "i", ifindex);
        if (r < 0)
                return r;

        if (rr->key->type == DNS_TYPE_A) {
                r = sd_bus_message_append(reply, "i", AF_INET);
                if (r < 0)
                        return r;

                r = sd_bus_message_append_array(reply, 'y', &rr->a.in_addr, sizeof(struct in_addr));

        } else if (rr->key->type == DNS_TYPE_AAAA) {
                r = sd_bus_message_append(reply, "i", AF_INET6);
                if (r < 0)
                        return r;

                r = sd_bus_message_append_array(reply, 'y', &rr->aaaa.in6_addr, sizeof(struct in6_addr));
        } else
                return -EAFNOSUPPORT;

        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return 0;
}

static void bus_method_resolve_hostname_complete(DnsQuery *query) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        _cleanup_free_ char *normalized = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        unsigned added = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = reply_method_errorf(q, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        r = sd_bus_message_new_method_return(q->bus_request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto finish;

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {

                r = dns_question_matches_rr(question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = append_address(reply, rr, ifindex);
                if (r < 0)
                        goto finish;

                if (!canonical)
                        canonical = dns_resource_record_ref(rr);

                added++;
        }

        if (added <= 0) {
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        /* The key names are not necessarily normalized, make sure that they are when we return them to our
         * bus clients. */
        assert(canonical);
        r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
        if (r < 0)
                goto finish;

        /* Return the precise spelling and uppercasing and CNAME target reported by the server */
        r = sd_bus_message_append(
                        reply, "st",
                        normalized,
                        dns_query_reply_flags_make(q));
        if (r < 0)
                goto finish;

        q->bus_request = sd_bus_message_unref(q->bus_request);
        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send hostname reply: %m");
                (void) reply_method_errnof(q, r, NULL);
        }
}

static int validate_and_mangle_flags(
                const char *name,
                uint64_t *flags,
                uint64_t ok,
                sd_bus_error *error) {

        assert(flags);

        /* Checks that the client supplied interface index and flags parameter actually are valid and make
         * sense in our method call context. Specifically:
         *
         * 1. Checks that the interface index is either 0 (meaning *all* interfaces) or positive
         *
         * 2. Only the protocols flags and a bunch of NO_XYZ flags are set, at most. Plus additional flags
         *    specific to our method, passed in the "ok" parameter.
         *
         * 3. If zero protocol flags are specified it is automatically turned into *all* protocols. This way
         *    clients can simply pass 0 as flags and all will work as it should. They can also use this so
         *    that clients don't have to know all the protocols resolved implements, but can just specify 0
         *    to mean "all supported protocols".
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
                       ok))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags parameter");

        if ((*flags & SD_RESOLVED_PROTOCOLS_ALL) == 0) /* If no protocol is enabled, enable all */
                *flags |= SD_RESOLVED_PROTOCOLS_ALL;

        /* Imply SD_RESOLVED_NO_SEARCH if permitted and name is dot suffixed. */
        if (name && FLAGS_SET(ok, SD_RESOLVED_NO_SEARCH) && dns_name_dot_suffixed(name) > 0)
                *flags |= SD_RESOLVED_NO_SEARCH;

        return 0;
}

static int parse_as_address(sd_bus_message *m, int ifindex, const char *hostname, int family, uint64_t flags) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *canonical = NULL;
        union in_addr_union parsed;
        int r, ff, parsed_ifindex = 0;

        /* Check if the hostname is actually already an IP address formatted as string. In that case just parse it,
         * let's not attempt to look it up. */

        r = in_addr_ifindex_from_string_auto(hostname, &ff, &parsed, &parsed_ifindex);
        if (r < 0) /* not an address */
                return 0;

        if (family != AF_UNSPEC && ff != family)
                return sd_bus_reply_method_errorf(m, BUS_ERROR_NO_SUCH_RR, "The specified address is not of the requested family.");
        if (ifindex > 0 && parsed_ifindex > 0 && parsed_ifindex != ifindex)
                return sd_bus_reply_method_errorf(m, BUS_ERROR_NO_SUCH_RR, "The specified address interface index does not match requested interface.");

        if (parsed_ifindex > 0)
                ifindex = parsed_ifindex;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'r', "iiay");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "ii", ifindex, ff);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', &parsed, FAMILY_ADDRESS_SIZE(ff));
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        /* When an IP address is specified we just return it as canonical name, in order to avoid a DNS
         * look-up. However, we reformat it to make sure it's in a truly canonical form (i.e. on IPv6 the inner
         * omissions are always done the same way). */
        r = in_addr_ifindex_to_string(ff, &parsed, ifindex, &canonical);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "st", canonical,
                                  SD_RESOLVED_FLAGS_MAKE(dns_synthesize_protocol(flags), ff, true, true) |
                                  SD_RESOLVED_SYNTHETIC);
        if (r < 0)
                return r;

        return sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
}

void bus_client_log(sd_bus_message *m, const char *what) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        const char *comm = NULL;
        uid_t uid = UID_INVALID;
        pid_t pid = 0;
        int r;

        assert(m);
        assert(what);

        if (!DEBUG_LOGGING)
                return;

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_AUGMENT, &creds);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to query client credentials, ignoring: %m");

        (void) sd_bus_creds_get_uid(creds, &uid);
        (void) sd_bus_creds_get_pid(creds, &pid);
        (void) sd_bus_creds_get_comm(creds, &comm);

        log_debug("D-Bus %s request from client PID " PID_FMT " (%s) with UID " UID_FMT,
                  what, pid, strna(comm), uid);
}

static int bus_method_resolve_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *hostname;
        int family, ifindex;
        uint64_t flags;
        int r;

        assert(message);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isit", &ifindex, &hostname, &family, &flags);
        if (r < 0)
                return r;

        if (ifindex < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        r = validate_and_mangle_flags(hostname, &flags, SD_RESOLVED_NO_SEARCH, error);
        if (r < 0)
                return r;

        r = parse_as_address(message, ifindex, hostname, family, flags);
        if (r != 0)
                return r;

        r = dns_name_is_valid(hostname);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid hostname '%s'", hostname);

        r = dns_question_new_address(&question_utf8, family, hostname, false);
        if (r < 0)
                return r;

        r = dns_question_new_address(&question_idna, family, hostname, true);
        if (r < 0 && r != -EALREADY)
                return r;

        bus_client_log(message, "hostname resolution");

        r = dns_query_new(m, &q, question_utf8, question_idna ?: question_utf8, NULL, ifindex, flags);
        if (r < 0)
                return r;

        q->bus_request = sd_bus_message_ref(message);
        q->request_family = family;
        q->complete = bus_method_resolve_hostname_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                return r;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static void bus_method_resolve_address_complete(DnsQuery *query) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        unsigned added = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = reply_method_errorf(q, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        r = sd_bus_message_new_method_return(q->bus_request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(is)");
        if (r < 0)
                goto finish;

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

                r = sd_bus_message_append(reply, "(is)", ifindex, normalized);
                if (r < 0)
                        goto finish;

                added++;
        }

        if (added <= 0) {
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_RR,
                                        "Address %s does not have any RR of requested type",
                                        IN_ADDR_TO_STRING(q->request_family, &q->request_address));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", dns_query_reply_flags_make(q));
        if (r < 0)
                goto finish;

        q->bus_request = sd_bus_message_unref(q->bus_request);
        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send address reply: %m");
                (void) reply_method_errnof(q, r, NULL);
        }
}

static int bus_method_resolve_address(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m = ASSERT_PTR(userdata);
        union in_addr_union a;
        int family, ifindex;
        uint64_t flags;
        int r;

        assert(message);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "i", &ifindex);
        if (r < 0)
                return r;

        r = bus_message_read_in_addr_auto(message, error, &family, &a);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "t", &flags);
        if (r < 0)
                return r;

        if (ifindex < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        r = validate_and_mangle_flags(NULL, &flags, 0, error);
        if (r < 0)
                return r;

        r = dns_question_new_reverse(&question, family, &a);
        if (r < 0)
                return r;

        bus_client_log(message, "address resolution");

        r = dns_query_new(m, &q, question, question, NULL, ifindex, flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->bus_request = sd_bus_message_ref(message);
        q->request_family = family;
        q->request_address = a;
        q->complete = bus_method_resolve_address_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                return r;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int bus_message_append_rr(sd_bus_message *m, DnsResourceRecord *rr, int ifindex) {
        int r;

        assert(m);
        assert(rr);

        r = sd_bus_message_open_container(m, 'r', "iqqay");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "iqq",
                                  ifindex,
                                  rr->key->class,
                                  rr->key->type);
        if (r < 0)
                return r;

        r = dns_resource_record_to_wire_format(rr, false);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(m, 'y', rr->wire_format, rr->wire_format_size);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(m);
}

static void bus_method_resolve_record_complete(DnsQuery *query) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsResourceRecord *rr;
        DnsQuestion *question;
        unsigned added = 0;
        int ifindex;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = reply_method_errorf(q, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_CNAME) {
                /* This was a cname, and the query was restarted. */
                TAKE_PTR(q);
                return;
        }

        r = sd_bus_message_new_method_return(q->bus_request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(iqqay)");
        if (r < 0)
                goto finish;

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = bus_message_append_rr(reply, rr, ifindex);
                if (r < 0)
                        goto finish;

                added++;
        }

        if (added <= 0) {
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_RR, "Name '%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", dns_query_reply_flags_make(q));
        if (r < 0)
                goto finish;

        q->bus_request = sd_bus_message_unref(q->bus_request);
        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send record reply: %m");
                (void) reply_method_errnof(q, r, NULL);
        }
}

static int bus_method_resolve_record(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uint16_t class, type;
        const char *name;
        int r, ifindex;
        uint64_t flags;

        assert(message);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isqqt", &ifindex, &name, &class, &type, &flags);
        if (r < 0)
                return r;

        if (ifindex < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        r = dns_name_is_valid(name);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid name '%s'", name);

        if (!dns_type_is_valid_query(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified resource record type %" PRIu16 " may not be used in a query.", type);
        if (dns_type_is_zone_transfer(type))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Zone transfers not permitted via this programming interface.");
        if (dns_type_is_obsolete(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Specified DNS resource record type %" PRIu16 " is obsolete.", type);

        r = validate_and_mangle_flags(name, &flags, 0, error);
        if (r < 0)
                return r;

        question = dns_question_new(1);
        if (!question)
                return -ENOMEM;

        key = dns_resource_key_new(class, type, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(question, key, 0);
        if (r < 0)
                return r;

        bus_client_log(message, "resource record resolution");

        /* Setting SD_RESOLVED_CLAMP_TTL: let's request that the TTL is fixed up for locally cached entries,
         * after all we return it in the wire format blob. */
        r = dns_query_new(m, &q, question, question, NULL, ifindex, flags|SD_RESOLVED_NO_SEARCH|SD_RESOLVED_CLAMP_TTL);
        if (r < 0)
                return r;

        q->bus_request = sd_bus_message_ref(message);
        q->complete = bus_method_resolve_record_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                return r;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

static int append_srv(DnsQuery *q, sd_bus_message *reply, DnsResourceRecord *rr) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_free_ char *normalized = NULL;
        int r;

        assert(q);
        assert(reply);
        assert(rr);
        assert(rr->key);

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

        r = sd_bus_message_open_container(reply, 'r', "qqqsa(iiay)s");
        if (r < 0)
                return r;

        r = dns_name_normalize(rr->srv.name, 0, &normalized);
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        reply,
                        "qqqs",
                        rr->srv.priority, rr->srv.weight, rr->srv.port, normalized);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                return r;

        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                LIST_FOREACH(auxiliary_queries, aux, q->auxiliary_queries) {
                        DnsResourceRecord *zz;
                        DnsQuestion *question;
                        int ifindex;

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

                        DNS_ANSWER_FOREACH_IFINDEX(zz, ifindex, aux->answer) {

                                r = dns_question_matches_rr(question, zz, NULL);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                r = append_address(reply, zz, ifindex);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        if (canonical) {
                normalized = mfree(normalized);

                r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
                if (r < 0)
                        return r;
        }

        /* Note that above we appended the hostname as encoded in the
         * SRV, and here the canonical hostname this maps to. */
        r = sd_bus_message_append(reply, "s", normalized);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return 1;
}

static int append_txt(sd_bus_message *reply, DnsResourceRecord *rr) {
        int r;

        assert(reply);
        assert(rr);
        assert(rr->key);

        if (rr->key->type != DNS_TYPE_TXT)
                return 0;

        LIST_FOREACH(items, i, rr->txt.items) {

                if (i->length <= 0)
                        continue;

                r = sd_bus_message_append_array(reply, 'y', i->data, i->length);
                if (r < 0)
                        return r;
        }

        return 1;
}

static void resolve_service_all_complete(DnsQuery *query) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        unsigned added = 0;
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

                                if (bad->auxiliary_result == -ELOOP) {
                                        r = reply_method_errorf(q, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(bad));
                                        goto finish;
                                }

                                assert(bad->auxiliary_result < 0);
                                r = bad->auxiliary_result;
                                goto finish;
                        }

                        r = reply_query_state(bad);
                        goto finish;
                }
        }

        r = sd_bus_message_new_method_return(q->bus_request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(qqqsa(iiay)s)");
        if (r < 0)
                goto finish;

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = append_srv(q, reply, rr);
                if (r < 0)
                        goto finish;
                if (r == 0) /* not an SRV record */
                        continue;

                if (!canonical)
                        canonical = dns_resource_record_ref(rr);

                added++;
        }

        if (added <= 0) {
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "ay");
        if (r < 0)
                goto finish;

        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = append_txt(reply, rr);
                if (r < 0)
                        goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        assert(canonical);
        r = dns_service_split(dns_resource_key_name(canonical->key), &name, &type, &domain);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(
                        reply,
                        "ssst",
                        name, type, domain,
                        dns_query_reply_flags_make(q));
        if (r < 0)
                goto finish;

        q->bus_request = sd_bus_message_unref(q->bus_request);
        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send service reply: %m");
                (void) reply_method_errnof(q, r, NULL);
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

        /* Note that auxiliary queries do not track the original bus
         * client, only the primary request does that. */

        r = dns_query_go(aux);
        if (r < 0)
                return r;

        TAKE_PTR(aux);
        return 1;
}

static void bus_method_resolve_service_complete(DnsQuery *query) {
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        bool has_root_domain = false;
        DnsResourceRecord *rr;
        DnsQuestion *question;
        unsigned found = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname_many(q);
        if (r == -ELOOP) {
                r = reply_method_errorf(q, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
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
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
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
                                goto finish;
                }

                found++;
        }

        if (has_root_domain && found <= 0) {
                /* If there's exactly one SRV RR and it uses the root domain as hostname, then the service is
                 * explicitly not offered on the domain. Report this as a recognizable error. See RFC 2782,
                 * Section "Usage Rules". */
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_SERVICE, "'%s' does not provide the requested service", dns_query_string(q));
                goto finish;
        }

        if (found <= 0) {
                r = reply_method_errorf(q, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        /* Maybe we are already finished? check now... */
        resolve_service_all_complete(TAKE_PTR(q));
        return;

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send service reply: %m");
                (void) reply_method_errnof(q, r, NULL);
        }
}

static int bus_method_resolve_service(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        const char *name, *type, *domain;
        Manager *m = ASSERT_PTR(userdata);
        int family, ifindex;
        uint64_t flags;
        int r;

        assert(message);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isssit", &ifindex, &name, &type, &domain, &family, &flags);
        if (r < 0)
                return r;

        if (ifindex < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        if (isempty(name))
                name = NULL;
        else if (!dns_service_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid service name '%s'", name);

        if (isempty(type))
                type = NULL;
        else if (!dns_srv_type_is_valid(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid SRV service type '%s'", type);

        r = dns_name_is_valid(domain);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid domain '%s'", domain);

        if (name && !type)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Service name cannot be specified without service type.");

        r = validate_and_mangle_flags(name, &flags, SD_RESOLVED_NO_TXT|SD_RESOLVED_NO_ADDRESS, error);
        if (r < 0)
                return r;

        r = dns_question_new_service(&question_utf8, name, type, domain, !(flags & SD_RESOLVED_NO_TXT), false);
        if (r < 0)
                return r;

        r = dns_question_new_service(&question_idna, name, type, domain, !(flags & SD_RESOLVED_NO_TXT), true);
        if (r < 0)
                return r;

        bus_client_log(message, "service resolution");

        r = dns_query_new(m, &q, question_utf8, question_idna, NULL, ifindex, flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->bus_request = sd_bus_message_ref(message);
        q->request_family = family;
        q->complete = bus_method_resolve_service_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                return r;

        r = dns_query_go(q);
        if (r < 0)
                return r;

        TAKE_PTR(q);
        return 1;
}

int bus_dns_server_append(
                sd_bus_message *reply,
                DnsServer *s,
                bool with_ifindex, /* include "ifindex" field */
                bool extended) {   /* also include port number and server name */
        int r;

        assert(reply);

        if (!s) {
                if (with_ifindex) {
                        if (extended)
                                return sd_bus_message_append(reply, "(iiayqs)", 0, AF_UNSPEC, 0, 0, NULL);
                        else
                                return sd_bus_message_append(reply, "(iiay)", 0, AF_UNSPEC, 0);
                } else {
                        if (extended)
                                return sd_bus_message_append(reply, "(iayqs)", AF_UNSPEC, 0, 0, NULL);
                        else
                                return sd_bus_message_append(reply, "(iay)", AF_UNSPEC, 0);
                }
        }

        r = sd_bus_message_open_container(
                        reply,
                        'r',
                        with_ifindex ? (extended ? "iiayqs" : "iiay") :
                                       (extended ? "iayqs" : "iay"));
        if (r < 0)
                return r;

        if (with_ifindex) {
                r = sd_bus_message_append(reply, "i", dns_server_ifindex(s));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_append(reply, "i", s->family);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', &s->address, FAMILY_ADDRESS_SIZE(s->family));
        if (r < 0)
                return r;

        if (extended) {
                r = sd_bus_message_append(reply, "q", s->port);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "s", s->server_name);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_dns_servers_internal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error,
                bool extended) {

        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        int r;

        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', extended ? "(iiayqs)" : "(iiay)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, m->dns_servers) {
                r = bus_dns_server_append(reply, s, true, extended);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links)
                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = bus_dns_server_append(reply, s, true, extended);
                        if (r < 0)
                                return r;
                }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_dns_servers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_dns_servers_internal(bus, path, interface, property, reply, userdata, error, false);
}

static int bus_property_get_dns_servers_ex(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_dns_servers_internal(bus, path, interface, property, reply, userdata, error, true);
}

static int bus_property_get_fallback_dns_servers_internal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error,
                bool extended) {

        DnsServer **f = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', extended ? "(iiayqs)" : "(iiay)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, *f) {
                r = bus_dns_server_append(reply, s, true, extended);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_fallback_dns_servers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_fallback_dns_servers_internal(bus, path, interface, property, reply, userdata, error, false);
}

static int bus_property_get_fallback_dns_servers_ex(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_fallback_dns_servers_internal(bus, path, interface, property, reply, userdata, error, true);
}

static int bus_property_get_current_dns_server_internal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error,
                bool extended) {

        DnsServer *s;

        assert(reply);
        assert(userdata);

        s = *(DnsServer **) userdata;

        return bus_dns_server_append(reply, s, true, extended);
}

static int bus_property_get_current_dns_server(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_current_dns_server_internal(bus, path, interface, property, reply, userdata, error, false);
}

static int bus_property_get_current_dns_server_ex(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        return bus_property_get_current_dns_server_internal(bus, path, interface, property, reply, userdata, error, true);
}

static int bus_property_get_domains(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        int r;

        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(isb)");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, m->search_domains) {
                r = sd_bus_message_append(reply, "(isb)", 0, d->name, d->route_only);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links) {
                LIST_FOREACH(domains, d, l->search_domains) {
                        r = sd_bus_message_append(reply, "(isb)", l->ifindex, d->name, d->route_only);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_transaction_statistics(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(reply);

        return sd_bus_message_append(reply, "(tt)",
                                     (uint64_t) hashmap_size(m->dns_transactions),
                                     (uint64_t) m->n_transactions_total);
}

static int bus_property_get_cache_statistics(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t size = 0, hit = 0, miss = 0;
        Manager *m = ASSERT_PTR(userdata);

        assert(reply);

        LIST_FOREACH(scopes, s, m->dns_scopes) {
                size += dns_cache_size(&s->cache);
                hit += s->cache.n_hit;
                miss += s->cache.n_miss;
        }

        return sd_bus_message_append(reply, "(ttt)", size, hit, miss);
}

static int bus_property_get_dnssec_statistics(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(reply);

        return sd_bus_message_append(reply, "(tttt)",
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_SECURE],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_INSECURE],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_BOGUS],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_INDETERMINATE]);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_dns_stub_listener_mode, dns_stub_listener_mode, DnsStubListenerMode);
static BUS_DEFINE_PROPERTY_GET(bus_property_get_dnssec_supported, "b", Manager, manager_dnssec_supported);
static BUS_DEFINE_PROPERTY_GET2(bus_property_get_dnssec_mode, "s", Manager, manager_get_dnssec_mode, dnssec_mode_to_string);
static BUS_DEFINE_PROPERTY_GET2(bus_property_get_dns_over_tls_mode, "s", Manager, manager_get_dns_over_tls_mode, dns_over_tls_mode_to_string);

static int bus_property_get_resolv_conf_mode(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int r;

        assert(reply);

        r = resolv_conf_mode();
        if (r < 0) {
                log_warning_errno(r, "Failed to test /etc/resolv.conf mode, ignoring: %m");
                return sd_bus_message_append(reply, "s", NULL);
        }

        return sd_bus_message_append(reply, "s", resolv_conf_mode_to_string(r));
}

static int bus_method_reset_statistics(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(message);

        bus_client_log(message, "statistics reset");

        dns_manager_reset_statistics(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int get_any_link(Manager *m, int ifindex, Link **ret, sd_bus_error *error) {
        Link *l;

        assert(m);
        assert(ret);

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!l)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_LINK, "Link %i not known", ifindex);

        *ret = l;
        return 0;
}

static int call_link_method(Manager *m, sd_bus_message *message, sd_bus_message_handler_t handler, sd_bus_error *error) {
        int ifindex, r;
        Link *l;

        assert(m);
        assert(message);
        assert(handler);

        r = bus_message_read_ifindex(message, error, &ifindex);
        if (r < 0)
                return r;

        r = get_any_link(m, ifindex, &l, error);
        if (r < 0)
                return r;

        return handler(message, l, error);
}

static int bus_method_set_link_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_servers, error);
}

static int bus_method_set_link_dns_servers_ex(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_servers_ex, error);
}

static int bus_method_set_link_domains(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_domains, error);
}

static int bus_method_set_link_default_route(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_default_route, error);
}

static int bus_method_set_link_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_llmnr, error);
}

static int bus_method_set_link_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_mdns, error);
}

static int bus_method_set_link_dns_over_tls(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_over_tls, error);
}

static int bus_method_set_link_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dnssec, error);
}

static int bus_method_set_link_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dnssec_negative_trust_anchors, error);
}

static int bus_method_revert_link(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_revert, error);
}

static int bus_method_get_link(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r, ifindex;
        Link *l;

        assert(message);

        r = bus_message_read_ifindex(message, error, &ifindex);
        if (r < 0)
                return r;

        r = get_any_link(m, ifindex, &l, error);
        if (r < 0)
                return r;

        p = link_bus_path(l);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int bus_method_flush_caches(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(message);

        bus_client_log(message, "cache flush");

        manager_flush_caches(m, LOG_INFO);

        return sd_bus_reply_method_return(message, NULL);
}

static int bus_method_reset_server_features(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(message);

        bus_client_log(message, "server feature reset");

        manager_reset_server_features(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int dnssd_service_on_bus_track(sd_bus_track *t, void *userdata) {
        DnssdService *s = ASSERT_PTR(userdata);

        assert(t);

        log_debug("Client of active request vanished, destroying DNS-SD service.");
        dnssd_service_free(s);

        return 0;
}

static int bus_method_register_service(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(dnssd_service_freep) DnssdService *service = NULL;
        _cleanup_(sd_bus_track_unrefp) sd_bus_track *bus_track = NULL;
        const char *name, *name_template, *type;
        _cleanup_free_ char *path = NULL;
        DnssdService *s = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uid_t euid;
        int r;

        assert(message);

        if (m->mdns_support != RESOLVE_SUPPORT_YES)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Support for MulticastDNS is disabled");

        service = new0(DnssdService, 1);
        if (!service)
                return log_oom();

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &euid);
        if (r < 0)
                return r;
        service->originator = euid;

        r = sd_bus_message_read(message, "sssqqq", &name, &name_template, &type,
                                &service->port, &service->priority,
                                &service->weight);
        if (r < 0)
                return r;

        s = hashmap_get(m->dnssd_services, name);
        if (s)
                return sd_bus_error_setf(error, BUS_ERROR_DNSSD_SERVICE_EXISTS, "DNS-SD service '%s' exists already", name);

        if (!dnssd_srv_type_is_valid(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "DNS-SD service type '%s' is invalid", type);

        service->name = strdup(name);
        if (!service->name)
                return log_oom();

        service->name_template = strdup(name_template);
        if (!service->name_template)
                return log_oom();

        service->type = strdup(type);
        if (!service->type)
                return log_oom();

        r = dnssd_render_instance_name(m, service, NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "a{say}");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{say}")) > 0) {
                _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
                DnsTxtItem *last = NULL;

                txt_data = new0(DnssdTxtData, 1);
                if (!txt_data)
                        return log_oom();

                while ((r = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "say")) > 0) {
                        const char *key;
                        const void *value;
                        size_t size;
                        DnsTxtItem *i;

                        r = sd_bus_message_read(message, "s", &key);
                        if (r < 0)
                                return r;

                        if (isempty(key))
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Keys in DNS-SD TXT RRs can't be empty");

                        if (!ascii_is_valid(key))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "TXT key '%s' contains non-ASCII symbols", key);

                        r = sd_bus_message_read_array(message, 'y', &value, &size);
                        if (r < 0)
                                return r;

                        r = dnssd_txt_item_new_from_data(key, value, size, &i);
                        if (r < 0)
                                return r;

                        LIST_INSERT_AFTER(items, txt_data->txts, last, i);
                        last = i;

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return r;

                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (txt_data->txts) {
                        LIST_PREPEND(items, service->txt_data_items, txt_data);
                        txt_data = NULL;
                }
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        if (!service->txt_data_items) {
                _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;

                txt_data = new0(DnssdTxtData, 1);
                if (!txt_data)
                        return log_oom();

                r = dns_txt_item_new_empty(&txt_data->txts);
                if (r < 0)
                        return r;

                LIST_PREPEND(items, service->txt_data_items, txt_data);
                txt_data = NULL;
        }

        r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", service->name, &path);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.resolve1.register-service",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        r = hashmap_ensure_put(&m->dnssd_services, &string_hash_ops, service->name, service);
        if (r < 0)
                return r;

        r = sd_bus_track_new(sd_bus_message_get_bus(message), &bus_track, dnssd_service_on_bus_track, service);
        if (r < 0)
                return r;

        r = sd_bus_track_add_sender(bus_track, message);
        if (r < 0)
                return r;

        service->manager = m;

        service = NULL;

        manager_refresh_rrs(m);

        return sd_bus_reply_method_return(message, "o", path);
}

static int call_dnssd_method(Manager *m, sd_bus_message *message, sd_bus_message_handler_t handler, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        DnssdService *s = NULL;
        const char *path;
        int r;

        assert(m);
        assert(message);
        assert(handler);

        r = sd_bus_message_read(message, "o", &path);
        if (r < 0)
                return r;

        r = sd_bus_path_decode(path, "/org/freedesktop/resolve1/dnssd", &name);
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_DNSSD_SERVICE, "DNS-SD service with object path '%s' does not exist", path);
        if (r < 0)
                return r;

        s = hashmap_get(m->dnssd_services, name);
        if (!s)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_DNSSD_SERVICE, "DNS-SD service '%s' not known", name);

        return handler(message, s, error);
}

static int bus_method_unregister_service(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(message);

        return call_dnssd_method(m, message, bus_dnssd_method_unregister, error);
}

static const sd_bus_vtable resolve_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("LLMNRHostname", "s", NULL, offsetof(Manager, llmnr_hostname), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("LLMNR", "s", bus_property_get_resolve_support, offsetof(Manager, llmnr_support), 0),
        SD_BUS_PROPERTY("MulticastDNS", "s", bus_property_get_resolve_support, offsetof(Manager, mdns_support), 0),
        SD_BUS_PROPERTY("DNSOverTLS", "s", bus_property_get_dns_over_tls_mode, 0, 0),
        SD_BUS_PROPERTY("DNS", "a(iiay)", bus_property_get_dns_servers, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DNSEx", "a(iiayqs)", bus_property_get_dns_servers_ex, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("FallbackDNS", "a(iiay)", bus_property_get_fallback_dns_servers, offsetof(Manager, fallback_dns_servers), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FallbackDNSEx", "a(iiayqs)", bus_property_get_fallback_dns_servers_ex, offsetof(Manager, fallback_dns_servers), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CurrentDNSServer", "(iiay)", bus_property_get_current_dns_server, offsetof(Manager, current_dns_server), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CurrentDNSServerEx", "(iiayqs)", bus_property_get_current_dns_server_ex, offsetof(Manager, current_dns_server), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Domains", "a(isb)", bus_property_get_domains, 0, 0),
        SD_BUS_PROPERTY("TransactionStatistics", "(tt)", bus_property_get_transaction_statistics, 0, 0),
        SD_BUS_PROPERTY("CacheStatistics", "(ttt)", bus_property_get_cache_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSEC", "s", bus_property_get_dnssec_mode, 0, 0),
        SD_BUS_PROPERTY("DNSSECStatistics", "(tttt)", bus_property_get_dnssec_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSECSupported", "b", bus_property_get_dnssec_supported, 0, 0),
        SD_BUS_PROPERTY("DNSSECNegativeTrustAnchors", "as", bus_property_get_string_set, offsetof(Manager, trust_anchor.negative_by_name), 0),
        SD_BUS_PROPERTY("DNSStubListener", "s", bus_property_get_dns_stub_listener_mode, offsetof(Manager, dns_stub_listener_mode), 0),
        SD_BUS_PROPERTY("ResolvConfMode", "s", bus_property_get_resolv_conf_mode, 0, 0),

        SD_BUS_METHOD_WITH_ARGS("ResolveHostname",
                                SD_BUS_ARGS("i", ifindex, "s", name, "i", family, "t", flags),
                                SD_BUS_RESULT("a(iiay)", addresses, "s", canonical, "t", flags),
                                bus_method_resolve_hostname,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResolveAddress",
                                SD_BUS_ARGS("i",  ifindex, "i", family, "ay", address, "t", flags),
                                SD_BUS_RESULT("a(is)", names, "t", flags),
                                bus_method_resolve_address,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResolveRecord",
                                SD_BUS_ARGS("i", ifindex, "s", name, "q", class, "q", type, "t", flags),
                                SD_BUS_RESULT("a(iqqay)", records, "t", flags),
                                bus_method_resolve_record,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResolveService",
                                SD_BUS_ARGS("i", ifindex,
                                            "s", name,
                                            "s", type,
                                            "s", domain,
                                            "i", family,
                                            "t", flags),
                                SD_BUS_RESULT("a(qqqsa(iiay)s)", srv_data,
                                              "aay", txt_data,
                                              "s", canonical_name,
                                              "s", canonical_type,
                                              "s", canonical_domain,
                                              "t", flags),
                                bus_method_resolve_service,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetLink",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_RESULT("o", path),
                                bus_method_get_link,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNS",
                                SD_BUS_ARGS("i", ifindex, "a(iay)", addresses),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_servers,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSEx",
                                SD_BUS_ARGS("i", ifindex, "a(iayqs)", addresses),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_servers_ex,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDomains",
                                SD_BUS_ARGS("i", ifindex, "a(sb)", domains),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_domains,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDefaultRoute",
                                SD_BUS_ARGS("i", ifindex, "b", enable),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_default_route,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkLLMNR",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_llmnr,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkMulticastDNS",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_mdns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSOverTLS",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_over_tls,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSSEC",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dnssec,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSSECNegativeTrustAnchors",
                                SD_BUS_ARGS("i", ifindex, "as", names),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dnssec_negative_trust_anchors,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RevertLink",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_revert_link,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RegisterService",
                                SD_BUS_ARGS("s", name,
                                            "s", name_template,
                                            "s", type,
                                            "q", service_port,
                                            "q", service_priority,
                                            "q", service_weight,
                                            "aa{say}", txt_datas),
                                SD_BUS_RESULT("o", service_path),
                                bus_method_register_service,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnregisterService",
                                SD_BUS_ARGS("o", service_path),
                                SD_BUS_NO_RESULT,
                                bus_method_unregister_service,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResetStatistics",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_RESULT,
                                bus_method_reset_statistics,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("FlushCaches",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_RESULT,
                                bus_method_flush_caches,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResetServerFeatures",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_RESULT,
                                bus_method_reset_server_features,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        .vtables = BUS_VTABLES(resolve_vtable),
        .children = BUS_IMPLEMENTATIONS(&link_object,
                                        &dnssd_object),
};

static int match_prepare_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = ASSERT_PTR(userdata);
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (b)
                return 0;

        log_debug("Coming back from suspend, verifying all RRs...");

        manager_verify_all(m);
        return 0;
}

int manager_connect_bus(Manager *m) {
        int r;

        assert(m);

        if (m->bus)
                return 0;

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-resolve");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.resolve1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = bus_match_signal_async(
                        m->bus,
                        NULL,
                        bus_login_mgr,
                        "PrepareForSleep",
                        match_prepare_for_sleep,
                        NULL,
                        m);
        if (r < 0)
                log_warning_errno(r, "Failed to request match for PrepareForSleep, ignoring: %m");

        return 0;
}

int _manager_send_changed(Manager *manager, const char *property, ...) {
        assert(manager);

        if (sd_bus_is_ready(manager->bus) <= 0)
                return 0;

        char **l = strv_from_stdarg_alloca(property);

        int r = sd_bus_emit_properties_changed_strv(
                        manager->bus,
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        l);
        if (r < 0)
                log_notice_errno(r, "Failed to emit notification about changed property %s: %m", property);
        return r;
}

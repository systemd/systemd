/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "dns-domain.h"
#include "memory-util.h"
#include "missing_capability.h"
#include "resolved-bus.h"
#include "resolved-def.h"
#include "resolved-dns-synthesize.h"
#include "resolved-dnssd-bus.h"
#include "resolved-dnssd.h"
#include "resolved-link-bus.h"
#include "user-util.h"
#include "utf8.h"

BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_resolve_support, resolve_support, ResolveSupport);

static int reply_query_state(DnsQuery *q) {

        switch (q->state) {

        case DNS_TRANSACTION_NO_SERVERS:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_NAME_SERVERS, "No appropriate name servers or networks for name found");

        case DNS_TRANSACTION_TIMEOUT:
                return sd_bus_reply_method_errorf(q->request, SD_BUS_ERROR_TIMEOUT, "Query timed out");

        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                return sd_bus_reply_method_errorf(q->request, SD_BUS_ERROR_TIMEOUT, "All attempts to contact name servers or networks failed");

        case DNS_TRANSACTION_INVALID_REPLY:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_INVALID_REPLY, "Received invalid reply");

        case DNS_TRANSACTION_ERRNO:
                return sd_bus_reply_method_errnof(q->request, q->answer_errno, "Lookup failed due to system error: %m");

        case DNS_TRANSACTION_ABORTED:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_ABORTED, "Query aborted");

        case DNS_TRANSACTION_DNSSEC_FAILED:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_DNSSEC_FAILED, "DNSSEC validation failed: %s",
                                                  dnssec_result_to_string(q->answer_dnssec_result));

        case DNS_TRANSACTION_NO_TRUST_ANCHOR:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_TRUST_ANCHOR, "No suitable trust anchor known");

        case DNS_TRANSACTION_RR_TYPE_UNSUPPORTED:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_RR_TYPE_UNSUPPORTED, "Server does not support requested resource record type");

        case DNS_TRANSACTION_NETWORK_DOWN:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_NETWORK_DOWN, "Network is down");

        case DNS_TRANSACTION_NOT_FOUND:
                /* We return this as NXDOMAIN. This is only generated when a host doesn't implement LLMNR/TCP, and we
                 * thus quickly know that we cannot resolve an in-addr.arpa or ip6.arpa address. */
                return sd_bus_reply_method_errorf(q->request, _BUS_ERROR_DNS "NXDOMAIN", "'%s' not found", dns_query_string(q));

        case DNS_TRANSACTION_RCODE_FAILURE: {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                if (q->answer_rcode == DNS_RCODE_NXDOMAIN)
                        sd_bus_error_setf(&error, _BUS_ERROR_DNS "NXDOMAIN", "'%s' not found", dns_query_string(q));
                else {
                        const char *rc, *n;
                        char p[DECIMAL_STR_MAX(q->answer_rcode)];

                        rc = dns_rcode_to_string(q->answer_rcode);
                        if (!rc) {
                                sprintf(p, "%i", q->answer_rcode);
                                rc = p;
                        }

                        n = strjoina(_BUS_ERROR_DNS, rc);
                        sd_bus_error_setf(&error, n, "Could not resolve '%s', server or network returned error %s", dns_query_string(q), rc);
                }

                return sd_bus_reply_method_error(q->request, &error);
        }

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
        case DNS_TRANSACTION_VALIDATING:
        case DNS_TRANSACTION_SUCCESS:
        default:
                assert_not_reached("Impossible state");
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

static void bus_method_resolve_hostname_complete(DnsQuery *q) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *normalized = NULL;
        DnsResourceRecord *rr;
        unsigned added = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_RESTARTED) /* This was a cname, and the query was restarted. */
                return;

        r = sd_bus_message_new_method_return(q->request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto finish;

        DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                DnsQuestion *question;

                question = dns_query_question_for_protocol(q, q->answer_protocol);

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
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        /* The key names are not necessarily normalized, make sure that they are when we return them to our bus
         * clients. */
        r = dns_name_normalize(dns_resource_key_name(canonical->key), 0, &normalized);
        if (r < 0)
                goto finish;

        /* Return the precise spelling and uppercasing and CNAME target reported by the server */
        assert(canonical);
        r = sd_bus_message_append(
                        reply, "st",
                        normalized,
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, dns_query_fully_authenticated(q)));
        if (r < 0)
                goto finish;

        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send hostname reply: %m");
                sd_bus_reply_method_errno(q->request, r, NULL);
        }

        dns_query_free(q);
}

static int check_ifindex_flags(int ifindex, uint64_t *flags, uint64_t ok, sd_bus_error *error) {
        assert(flags);

        if (ifindex < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        if (*flags & ~(SD_RESOLVED_PROTOCOLS_ALL|SD_RESOLVED_NO_CNAME|ok))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags parameter");

        if ((*flags & SD_RESOLVED_PROTOCOLS_ALL) == 0) /* If no protocol is enabled, enable all */
                *flags |= SD_RESOLVED_PROTOCOLS_ALL;

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
                                  SD_RESOLVED_FLAGS_MAKE(dns_synthesize_protocol(flags), ff, true));
        if (r < 0)
                return r;

        return sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
}

static int bus_method_resolve_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        Manager *m = userdata;
        const char *hostname;
        int family, ifindex;
        uint64_t flags;
        DnsQuery *q;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isit", &ifindex, &hostname, &family, &flags);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        r = check_ifindex_flags(ifindex, &flags, SD_RESOLVED_NO_SEARCH, error);
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

        r = dns_query_new(m, &q, question_utf8, question_idna ?: question_utf8, ifindex, flags);
        if (r < 0)
                return r;

        q->request = sd_bus_message_ref(message);
        q->request_family = family;
        q->complete = bus_method_resolve_hostname_complete;
        q->suppress_unroutable_family = family == AF_UNSPEC;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                goto fail;

        r = dns_query_go(q);
        if (r < 0)
                goto fail;

        return 1;

fail:
        dns_query_free(q);
        return r;
}

static void bus_method_resolve_address_complete(DnsQuery *q) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        unsigned added = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_RESTARTED) /* This was a cname, and the query was restarted. */
                return;

        r = sd_bus_message_new_method_return(q->request, &reply);
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
                _cleanup_free_ char *ip = NULL;

                (void) in_addr_to_string(q->request_family, &q->request_address, &ip);
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR,
                                               "Address '%s' does not have any RR of requested type", strnull(ip));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, dns_query_fully_authenticated(q)));
        if (r < 0)
                goto finish;

        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send address reply: %m");
                sd_bus_reply_method_errno(q->request, r, NULL);
        }

        dns_query_free(q);
}

static int bus_method_resolve_address(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        Manager *m = userdata;
        int family, ifindex;
        uint64_t flags;
        const void *d;
        DnsQuery *q;
        size_t sz;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "ii", &ifindex, &family);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        r = sd_bus_message_read_array(message, 'y', &d, &sz);
        if (r < 0)
                return r;

        if (sz != FAMILY_ADDRESS_SIZE(family))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address size");

        r = sd_bus_message_read(message, "t", &flags);
        if (r < 0)
                return r;

        r = check_ifindex_flags(ifindex, &flags, 0, error);
        if (r < 0)
                return r;

        r = dns_question_new_reverse(&question, family, d);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, question, ifindex, flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->request = sd_bus_message_ref(message);
        q->request_family = family;
        memcpy(&q->request_address, d, sz);
        q->complete = bus_method_resolve_address_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                goto fail;

        r = dns_query_go(q);
        if (r < 0)
                goto fail;

        return 1;

fail:
        dns_query_free(q);
        return r;
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

static void bus_method_resolve_record_complete(DnsQuery *q) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_RESTARTED) /* This was a cname, and the query was restarted. */
                return;

        r = sd_bus_message_new_method_return(q->request, &reply);
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
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "Name '%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, dns_query_fully_authenticated(q)));
        if (r < 0)
                goto finish;

        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send record reply: %m");
                sd_bus_reply_method_errno(q->request, r, NULL);
        }

        dns_query_free(q);
}

static int bus_method_resolve_record(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        Manager *m = userdata;
        uint16_t class, type;
        const char *name;
        int r, ifindex;
        uint64_t flags;
        DnsQuery *q;

        assert(message);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isqqt", &ifindex, &name, &class, &type, &flags);
        if (r < 0)
                return r;

        r = dns_name_is_valid(name);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid name '%s'", name);

        if (!dns_type_is_valid_query(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified resource record type %" PRIu16 " may not be used in a query.", type);
        if (dns_type_is_zone_transer(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Zone transfers not permitted via this programming interface.");
        if (dns_type_is_obsolete(type))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Specified DNS resource record type %" PRIu16 " is obsolete.", type);

        r = check_ifindex_flags(ifindex, &flags, 0, error);
        if (r < 0)
                return r;

        question = dns_question_new(1);
        if (!question)
                return -ENOMEM;

        key = dns_resource_key_new(class, type, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(question, key);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, question, ifindex, flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        /* Let's request that the TTL is fixed up for locally cached entries, after all we return it in the wire format
         * blob */
        q->clamp_ttl = true;

        q->request = sd_bus_message_ref(message);
        q->complete = bus_method_resolve_record_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                goto fail;

        r = dns_query_go(q);
        if (r < 0)
                goto fail;

        return 1;

fail:
        dns_query_free(q);
        return r;
}

static int append_srv(DnsQuery *q, sd_bus_message *reply, DnsResourceRecord *rr) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_free_ char *normalized = NULL;
        DnsQuery *aux;
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
        DnsTxtItem *i;
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

static void resolve_service_all_complete(DnsQuery *q) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *canonical = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        unsigned added = 0;
        DnsQuery *aux;
        int r;

        assert(q);

        if (q->block_all_complete > 0)
                return;

        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                DnsQuery *bad = NULL;
                bool have_success = false;

                LIST_FOREACH(auxiliary_queries, aux, q->auxiliary_queries) {

                        switch (aux->state) {

                        case DNS_TRANSACTION_PENDING:
                                /* If an auxiliary query is still pending, let's wait */
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
                                        r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(bad));
                                        goto finish;
                                }

                                r = bad->auxiliary_result;
                                goto finish;
                        }

                        r = reply_query_state(bad);
                        goto finish;
                }
        }

        r = sd_bus_message_new_method_return(q->request, &reply);
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
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
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
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, dns_query_fully_authenticated(q)));
        if (r < 0)
                goto finish;

        r = sd_bus_send(q->manager->bus, reply, NULL);

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send service reply: %m");
                sd_bus_reply_method_errno(q->request, r, NULL);
        }

        dns_query_free(q);
}

static void resolve_service_hostname_complete(DnsQuery *q) {
        int r;

        assert(q);
        assert(q->auxiliary_for);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                resolve_service_all_complete(q->auxiliary_for);
                return;
        }

        r = dns_query_process_cname(q);
        if (r == DNS_QUERY_RESTARTED) /* This was a cname, and the query was restarted. */
                return;

        /* This auxiliary lookup is finished or failed, let's see if all are finished now. */
        q->auxiliary_result = r;
        resolve_service_all_complete(q->auxiliary_for);
}

static int resolve_service_hostname(DnsQuery *q, DnsResourceRecord *rr, int ifindex) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsQuery *aux;
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

        r = dns_query_new(q->manager, &aux, question, question, ifindex, q->flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        aux->request_family = q->request_family;
        aux->complete = resolve_service_hostname_complete;

        r = dns_query_make_auxiliary(aux, q);
        if (r == -EAGAIN) {
                /* Too many auxiliary lookups? If so, don't complain,
                 * let's just not add this one, we already have more
                 * than enough */

                dns_query_free(aux);
                return 0;
        }
        if (r < 0)
                goto fail;

        /* Note that auxiliary queries do not track the original bus
         * client, only the primary request does that. */

        r = dns_query_go(aux);
        if (r < 0)
                goto fail;

        return 1;

fail:
        dns_query_free(aux);
        return r;
}

static void bus_method_resolve_service_complete(DnsQuery *q) {
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

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_query_string(q));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r == DNS_QUERY_RESTARTED) /* This was a cname, and the query was restarted. */
                return;

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
                /* If there's exactly one SRV RR and it uses
                 * the root domain as host name, then the
                 * service is explicitly not offered on the
                 * domain. Report this as a recognizable
                 * error. See RFC 2782, Section "Usage
                 * Rules". */
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_SERVICE, "'%s' does not provide the requested service", dns_query_string(q));
                goto finish;
        }

        if (found <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        /* Maybe we are already finished? check now... */
        resolve_service_all_complete(q);
        return;

finish:
        if (r < 0) {
                log_error_errno(r, "Failed to send service reply: %m");
                sd_bus_reply_method_errno(q->request, r, NULL);
        }

        dns_query_free(q);
}

static int bus_method_resolve_service(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        const char *name, *type, *domain;
        Manager *m = userdata;
        int family, ifindex;
        uint64_t flags;
        DnsQuery *q;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "isssit", &ifindex, &name, &type, &domain, &family, &flags);
        if (r < 0)
                return r;

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
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Service name cannot be specified without service type.");

        r = check_ifindex_flags(ifindex, &flags, SD_RESOLVED_NO_TXT|SD_RESOLVED_NO_ADDRESS, error);
        if (r < 0)
                return r;

        r = dns_question_new_service(&question_utf8, name, type, domain, !(flags & SD_RESOLVED_NO_TXT), false);
        if (r < 0)
                return r;

        r = dns_question_new_service(&question_idna, name, type, domain, !(flags & SD_RESOLVED_NO_TXT), true);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question_utf8, question_idna, ifindex, flags|SD_RESOLVED_NO_SEARCH);
        if (r < 0)
                return r;

        q->request = sd_bus_message_ref(message);
        q->request_family = family;
        q->complete = bus_method_resolve_service_complete;

        r = dns_query_bus_track(q, message);
        if (r < 0)
                goto fail;

        r = dns_query_go(q);
        if (r < 0)
                goto fail;

        return 1;

fail:
        dns_query_free(q);
        return r;
}

int bus_dns_server_append(sd_bus_message *reply, DnsServer *s, bool with_ifindex) {
        int r;

        assert(reply);

        if (!s) {
                if (with_ifindex)
                        return sd_bus_message_append(reply, "(iiay)", 0, AF_UNSPEC, 0);
                else
                        return sd_bus_message_append(reply, "(iay)", AF_UNSPEC, 0);
        }

        r = sd_bus_message_open_container(reply, 'r', with_ifindex ? "iiay" : "iay");
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

        Manager *m = userdata;
        DnsServer *s;
        Iterator i;
        Link *l;
        int r;

        assert(reply);
        assert(m);

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, m->dns_servers) {
                r = bus_dns_server_append(reply, s, true);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links, i) {
                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = bus_dns_server_append(reply, s, true);
                        if (r < 0)
                                return r;
                }
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

        DnsServer *s, **f = userdata;
        int r;

        assert(reply);
        assert(f);

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, *f) {
                r = bus_dns_server_append(reply, s, true);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_current_dns_server(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        DnsServer *s;

        assert(reply);
        assert(userdata);

        s = *(DnsServer **) userdata;

        return bus_dns_server_append(reply, s, true);
}

static int bus_property_get_domains(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        DnsSearchDomain *d;
        Iterator i;
        Link *l;
        int r;

        assert(reply);
        assert(m);

        r = sd_bus_message_open_container(reply, 'a', "(isb)");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, m->search_domains) {
                r = sd_bus_message_append(reply, "(isb)", 0, d->name, d->route_only);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links, i) {
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

        Manager *m = userdata;

        assert(reply);
        assert(m);

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
        Manager *m = userdata;
        DnsScope *s;

        assert(reply);
        assert(m);

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

        Manager *m = userdata;

        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "(tttt)",
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_SECURE],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_INSECURE],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_BOGUS],
                                     (uint64_t) m->n_dnssec_verdict[DNSSEC_INDETERMINATE]);
}

static int bus_property_get_ntas(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        const char *domain;
        Iterator i;
        int r;

        assert(reply);
        assert(m);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(domain, m->trust_anchor.negative_by_name, i) {
                r = sd_bus_message_append(reply, "s", domain);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_dns_stub_listener_mode, dns_stub_listener_mode, DnsStubListenerMode);
static BUS_DEFINE_PROPERTY_GET(bus_property_get_dnssec_supported, "b", Manager, manager_dnssec_supported);
static BUS_DEFINE_PROPERTY_GET2(bus_property_get_dnssec_mode, "s", Manager, manager_get_dnssec_mode, dnssec_mode_to_string);
static BUS_DEFINE_PROPERTY_GET2(bus_property_get_dns_over_tls_mode, "s", Manager, manager_get_dns_over_tls_mode, dns_over_tls_mode_to_string);

static int bus_method_reset_statistics(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        DnsScope *s;

        assert(message);
        assert(m);

        LIST_FOREACH(scopes, s, m->dns_scopes)
                s->cache.n_hit = s->cache.n_miss = 0;

        m->n_transactions_total = 0;
        zero(m->n_dnssec_verdict);

        return sd_bus_reply_method_return(message, NULL);
}

static int get_any_link(Manager *m, int ifindex, Link **ret, sd_bus_error *error) {
        Link *l;

        assert(m);
        assert(ret);

        if (ifindex <= 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

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

        assert_cc(sizeof(int) == sizeof(int32_t));
        r = sd_bus_message_read(message, "i", &ifindex);
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
        Manager *m = userdata;
        int r, ifindex;
        Link *l;

        assert(message);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));
        r = sd_bus_message_read(message, "i", &ifindex);
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
        Manager *m = userdata;

        assert(message);
        assert(m);

        manager_flush_caches(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int bus_method_reset_server_features(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        assert(message);
        assert(m);

        manager_reset_server_features(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int on_bus_track(sd_bus_track *t, void *userdata) {
        DnssdService *s = userdata;

        assert(t);
        assert(s);

        log_debug("Client of active request vanished, destroying DNS-SD service.");
        dnssd_service_free(s);

        return 0;
}

static int bus_method_register_service(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(dnssd_service_freep) DnssdService *service = NULL;
        _cleanup_(sd_bus_track_unrefp) sd_bus_track *bus_track = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ char *instance_name = NULL;
        Manager *m = userdata;
        DnssdService *s = NULL;
        const char *name;
        const char *name_template;
        const char *type;
        uid_t euid;
        int r;

        assert(message);
        assert(m);

        if (m->mdns_support != RESOLVE_SUPPORT_YES)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Support for MulticastDNS is disabled");

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

        r = dnssd_render_instance_name(service, &instance_name);
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
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Keys in DNS-SD TXT RRs can't be empty");

                        if (!ascii_is_valid(key))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "TXT key '%s' contains non-ASCII symbols", key);

                        r = sd_bus_message_read_array(message, 'y', &value, &size);
                        if (r < 0)
                                return r;

                        r = dnssd_txt_item_new_from_data(key, value, size, &i);
                        if (r < 0)
                                return r;

                        LIST_INSERT_AFTER(items, txt_data->txt, last, i);
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

                if (txt_data->txt) {
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

                r = dns_txt_item_new_empty(&txt_data->txt);
                if (r < 0)
                        return r;

                LIST_PREPEND(items, service->txt_data_items, txt_data);
                txt_data = NULL;
        }

        r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", service->name, &path);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_SYS_ADMIN,
                                    "org.freedesktop.resolve1.register-service",
                                    NULL, false, UID_INVALID,
                                    &m->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        r = hashmap_ensure_allocated(&m->dnssd_services, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(m->dnssd_services, service->name, service);
        if (r < 0)
                return r;

        r = sd_bus_track_new(sd_bus_message_get_bus(message), &bus_track, on_bus_track, service);
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
        Manager *m = userdata;

        assert(message);
        assert(m);

        return call_dnssd_method(m, message, bus_dnssd_method_unregister, error);
}

static const sd_bus_vtable resolve_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("LLMNRHostname", "s", NULL, offsetof(Manager, llmnr_hostname), 0),
        SD_BUS_PROPERTY("LLMNR", "s", bus_property_get_resolve_support, offsetof(Manager, llmnr_support), 0),
        SD_BUS_PROPERTY("MulticastDNS", "s", bus_property_get_resolve_support, offsetof(Manager, mdns_support), 0),
        SD_BUS_PROPERTY("DNSOverTLS", "s", bus_property_get_dns_over_tls_mode, 0, 0),
        SD_BUS_PROPERTY("DNS", "a(iiay)", bus_property_get_dns_servers, 0, 0),
        SD_BUS_PROPERTY("FallbackDNS", "a(iiay)", bus_property_get_fallback_dns_servers, offsetof(Manager, fallback_dns_servers), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CurrentDNSServer", "(iiay)", bus_property_get_current_dns_server, offsetof(Manager, current_dns_server), 0),
        SD_BUS_PROPERTY("Domains", "a(isb)", bus_property_get_domains, 0, 0),
        SD_BUS_PROPERTY("TransactionStatistics", "(tt)", bus_property_get_transaction_statistics, 0, 0),
        SD_BUS_PROPERTY("CacheStatistics", "(ttt)", bus_property_get_cache_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSEC", "s", bus_property_get_dnssec_mode, 0, 0),
        SD_BUS_PROPERTY("DNSSECStatistics", "(tttt)", bus_property_get_dnssec_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSECSupported", "b", bus_property_get_dnssec_supported, 0, 0),
        SD_BUS_PROPERTY("DNSSECNegativeTrustAnchors", "as", bus_property_get_ntas, 0, 0),
        SD_BUS_PROPERTY("DNSStubListener", "s", bus_property_get_dns_stub_listener_mode, offsetof(Manager, dns_stub_listener_mode), 0),

        SD_BUS_METHOD("ResolveHostname", "isit", "a(iiay)st", bus_method_resolve_hostname, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveAddress", "iiayt", "a(is)t", bus_method_resolve_address, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveRecord", "isqqt", "a(iqqay)t", bus_method_resolve_record, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveService", "isssit", "a(qqqsa(iiay)s)aayssst", bus_method_resolve_service, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetStatistics", NULL, NULL, bus_method_reset_statistics, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("FlushCaches", NULL, NULL, bus_method_flush_caches, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetServerFeatures", NULL, NULL, bus_method_reset_server_features, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetLink", "i", "o", bus_method_get_link, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDNS", "ia(iay)", NULL, bus_method_set_link_dns_servers, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDomains", "ia(sb)", NULL, bus_method_set_link_domains, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDefaultRoute", "ib", NULL, bus_method_set_link_default_route, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkLLMNR", "is", NULL, bus_method_set_link_llmnr, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkMulticastDNS", "is", NULL, bus_method_set_link_mdns, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDNSOverTLS", "is", NULL, bus_method_set_link_dns_over_tls, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDNSSEC", "is", NULL, bus_method_set_link_dnssec, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDNSSECNegativeTrustAnchors", "ias", NULL, bus_method_set_link_dnssec_negative_trust_anchors, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RevertLink", "i", NULL, bus_method_revert_link, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD("RegisterService", "sssqqqaa{say}", "o", bus_method_register_service, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnregisterService", "o", NULL, bus_method_unregister_service, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static int match_prepare_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = userdata;
        int b, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse PrepareForSleep signal: %m");
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

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", resolve_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/resolve1/link", "org.freedesktop.resolve1.Link", link_vtable, link_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register link objects: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/resolve1/link", link_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register link enumerator: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/resolve1/dnssd", "org.freedesktop.resolve1.DnssdService", dnssd_vtable, dnssd_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register dnssd objects: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/resolve1/dnssd", dnssd_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register dnssd enumerator: %m");

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.resolve1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "PrepareForSleep",
                        match_prepare_for_sleep,
                        NULL,
                        m);
        if (r < 0)
                log_warning_errno(r, "Failed to request match for PrepareForSleep, ignoring: %m");

        return 0;
}

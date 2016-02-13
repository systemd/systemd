/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "dns-domain.h"
#include "resolved-bus.h"
#include "resolved-def.h"
#include "resolved-dns-synthesize.h"
#include "resolved-link-bus.h"

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

                added ++;
        }

        if (added <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        /* Return the precise spelling and uppercasing and CNAME target reported by the server */
        assert(canonical);
        r = sd_bus_message_append(
                        reply, "st",
                        DNS_RESOURCE_KEY_NAME(canonical->key),
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, q->answer_authenticated));
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
        int r, ff;

        /* Check if the hostname is actually already an IP address formatted as string. In that case just parse it,
         * let's not attempt to look it up. */

        r = in_addr_from_string_auto(hostname, &ff, &parsed);
        if (r < 0) /* not an address */
                return 0;

        if (family != AF_UNSPEC && ff != family)
                return sd_bus_reply_method_errorf(m, BUS_ERROR_NO_SUCH_RR, "The specified address is not of the requested family.");

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
        r = in_addr_to_string(ff, &parsed, &canonical);
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
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question_utf8, question_idna, ifindex, flags);
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
                r = dns_question_matches_rr(question, rr, NULL);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue;

                r = sd_bus_message_append(reply, "(is)", ifindex, rr->ptr.name);
                if (r < 0)
                        goto finish;

                added ++;
        }

        if (added <= 0) {
                _cleanup_free_ char *ip = NULL;

                in_addr_to_string(q->request_family, &q->request_address, &ip);
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "Address '%s' does not have any RR of requested type", strna(ip));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, q->answer_authenticated));
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

                added ++;
        }

        if (added <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "Name '%s' does not have any RR of the requested type", dns_query_string(q));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, q->answer_authenticated));
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

        r = sd_bus_message_append(
                        reply,
                        "qqqs",
                        rr->srv.priority, rr->srv.weight, rr->srv.port, rr->srv.name);
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

        /* Note that above we appended the hostname as encoded in the
         * SRV, and here the canonical hostname this maps to. */
        r = sd_bus_message_append(reply, "s", canonical ? DNS_RESOURCE_KEY_NAME(canonical->key) : rr->srv.name);
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
        r = dns_service_split(DNS_RESOURCE_KEY_NAME(canonical->key), &name, &type, &domain);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(
                        reply,
                        "ssst",
                        name, type, domain,
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family, q->answer_authenticated));
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
                        q->block_all_complete ++;
                        r = resolve_service_hostname(q, rr, ifindex);
                        q->block_all_complete --;

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
        _cleanup_free_ char *n = NULL;
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
        assert(s);

        r = sd_bus_message_open_container(reply, 'r', with_ifindex ? "iiay" : "iay");
        if (r < 0)
                return r;

        if (with_ifindex) {
                r = sd_bus_message_append(reply, "i", s->link ? s->link->ifindex : 0);
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
        unsigned c = 0;
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

                c++;
        }

        HASHMAP_FOREACH(l, m->links, i) {
                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = bus_dns_server_append(reply, s, true);
                        if (r < 0)
                                return r;
                        c++;
                }
        }

        if (c == 0) {
                LIST_FOREACH(servers, s, m->fallback_dns_servers) {
                        r = bus_dns_server_append(reply, s, true);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
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

static int bus_property_get_dnssec_supported(
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

        return sd_bus_message_append(reply, "b", manager_dnssec_supported(m));
}

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

static int get_unmanaged_link(Manager *m, int ifindex, Link **ret, sd_bus_error *error) {
        Link *l;
        int r;

        assert(m);
        assert(ret);

        r = get_any_link(m, ifindex, &l, error);
        if (r < 0)
                return r;

        if (l->flags & IFF_LOOPBACK)
                return sd_bus_error_setf(error, BUS_ERROR_LINK_BUSY, "Link %s is loopback device.", l->name);
        if (l->is_managed)
                return sd_bus_error_setf(error, BUS_ERROR_LINK_BUSY, "Link %s is managed.", l->name);

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

        r = get_unmanaged_link(m, ifindex, &l, error);
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

static int bus_method_set_link_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_llmnr, error);
}

static int bus_method_set_link_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_mdns, error);
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

static const sd_bus_vtable resolve_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("LLMNRHostname", "s", NULL, offsetof(Manager, llmnr_hostname), 0),
        SD_BUS_PROPERTY("DNS", "a(iiay)", bus_property_get_dns_servers, 0, 0),
        SD_BUS_PROPERTY("Domains", "a(isb)", bus_property_get_domains, 0, 0),
        SD_BUS_PROPERTY("TransactionStatistics", "(tt)", bus_property_get_transaction_statistics, 0, 0),
        SD_BUS_PROPERTY("CacheStatistics", "(ttt)", bus_property_get_cache_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSECStatistics", "(tttt)", bus_property_get_dnssec_statistics, 0, 0),
        SD_BUS_PROPERTY("DNSSECSupported", "b", bus_property_get_dnssec_supported, 0, 0),

        SD_BUS_METHOD("ResolveHostname", "isit", "a(iiay)st", bus_method_resolve_hostname, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveAddress", "iiayt", "a(is)t", bus_method_resolve_address, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveRecord", "isqqt", "a(iqqay)t", bus_method_resolve_record, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveService", "isssit", "a(qqqsa(iiay)s)aayssst", bus_method_resolve_service, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetStatistics", NULL, NULL, bus_method_reset_statistics, 0),
        SD_BUS_METHOD("GetLink", "i", "o", bus_method_get_link, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLinkDNS", "ia(iay)", NULL, bus_method_set_link_dns_servers, 0),
        SD_BUS_METHOD("SetLinkDomains", "ia(sb)", NULL, bus_method_set_link_domains, 0),
        SD_BUS_METHOD("SetLinkLLMNR", "is", NULL, bus_method_set_link_llmnr, 0),
        SD_BUS_METHOD("SetLinkMulticastDNS", "is", NULL, bus_method_set_link_mdns, 0),
        SD_BUS_METHOD("SetLinkDNSSEC", "is", NULL, bus_method_set_link_dnssec, 0),
        SD_BUS_METHOD("SetLinkDNSSECNegativeTrustAnchors", "ias", NULL, bus_method_set_link_dnssec_negative_trust_anchors, 0),
        SD_BUS_METHOD("RevertLink", "i", NULL, bus_method_revert_link, 0),

        SD_BUS_VTABLE_END,
};

static int on_bus_retry(sd_event_source *s, usec_t usec, void *userdata) {
        Manager *m = userdata;

        assert(s);
        assert(m);

        m->bus_retry_event_source = sd_event_source_unref(m->bus_retry_event_source);

        manager_connect_bus(m);
        return 0;
}

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

        r = sd_bus_default_system(&m->bus);
        if (r < 0) {
                /* We failed to connect? Yuck, we must be in early
                 * boot. Let's try in 5s again. As soon as we have
                 * kdbus we can stop doing this... */

                log_debug_errno(r, "Failed to connect to bus, trying again in 5s: %m");

                r = sd_event_add_time(m->event, &m->bus_retry_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + 5*USEC_PER_SEC, 0, on_bus_retry, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to install bus reconnect time event: %m");

                (void) sd_event_source_set_description(m->bus_retry_event_source, "bus-retry");
                return 0;
        }

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", resolve_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/resolve1/link", "org.freedesktop.resolve1.Link", link_vtable, link_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register link objects: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/resolve1/link", link_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register link enumerator: %m");

        r = sd_bus_request_name(m->bus, "org.freedesktop.resolve1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to register name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_bus_add_match(m->bus, &m->prepare_for_sleep_slot,
                             "type='signal',"
                             "sender='org.freedesktop.login1',"
                             "interface='org.freedesktop.login1.Manager',"
                             "member='PrepareForSleep',"
                             "path='/org/freedesktop/login1'",
                             match_prepare_for_sleep,
                             m);
        if (r < 0)
                log_error_errno(r, "Failed to add match for PrepareForSleep: %m");

        return 0;
}

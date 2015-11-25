/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

static int reply_query_state(DnsQuery *q) {
        _cleanup_free_ char *ip = NULL;
        const char *name;
        int r;

        if (q->request_address_valid) {
                r = in_addr_to_string(q->request_family, &q->request_address, &ip);
                if (r < 0)
                        return r;

                name = ip;
        } else
                name = dns_question_first_name(q->question);

        switch (q->state) {

        case DNS_TRANSACTION_NO_SERVERS:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_NAME_SERVERS, "No appropriate name servers or networks for name found");

        case DNS_TRANSACTION_TIMEOUT:
                return sd_bus_reply_method_errorf(q->request, SD_BUS_ERROR_TIMEOUT, "Query timed out");

        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                return sd_bus_reply_method_errorf(q->request, SD_BUS_ERROR_TIMEOUT, "All attempts to contact name servers or networks failed");

        case DNS_TRANSACTION_INVALID_REPLY:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_INVALID_REPLY, "Received invalid reply");

        case DNS_TRANSACTION_RESOURCES:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_RESOURCES, "Not enough resources");

        case DNS_TRANSACTION_ABORTED:
                return sd_bus_reply_method_errorf(q->request, BUS_ERROR_ABORTED, "Query aborted");

        case DNS_TRANSACTION_FAILURE: {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (q->answer_rcode == DNS_RCODE_NXDOMAIN)
                        sd_bus_error_setf(&error, _BUS_ERROR_DNS "NXDOMAIN", "'%s' not found", name);
                else {
                        const char *rc, *n;
                        char p[3]; /* the rcode is 4 bits long */

                        rc = dns_rcode_to_string(q->answer_rcode);
                        if (!rc) {
                                sprintf(p, "%i", q->answer_rcode);
                                rc = p;
                        }

                        n = strjoina(_BUS_ERROR_DNS, rc);
                        sd_bus_error_setf(&error, n, "Could not resolve '%s', server or network returned error %s", name, rc);
                }

                return sd_bus_reply_method_error(q->request, &error);
        }

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        unsigned added = 0;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_question_first_name(q->question));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r > 0) /* This was a cname, and the query was restarted. */
                return;

        r = sd_bus_message_new_method_return(q->request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto finish;

        if (q->answer) {
                DnsResourceRecord *rr;
                int ifindex;

                DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
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
        }

        if (added <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_question_first_name(q->question));
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
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family));
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

static int bus_method_resolve_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
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

        r = dns_name_is_valid(hostname);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid hostname '%s'", hostname);

        r = check_ifindex_flags(ifindex, &flags, SD_RESOLVED_NO_SEARCH, error);
        if (r < 0)
                return r;

        r = dns_question_new_address(&question, family, hostname);
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, ifindex, flags);
        if (r < 0)
                return r;

        q->request = sd_bus_message_ref(message);
        q->request_family = family;
        q->complete = bus_method_resolve_hostname_complete;

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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        DnsResourceRecord *rr;
        unsigned added = 0;
        int ifindex, r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        /* We don't process CNAME for PTR lookups. */

        r = sd_bus_message_new_method_return(q->request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(is)");
        if (r < 0)
                goto finish;

        if (q->answer) {
                DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, NULL);
                        if (r < 0)
                                goto finish;
                        if (r == 0)
                                continue;

                        r = sd_bus_message_append(reply, "(is)", ifindex, rr->ptr.name);
                        if (r < 0)
                                goto finish;

                        added ++;
                }
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

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family));
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

        r = dns_query_new(m, &q, question, ifindex, flags|SD_RESOLVED_NO_SEARCH);
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
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        size_t start;
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

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0);
        if (r < 0)
                return r;

        p->refuse_compression = true;

        r = dns_packet_append_rr(p, rr, &start);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(m, 'y', DNS_PACKET_DATA(p) + start, p->size - start);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(m);
}

static void bus_method_resolve_record_complete(DnsQuery *q) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        unsigned added = 0;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_question_first_name(q->question));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r > 0) /* Following a CNAME */
                return;

        r = sd_bus_message_new_method_return(q->request, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "(iqqay)");
        if (r < 0)
                goto finish;

        if (q->answer) {
                DnsResourceRecord *rr;
                int ifindex;

                DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, NULL);
                        if (r < 0)
                                goto finish;
                        if (r == 0)
                                continue;

                        r = bus_message_append_rr(reply, rr, ifindex);
                        if (r < 0)
                                goto finish;

                        added ++;
                }
        }

        if (added <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "Name '%s' does not have any RR of the requested type", dns_question_first_name(q->question));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_append(reply, "t", SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family));
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

        r = dns_query_new(m, &q, question, ifindex, flags|SD_RESOLVED_NO_SEARCH);
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

                        if (aux->state != DNS_TRANSACTION_SUCCESS)
                                continue;
                        if (aux->auxiliary_result != 0)
                                continue;

                        r = dns_name_equal(dns_question_first_name(aux->question), rr->srv.name);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        DNS_ANSWER_FOREACH(zz, aux->answer) {

                                r = dns_question_matches_rr(aux->question, zz, NULL);
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
                        int ifindex;

                        if (aux->state != DNS_TRANSACTION_SUCCESS)
                                continue;
                        if (aux->auxiliary_result != 0)
                                continue;

                        r = dns_name_equal(dns_question_first_name(aux->question), rr->srv.name);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        DNS_ANSWER_FOREACH_IFINDEX(zz, ifindex, aux->answer) {

                                r = dns_question_matches_rr(aux->question, zz, NULL);
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
        DnsQuery *aux;
        unsigned added = false;
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
                                        r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_question_first_name(bad->question));
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

        if (q->answer) {
                DnsResourceRecord *rr;

                DNS_ANSWER_FOREACH(rr, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, NULL);
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
        }

        if (added <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_question_first_name(q->question));
                goto finish;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto finish;

        r = sd_bus_message_open_container(reply, 'a', "ay");
        if (r < 0)
                goto finish;

        if (q->answer) {
                DnsResourceRecord *rr;

                DNS_ANSWER_FOREACH(rr, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, NULL);
                        if (r < 0)
                                goto finish;
                        if (r == 0)
                                continue;

                        r = append_txt(reply, rr);
                        if (r < 0)
                                goto finish;
                }
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
                        SD_RESOLVED_FLAGS_MAKE(q->answer_protocol, q->answer_family));
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
        if (r > 0) /* This was a cname, and the query was restarted. */
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

        r = dns_question_new_address(&question, q->request_family, rr->srv.name);
        if (r < 0)
                return r;

        r = dns_query_new(q->manager, &aux, question, ifindex, q->flags|SD_RESOLVED_NO_SEARCH);
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
        unsigned found = 0;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_SUCCESS) {
                r = reply_query_state(q);
                goto finish;
        }

        r = dns_query_process_cname(q);
        if (r == -ELOOP) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_CNAME_LOOP, "CNAME loop detected, or CNAME resolving disabled on '%s'", dns_question_first_name(q->question));
                goto finish;
        }
        if (r < 0)
                goto finish;
        if (r > 0) /* This was a cname, and the query was restarted. */
                return;

        if (q->answer) {
                DnsResourceRecord *rr;
                int ifindex;

                DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, q->answer) {
                        r = dns_question_matches_rr(q->question, rr, NULL);
                        if (r < 0)
                                goto finish;
                        if (r == 0)
                                continue;

                        if (rr->key->type != DNS_TYPE_SRV)
                                continue;

                        if ((q->flags & SD_RESOLVED_NO_ADDRESS) == 0) {
                                q->block_all_complete ++;
                                r = resolve_service_hostname(q, rr, ifindex);
                                q->block_all_complete --;

                                if (r < 0)
                                        goto finish;
                        }

                        found++;
                }
        }

        if (found <= 0) {
                r = sd_bus_reply_method_errorf(q->request, BUS_ERROR_NO_SUCH_RR, "'%s' does not have any RR of the requested type", dns_question_first_name(q->question));
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
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        const char *name, *type, *domain, *joined;
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
        else {
                if (!dns_service_name_is_valid(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid service name '%s'", name);
        }

        if (isempty(type))
                type = NULL;
        else {
                r = dns_srv_type_verify(type);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid SRV service type '%s'", type);
        }

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

        if (type) {
                /* If the type is specified, we generate the full domain name to look up ourselves */
                r = dns_service_join(name, type, domain, &n);
                if (r < 0)
                        return r;

                joined = n;
        } else
                /* If no type is specified, we assume the domain
                 * contains the full domain name to lookup already */
                joined = domain;

        r = dns_question_new_service(&question, joined, !(flags & SD_RESOLVED_NO_TXT));
        if (r < 0)
                return r;

        r = dns_query_new(m, &q, question, ifindex, flags|SD_RESOLVED_NO_SEARCH);
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

static int append_dns_server(sd_bus_message *reply, DnsServer *s) {
        int r;

        assert(reply);
        assert(s);

        r = sd_bus_message_open_container(reply, 'r', "iiay");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "ii", s->link ? s->link->ifindex : 0, s->family);
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
                r = append_dns_server(reply, s);
                if (r < 0)
                        return r;

                c++;
        }

        HASHMAP_FOREACH(l, m->links, i) {
                LIST_FOREACH(servers, s, l->dns_servers) {
                        r = append_dns_server(reply, s);
                        if (r < 0)
                                return r;
                        c++;
                }
        }

        if (c == 0) {
                LIST_FOREACH(servers, s, m->fallback_dns_servers) {
                        r = append_dns_server(reply, s);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
}

static int bus_property_get_search_domains(
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

        r = sd_bus_message_open_container(reply, 'a', "(is)");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, m->search_domains) {
                r = sd_bus_message_append(reply, "(is)", 0, d->name);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(l, m->links, i) {
                LIST_FOREACH(domains, d, l->search_domains) {
                        r = sd_bus_message_append(reply, "is", l->ifindex, d->name);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
}

static const sd_bus_vtable resolve_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("LLMNRHostname", "s", NULL, offsetof(Manager, llmnr_hostname), 0),
        SD_BUS_PROPERTY("DNSServers", "a(iiay)", bus_property_get_dns_servers, 0, 0),
        SD_BUS_PROPERTY("SearchDomains", "a(is)", bus_property_get_search_domains, 0, 0),

        SD_BUS_METHOD("ResolveHostname", "isit", "a(iiay)st", bus_method_resolve_hostname, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveAddress", "iiayt", "a(is)t", bus_method_resolve_address, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveRecord", "isqqt", "a(iqqay)t", bus_method_resolve_record, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResolveService", "isssit", "a(qqqsa(iiay)s)aayssst", bus_method_resolve_service, SD_BUS_VTABLE_UNPRIVILEGED),
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

                return 0;
        }

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", resolve_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

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

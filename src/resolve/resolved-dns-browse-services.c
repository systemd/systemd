/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "event-util.h"
#include "log.h"
#include "random-util.h"
#include "resolved-dns-browse-services.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-manager.h"
#include "string-table.h"
#include "string-util.h"

typedef enum BrowseServiceUpdateEvent {
        BROWSE_SERVICE_UPDATE_ADDED,
        BROWSE_SERVICE_UPDATE_REMOVED,
        _BROWSE_SERVICE_UPDATE_MAX,
        _BROWSE_SERVICE_UPDATE_INVALID = -EINVAL,
} BrowseServiceUpdateEvent;

static const char * const browse_service_update_event_table[_BROWSE_SERVICE_UPDATE_MAX] = {
        [BROWSE_SERVICE_UPDATE_ADDED]   = "added",
        [BROWSE_SERVICE_UPDATE_REMOVED] = "removed",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(browse_service_update_event, BrowseServiceUpdateEvent);

/* RFC6762 5.2
 * The intervals between successive queries MUST increase by at least a
 * factor of two. When the interval between queries reaches or exceeds
 * 60 minutes, perform subsequent queries at a steady-state rate of one
 * query per hour. */
static usec_t mdns_calculate_next_query_delay(usec_t current_delay) {
        assert(current_delay <= 60 * 60 * USEC_PER_SEC);

        if (current_delay == 0)
                return USEC_PER_SEC;

        return current_delay < 60 * 60 / 2 * USEC_PER_SEC ? current_delay * 2 : 60 * 60 * USEC_PER_SEC;
}

/* RFC 6762 section 5.2
 * The querier should plan to issue a query at 80% of
 * the record lifetime, and then if no answer is received, at 85%, 90%, and 95%. */
static inline int DNS_RECORD_TTL_STATE_TO_PERCENT(DnsRecordTTLState ttl_state) {
        static const int ttl_percent_table[_DNS_RECORD_TTL_STATE_MAX] = {
                [DNS_RECORD_TTL_STATE_80_PERCENT]  = 80,
                [DNS_RECORD_TTL_STATE_85_PERCENT]  = 85,
                [DNS_RECORD_TTL_STATE_90_PERCENT]  = 90,
                [DNS_RECORD_TTL_STATE_95_PERCENT]  = 95,
                [DNS_RECORD_TTL_STATE_100_PERCENT] = 100,
        };
        if (ttl_state < 0 || ttl_state >= _DNS_RECORD_TTL_STATE_MAX)
                return -EINVAL;
        return ttl_percent_table[ttl_state];
}

static usec_t mdns_maintenance_next_time(usec_t until, uint32_t ttl, DnsRecordTTLState ttl_state) {
        assert(ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT);
        assert(ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        int percent = DNS_RECORD_TTL_STATE_TO_PERCENT(ttl_state);
        assert(percent > 0);
        assert(percent <= 100);

        return usec_sub_unsigned(until, (100 - percent) * ttl * USEC_PER_SEC / 100);
}

/* RFC 6762 section 5.2
 * A random variation of 2% of the record TTL should
 * be added to maintenance queries. */
static usec_t mdns_maintenance_jitter(uint32_t ttl) {
        return random_u64_range(2 * ttl * USEC_PER_SEC / 100);
}

static void mdns_maintenance_query_complete(DnsQuery *q) {
        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = q;
        DnssdDiscoveredService *service = NULL;
        int r;

        assert(query);
        assert(query->manager);

        if (query->state != DNS_TRANSACTION_SUCCESS)
                return;

        service = dnssd_discovered_service_ref(query->dnsservice_request);
        if (!service)
                return;

        sb = dns_service_browser_ref(service->service_browser);
        if (!sb)
                return;

        r = mdns_browser_revisit_cache(sb, query->answer_family);
        if (r < 0)
                return (void) log_error_errno(r, "Failed to revisit cache for family %s: %m", af_to_name(query->answer_family));
}

static int mdns_maintenance_query(sd_event_source *s, uint64_t usec, void *userdata) {
        DnssdDiscoveredService *service = ASSERT_PTR(userdata);
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        int r;

        /* Check if the TTL state has reached the maximum value, then revisit
         * cache */
        if (service->rr_ttl_state++ == DNS_RECORD_TTL_STATE_100_PERCENT)
                return mdns_browser_revisit_cache(service->service_browser, service->family);

        /* Create a new DNS query */
        r = dns_query_new(
                        service->service_browser->manager,
                        &q,
                        service->service_browser->question_utf8,
                        service->service_browser->question_idna,
                        /* question_bypass= */ NULL,
                        service->service_browser->ifindex,
                        service->service_browser->flags);
        if (r < 0)
                return log_error_errno(r, "Failed to create mDNS query for maintenance: %m");

        q->complete = mdns_maintenance_query_complete;
        q->varlink_request = sd_varlink_ref(service->service_browser->link);
        q->dnsservice_request = dnssd_discovered_service_ref(service);

        /* Schedule the next maintenance query based on the TTL */
        usec_t next_time = mdns_maintenance_next_time(service->until, service->rr->ttl, service->rr_ttl_state);

        r = event_reset_time(
                        service->service_browser->manager->event,
                        &service->schedule_event,
                        CLOCK_BOOTTIME,
                        next_time,
                        /* accuracy= */ 0,
                        mdns_maintenance_query,
                        service,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to schedule next mDNS maintenance query: %m");

        /* Perform the query */
        r = dns_query_go(q);
        if (r < 0)
                return log_error_errno(r, "Failed to send mDNS maintenance query: %m");

        TAKE_PTR(q);
        return 0;
}

int dns_add_new_service(DnsServiceBrowser *sb, DnsResourceRecord *rr, int owner_family, int ifindex, usec_t until) {
        _cleanup_(dnssd_discovered_service_unrefp) DnssdDiscoveredService *s = NULL;
        int r;

        assert(sb);
        assert(rr);

        s = new(DnssdDiscoveredService, 1);
        if (!s)
                return log_oom();

        usec_t usec = now(CLOCK_BOOTTIME);

        *s = (DnssdDiscoveredService) {
                .n_ref = 1,
                .service_browser = sb,
                .rr = dns_resource_record_copy(rr),
                .family = owner_family,
                .ifindex = ifindex,
                .until = until,
                .query = NULL,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT,
        };

        LIST_PREPEND(dns_services, sb->dns_services, s);

        /* Schedule the first cache maintenance query at 80% of the record's
         * TTL. Subsequent queries issued at 5% increments until 100% of the
         * TTL. RFC 6762 section 5.2. If service is being added after 80% of the
         * TTL has already elapsed, schedule the next query at the next 5%
         * increment. */
        usec_t next_time = 0;
        while (s->rr_ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT &&
               s->rr_ttl_state < _DNS_RECORD_TTL_STATE_MAX) {
                next_time = mdns_maintenance_next_time(s->until, s->rr->ttl, s->rr_ttl_state);
                if (next_time >= usec)
                        break;

                s->rr_ttl_state++;
        }

        if (next_time < usec) {
                /* If next_time is still in the past, the service is being added
                 * after it has already expired. Just schedule a 100%
                 * maintenance query. */
                next_time = usec_add(usec, USEC_PER_SEC);
                s->rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;
        }

        usec_t jitter = mdns_maintenance_jitter(rr->ttl);

        r = sd_event_add_time(
                        sb->manager->event,
                        &s->schedule_event,
                        CLOCK_BOOTTIME,
                        usec_add(next_time, jitter),
                        /* accuracy= */ 0,
                        mdns_maintenance_query,
                        s);
        if (r < 0)
                return log_error_errno(
                                r,
                                "Failed to schedule mDNS maintenance query for DNS service: %m");

        TAKE_PTR(s);
        return 0;
}

void dns_remove_service(DnsServiceBrowser *sb, DnssdDiscoveredService *service) {
        assert(sb);
        assert(service);

        LIST_REMOVE(dns_services, sb->dns_services, service);
        dnssd_discovered_service_unref(service);
}

DnssdDiscoveredService *dns_service_free(DnssdDiscoveredService *service) {
        if (!service)
                return NULL;

        service->schedule_event = sd_event_source_disable_unref(service->schedule_event);

        if (service->query && DNS_TRANSACTION_IS_LIVE(service->query->state))
                dns_query_complete(service->query, DNS_TRANSACTION_ABORTED);

        service->rr = dns_resource_record_unref(service->rr);

        return mfree(service);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnssdDiscoveredService, dnssd_discovered_service, dns_service_free);

int mdns_service_update(DnssdDiscoveredService *service, DnsResourceRecord *rr, usec_t t, usec_t until) {
        assert(service);
        assert(rr);

        service->until = until;
        service->rr->ttl = rr->ttl;

        /* Update the 80% TTL maintenance event based on new record received
         * from the network. RFC 6762 section 5.2  */
        if (service->schedule_event) {
                usec_t next_time = mdns_maintenance_next_time(
                        service->until, service->rr->ttl, DNS_RECORD_TTL_STATE_80_PERCENT);
                usec_t jitter = mdns_maintenance_jitter(service->rr->ttl);

                return sd_event_source_set_time(service->schedule_event, usec_add(next_time, jitter));
        }

        return 0;
}

bool dns_service_match_and_update(DnssdDiscoveredService *services, DnsResourceRecord *rr, int owner_family, usec_t until) {
        usec_t t = now(CLOCK_BOOTTIME);

        /* Check if a discovered service matching the given resource record and owner family exists in the list.
        * If found, update the service's expiration time if the new 'until' is later, unless the TTL is <= 1 (goodbye packet).
        * Return true if a matching service is found, false otherwise. */

        LIST_FOREACH(dns_services, service, services)
                if (dns_resource_record_equal(service->rr, rr) > 0 && service->family == owner_family) {
                        if (rr->ttl <= 1)
                                return true;

                        if (service->until < until)
                                mdns_service_update(service, rr, t, until);

                        return true;
                }

        return false;
}

void dns_browse_services_purge(Manager *m, int family) {
        int r = 0;

        /* Called after caches are flushed.
         * Clear local service records and notify varlink client. */
        if (!m)
                return;

        DnsServiceBrowser *sb;
        HASHMAP_FOREACH(sb, m->dns_service_browsers) {
                r = sd_event_source_set_enabled(sb->schedule_event, SD_EVENT_OFF);
                if (r < 0)
                        log_error_errno(r, "Failed to disable event source for service browser, ignoring: %m");

                if (IN_SET(family, AF_INET, AF_UNSPEC)) {
                     r = mdns_browser_revisit_cache(sb, AF_INET);
                        if (r < 0)
                                log_error_errno(r, "Failed to revisit cache for IPv4, ignoring: %m");
                }

                if (IN_SET(family, AF_INET6, AF_UNSPEC)) {
                        r = mdns_browser_revisit_cache(sb, AF_INET6);
                        if (r < 0)
                                log_error_errno(r, "Failed to revisit cache for IPv6, ignoring: %m");
                }
        }
}

int mdns_manage_services_answer(DnsServiceBrowser *sb, DnsAnswer *answer, int owner_family) {
        DnsAnswerItem *item;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(sb);

        /* Check for new service added */
        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
                int ifindex;

                if (dns_service_match_and_update(sb->dns_services, item->rr, owner_family, item->until))
                        continue;

                r = dns_service_split(item->rr->ptr.name, &name, &type, &domain);
                if (r < 0) {
                        log_error_errno(r, "Failed to split DNS service name: %m");
                        goto finish;
                }

                if (!name) {
                        type = mfree(type);
                        domain = mfree(domain);
                        r = dns_service_split(dns_resource_key_name(item->rr->key), &name, &type, &domain);
                        if (r < 0) {
                                log_error_errno(r, "Failed to split DNS service name (fallback): %m");
                                goto finish;
                        }
                }

                if (!type)
                        continue;

                /* Prefer the per-item ifindex, fall back to the service browser's ifindex */
                ifindex = item->ifindex > 0 ? item->ifindex : sb->ifindex;

                r = dns_add_new_service(sb, item->rr, owner_family, ifindex, item->until);
                if (r < 0) {
                        log_error_errno(r, "Failed to add new DNS service: %m");
                        goto finish;
                }

                log_debug("Add into the list %s, %s, %s, %s, %d",
                          strna(name),
                          strna(type),
                          strna(domain),
                          strna(af_to_ipv4_ipv6(owner_family)),
                          ifindex);

                r = sd_json_buildo(
                                &entry,
                                SD_JSON_BUILD_PAIR_STRING(
                                                "updateFlag",
                                                browse_service_update_event_to_string(
                                                                BROWSE_SERVICE_UPDATE_ADDED)),
                                SD_JSON_BUILD_PAIR_INTEGER("family", owner_family),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !isempty(name), "name", SD_JSON_BUILD_STRING(name)),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !isempty(type), "type", SD_JSON_BUILD_STRING(type)),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !isempty(domain), "domain", SD_JSON_BUILD_STRING(domain)),
                                SD_JSON_BUILD_PAIR_INTEGER("ifindex", ifindex));
                if (r < 0) {
                        log_error_errno(r, "Failed to build JSON for new service: %m");
                        goto finish;
                }

                r = sd_json_variant_append_array(&array, entry);
                if (r < 0) {
                        log_error_errno(r, "Failed to append JSON entry to array: %m");
                        goto finish;
                }
        }

        /* Check for services removed */
        LIST_FOREACH(dns_services, service, sb->dns_services) {
                _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
                int ifindex;

                if (service->family != owner_family)
                        continue;

                if (dns_answer_contains(answer, service->rr))
                        continue;

                r = dns_service_split(service->rr->ptr.name, &name, &type, &domain);
                if (r < 0) {
                        log_error_errno(r, "Failed to split DNS service name from list: %m");
                        goto finish;
                }

                if (!name) {
                        type = mfree(type);
                        domain = mfree(domain);
                        r = dns_service_split(dns_resource_key_name(service->rr->key), &name, &type, &domain);
                        if (r < 0) {
                                log_error_errno(r,
                                                "Failed to split DNS service name (fallback) from list: %m");
                                goto finish;
                        }
                }

                /* Capture ifindex before removing the service */
                ifindex = service->ifindex;

                dns_remove_service(sb, service);

                log_debug("Remove from the list %s, %s, %s, %s, %d",
                          strna(name),
                          strna(type),
                          strna(domain),
                          strna(af_to_ipv4_ipv6(owner_family)),
                          ifindex);

                r = sd_json_buildo(
                                &entry,
                                SD_JSON_BUILD_PAIR_STRING(
                                                "updateFlag",
                                                browse_service_update_event_to_string(
                                                                BROWSE_SERVICE_UPDATE_REMOVED)),
                                SD_JSON_BUILD_PAIR_INTEGER("family", owner_family),
                                SD_JSON_BUILD_PAIR_STRING("name", name ?: ""),
                                SD_JSON_BUILD_PAIR_STRING("type", type ?: ""),
                                SD_JSON_BUILD_PAIR_STRING("domain", domain ?: ""),
                                SD_JSON_BUILD_PAIR_INTEGER("ifindex", ifindex));
                if (r < 0) {
                        log_error_errno(r, "Failed to build JSON for removed service: %m");
                        goto finish;
                }

                r = sd_json_variant_append_array(&array, entry);
                if (r < 0) {
                        log_error_errno(r, "Failed to append JSON entry to array: %m");
                        goto finish;
                }
        }

        if (!sd_json_variant_is_blank_array(array)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *vm = NULL;

                r = sd_json_buildo(&vm, SD_JSON_BUILD_PAIR_VARIANT("browserServiceData", array));
                if (r < 0) {
                        log_error_errno(r,
                                        "Failed to build JSON object for browser service data: %m");
                        goto finish;
                }

                r = sd_varlink_notify(sb->link, vm);
                if (r < 0) {
                        log_error_errno(r, "Failed to notify via varlink: %m");
                        goto finish;
                }
        }

        return 0;

finish:
        return sd_varlink_error_errno(sb->link, r);
}

int mdns_browser_revisit_cache(DnsServiceBrowser *sb, int owner_family) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *lookup_ret_answer = NULL;
        int r;

        assert(sb);
        assert(sb->manager);

        /* ifindex=0 means "all interfaces" */
        if (sb->ifindex == 0) {
                LIST_FOREACH(scopes, scope, sb->manager->dns_scopes) {
                        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

                        if (scope->protocol != DNS_PROTOCOL_MDNS)
                                continue;

                        if (scope->family != owner_family)
                                continue;

                        dns_cache_prune(&scope->cache);

                        r = dns_cache_lookup(
                                        &scope->cache,
                                        sb->key,
                                        sb->flags,
                                        /* ret_rcode= */ NULL,
                                        &answer,
                                        /* ret_full_packet= */ NULL,
                                        /* ret_query_flags= */ NULL,
                                        /* ret_dnssec_result= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to look up DNS cache for service browser key on scope %s: %m",
                                                       dns_scope_ifname(scope) ?: "global");

                        r = mdns_manage_services_answer(sb, answer, owner_family);
                        if (r < 0)
                                return log_error_errno(r, "Failed to manage mDNS services after cache lookup on scope %s: %m",
                                                       dns_scope_ifname(scope) ?: "global");
                }
                return 0;
        }

        /* Single scope for specifically requested interface */
        DnsScope *scope = manager_find_scope_from_protocol(sb->manager, sb->ifindex, DNS_PROTOCOL_MDNS, owner_family);
        if (!scope)
                return 0;

        dns_cache_prune(&scope->cache);

        r = dns_cache_lookup(
                        &scope->cache,
                        sb->key,
                        sb->flags,
                        /* ret_rcode= */ NULL,
                        &lookup_ret_answer,
                        /* ret_full_packet= */ NULL,
                        /* ret_query_flags= */ NULL,
                        /* ret_dnssec_result= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to look up DNS cache for service browser key: %m");

        r = mdns_manage_services_answer(sb, lookup_ret_answer, owner_family);
        if (r < 0)
                return log_error_errno(r, "Failed to manage mDNS services after cache lookup: %m");

        return 0;
}

int mdns_notify_browsers_goodbye(DnsScope *scope) {
        DnsServiceBrowser *sb;
        int r;

        if (!scope)
                return 0;

        HASHMAP_FOREACH(sb, scope->manager->dns_service_browsers) {
                r = mdns_browser_revisit_cache(sb, scope->family);
                if (r < 0)
                        return log_error_errno(
                                        r,
                                        "Failed to revisit cache for service browser with family %d: %m",
                                        scope->family);
        }

        return 0;
}

int mdns_notify_browsers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family) {
        DnsServiceBrowser *sb;
        int r;

        assert(m);

        if (!answer)
                return 0;

        HASHMAP_FOREACH(sb, m->dns_service_browsers) {

                r = dns_answer_match_key(answer, sb->key, NULL);
                if (r < 0)
                        return log_error_errno(
                                        r,
                                        "Failed to match answer key with service browser's key: %m");
                if (r == 0)
                        continue;

                r = mdns_browser_revisit_cache(sb, owner_family);
                if (r < 0)
                        return log_error_errno(r, "Failed to revisit cache for service browser: %m");
        }

        return 0;
}

static void mdns_browse_service_query_complete(DnsQuery *q) {
        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = q;
        int r;

        assert(query);
        assert(query->manager);

        if (query->state != DNS_TRANSACTION_SUCCESS)
                return;

        sb = dns_service_browser_ref(query->service_browser_request);
        if (!sb)
                return;

        r = mdns_browser_revisit_cache(sb, query->answer_family);
        if (r < 0)
                return (void) log_error_errno(r, "Failed to revisit cache for service browser: %m");

        /* When the query is answered from cache, we only get answers for one
         * answer_family i.e. either ipv4 or ipv6. We need to perform another
         * cache lookup for the other answer_family */
        if (query->answer_query_flags == SD_RESOLVED_FROM_CACHE) {
                r = mdns_browser_revisit_cache(sb, query->answer_family == AF_INET ? AF_INET6 : AF_INET);
                if (r < 0)
                        return (void) log_error_errno(r, "Failed to revisit cache for service browser: %m");
        }
}

static int mdns_next_query_schedule(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        int r;

        assert(userdata);
        assert_se(sb = dns_service_browser_ref(userdata));

        /* Enable the answer from the cache for the very first query */
        if (sb->delay == 0)
                SET_FLAG(sb->flags, SD_RESOLVED_NO_CACHE, false);

        /* Set the flag indicating that the query is continuous.
         * RFC 6762 Section 5.2 outlines timing requirements for continuous queries.
         */
        sb->flags |= SD_RESOLVED_QUERY_CONTINUOUS;

        r = dns_query_new(sb->manager, &q, sb->question_utf8, sb->question_idna, NULL, sb->ifindex, sb->flags);
        if (r < 0)
                return log_error_errno(r, "Failed to create new DNS query: %m");

        q->complete = mdns_browse_service_query_complete;
        q->service_browser_request = dns_service_browser_ref(sb);
        q->varlink_request = sd_varlink_ref(sb->link);
        sd_varlink_set_userdata(sb->link, q);

        r = dns_query_go(q);
        if (r < 0)
                return log_error_errno(r, "Failed to send DNS query: %m");

        /* Calculate the next query delay */
        sb->delay = mdns_calculate_next_query_delay(sb->delay);

        SET_FLAG(sb->flags, SD_RESOLVED_NO_CACHE, true);

        r = event_reset_time_relative(
                        sb->manager->event,
                        &sb->schedule_event,
                        CLOCK_BOOTTIME,
                        sb->delay,
                        /* accuracy= */ 0,
                        mdns_next_query_schedule,
                        sb,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to reset event time for next query schedule: %m");

        TAKE_PTR(q);

        return 0;
}

void dns_browse_services_restart(Manager *m) {
        int r;

        if (!(m && m->dns_service_browsers))
                return;

        DnsServiceBrowser *sb;

        HASHMAP_FOREACH(sb, m->dns_service_browsers) {
                sb->delay = 0;

                r = event_reset_time_relative(
                                sb->manager->event,
                                &sb->schedule_event,
                                CLOCK_BOOTTIME,
                                (sb->delay * USEC_PER_SEC),
                                /* accuracy= */ 0,
                                mdns_next_query_schedule,
                                sb,
                                /* priority= */ 0,
                                "mdns-next-query-schedule",
                                /* force_reset= */ true);

                if (r < 0)
                        log_error_errno(r,
                                        "Failed to reset mDNS service subscriber event for service browser: %m");
        }
}

int dns_subscribe_browse_service(
                Manager *m, sd_varlink *link, const char *domain, const char *type, int ifindex, uint64_t flags) {

        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        int r;

        assert(m);
        assert(link);

        if (ifindex < 0)
                return sd_varlink_error_invalid_parameter_name(link, "ifindex");

        if (ifindex == 0)
                log_debug("BrowseServices: browsing all mDNS interfaces");

        if (isempty(type))
                type = NULL;
        else if (!dnssd_srv_type_is_valid(type))
                return sd_varlink_error_invalid_parameter_name(link, "type");

        if (isempty(domain))
                domain = "local";
        else {
                r = dns_name_is_valid(domain);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_varlink_error_invalid_parameter_name(link, "domain");
        }

        r = dns_question_new_service_pointer(
                        &question_utf8, type, domain, /* convert_idna= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to create DNS question for UTF8 version: %m");

        r = dns_question_new_service_pointer(
                        &question_idna, type, domain, /* convert_idna= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to create DNS question for IDNA version: %m");

        sb = new(DnsServiceBrowser, 1);
        if (!sb)
                return log_oom();

        *sb = (DnsServiceBrowser) {
                .n_ref = 1,
                .manager = m,
                .link = sd_varlink_ref(link),
                .question_utf8 = dns_question_ref(question_utf8),
                .question_idna = dns_question_ref(question_idna),
                .key = dns_question_first_key(question_utf8),
                .ifindex = ifindex,
                .flags = flags,
                .delay = 0,
        };

        /* Only mDNS continuous querying is currently supported. See RFC 6762 */
        if (!FLAGS_SET(flags, SD_RESOLVED_MDNS))
                return -EINVAL;

        r = sd_event_add_time_relative(
                        m->event,
                        &sb->schedule_event,
                        CLOCK_BOOTTIME,
                        sb->delay,
                        /* accuracy= */ 0,
                        mdns_next_query_schedule,
                        sb);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&m->dns_service_browsers, NULL, link, sb);
        if (r < 0)
                return log_error_errno(r, "Failed to add service browser to the hashmap: %m");

        TAKE_PTR(sb);

        return 0;
}

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb) {
        DnsQuery *q;

        if (!sb)
                return NULL;

        while (sb->dns_services)
                dns_remove_service(sb, sb->dns_services);

        sb->schedule_event = sd_event_source_disable_unref(sb->schedule_event);

        q = sd_varlink_get_userdata(sb->link);
        if (q && DNS_TRANSACTION_IS_LIVE(q->state))
                dns_query_complete(q, DNS_TRANSACTION_ABORTED);

        sb->question_idna = dns_question_unref(sb->question_idna);
        sb->question_utf8 = dns_question_unref(sb->question_utf8);

        sb->link = sd_varlink_unref(sb->link);

        return mfree(sb);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsServiceBrowser, dns_service_browser, dns_service_browser_free);

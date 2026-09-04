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
#include "time-util.h"

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

/* The maintenance points and the jitter below are fractions of the record's lifetime, but they are
 * anchored at 'until'. Hence take the lifetime to be the part of it that is actually cached, i.e. what
 * is left until 'until': the cache caps entries at CACHE_TTL_MAX_USEC (see calculate_until_valid())
 * while the TTL taken off the network is not capped at all, and a browse subscription may also start
 * in the middle of a record's lifetime. Anchoring fractions of the raw TTL at 'until' would put the
 * maintenance queries in the past or past cache expiry, where they are never sent. The TTL is an upper
 * bound for it, and note the cast: it is a 32-bit value taken directly off the network, and the
 * arithmetic on the percentages below wraps if it is left at 32 bits. */
static usec_t mdns_maintenance_lifetime(const DnsResourceRecord *rr, usec_t until, usec_t usec) {
        assert(rr);

        return MIN((usec_t) rr->ttl * USEC_PER_SEC, usec_sub_unsigned(until, usec));
}

static usec_t mdns_maintenance_next_time(usec_t until, usec_t lifetime, DnsRecordTTLState ttl_state) {
        assert(ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT);
        assert(ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        int percent = DNS_RECORD_TTL_STATE_TO_PERCENT(ttl_state);
        assert(percent > 0);
        assert(percent <= 100);

        return usec_sub_unsigned(until, (100 - percent) * lifetime / 100);
}

/* RFC 6762 section 5.2
 * A random variation of 2% of the record TTL should
 * be added to maintenance queries. */
static usec_t mdns_maintenance_jitter(usec_t lifetime) {
        usec_t range = 2 * lifetime / 100;

        /* Note that random_u64_range(0) returns a value from the full 64-bit range rather than 0. */
        if (range == 0)
                return 0;

        return random_u64_range(range);
}

/* The maintenance points are fractions of the record's remaining cached lifetime, and each dispatch
 * schedules the next one from the time it actually runs at. Requiring every point to be at least this
 * far ahead hence also bounds the interval between two consecutive maintenance queries: a short
 * remaining window would otherwise squeeze all five points into it - with 5 s left they come out 250 ms
 * apart, and the 2% jitter is far too small to spread them - and each of them is a multicast query plus
 * a full reconciliation of the browser's service list, none of which could plausibly be answered and
 * re-cached before that window is over anyway. */
#define MDNS_MAINTENANCE_MIN_GAP_USEC (1 * USEC_PER_SEC)

/* Returns the time the maintenance event for 'service' is to be armed at, scheduling from the TTL state
 * '*ttl_state' and storing the state the returned time belongs to back in it. Maintenance queries are
 * issued at 80% of the record's cached lifetime and at 5% increments from there up to 100%. RFC 6762
 * section 5.2. Points that have already elapsed, or that are less than MDNS_MAINTENANCE_MIN_GAP_USEC
 * ahead, are skipped: arming the source there would only make it fire immediately, or in a rapid burst,
 * and walk the remaining increments without any of the queries having a chance to be answered. Note
 * that the state is not committed to 'service' here, so that callers can do so only once the source is
 * actually armed. */
static usec_t mdns_maintenance_schedule(
                const DnssdDiscoveredService *service,
                usec_t usec,
                DnsRecordTTLState *ttl_state) {

        assert(service);
        assert(ttl_state);
        assert(*ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT);
        assert(*ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        /* An 'until' that is not a proper timestamp leaves no schedule to lay out: for USEC_INFINITY
         * every maintenance point comes out as USEC_INFINITY as well, which is sd-event's "never fires"
         * value and would leave the service with an armed but dead source - and dns_answer_add_extend()
         * and friends do default 'until' to USEC_INFINITY. Likewise, with none of the cached lifetime
         * left all five points coincide with 'until', so there is no query that could still be answered
         * and re-cached in time. Either way just revisit the cache, at 'until' if that is still ahead
         * and promptly otherwise. */
        if (!timestamp_is_set(service->until) || service->lifetime == 0) {
                usec_t prompt = usec_add(usec, USEC_PER_SEC);

                *ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;
                return timestamp_is_set(service->until) ? MAX(service->until, prompt) : prompt;
        }

        usec_t next_time = 0;
        DnsRecordTTLState state = *ttl_state;

        for (; state < _DNS_RECORD_TTL_STATE_MAX; state++) {
                next_time = mdns_maintenance_next_time(service->until, service->lifetime, state);
                if (next_time >= usec_add(usec, MDNS_MAINTENANCE_MIN_GAP_USEC))
                        break;
        }

        if (state == _DNS_RECORD_TTL_STATE_MAX) {
                /* Not one maintenance point is far enough ahead to arm the source for: the cached
                 * lifetime is over, or what is left of it is too short to spread the remaining points
                 * over. Just revisit the cache promptly, and without jitter: no query is sent at that
                 * point anymore. */
                *ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;
                return usec_add(usec, USEC_PER_SEC);
        }

        *ttl_state = state;

        if (state == DNS_RECORD_TTL_STATE_100_PERCENT)
                /* The 100% event only revisits the cache, hence no jitter here either: it would just
                 * push the cleanup of the expired entry further past 'until'. Note that the source is
                 * armed with the default accuracy, so it may still be dispatched up to 250 ms late;
                 * this only avoids adding a multiple of that on top. */
                return next_time;

        return usec_add(next_time, mdns_maintenance_jitter(service->lifetime));
}

static void mdns_maintenance_query_complete(DnsQuery *q) {
        _cleanup_(dnssd_discovered_service_unrefp) DnssdDiscoveredService *service = NULL;
        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = q;
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

static int mdns_maintenance_query(sd_event_source *s, uint64_t usec, void *userdata);

/* Arms the maintenance event source of 'service' for the first maintenance point at or after 'usec',
 * scheduling from the TTL state 'ttl_state', and commits the state that point belongs to. The state is
 * only committed once the source is armed, and the source is left disabled if it is not, so that the
 * time the source is armed at and 'service->rr_ttl_state' cannot disagree. */
int mdns_service_arm_maintenance(DnssdDiscoveredService *service, usec_t usec, DnsRecordTTLState ttl_state) {
        int r;

        assert(service);
        assert(service->service_browser);
        assert(service->service_browser->manager);

        usec_t next_time = mdns_maintenance_schedule(service, usec, &ttl_state);

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
        if (r < 0) {
                /* event_reset_time() sets the time and enables the source before it sets the priority
                 * and the description, i.e. it may fail with the source already armed. Disable it
                 * again, so that it cannot fire for a maintenance point the TTL state knows nothing
                 * about. */
                if (service->schedule_event)
                        (void) sd_event_source_set_enabled(service->schedule_event, SD_EVENT_OFF);

                return log_error_errno(r, "Failed to schedule mDNS maintenance query: %m");
        }

        service->rr_ttl_state = ttl_state;

        return 0;
}

static int mdns_maintenance_query(sd_event_source *s, uint64_t usec, void *userdata) {
        DnssdDiscoveredService *service = ASSERT_PTR(userdata);
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        int r;

        /* Note that no failure below is propagated to the event loop. sd-event logs an error returned
         * by a callback at debug level only and disables the source, so propagating one would both
         * undo the re-arm and hide the failure from the log; report them here instead. */

        /* Check if the TTL state has reached the maximum value, then revisit
         * cache */
        if (service->rr_ttl_state == DNS_RECORD_TTL_STATE_100_PERCENT) {
                r = mdns_browser_revisit_cache(service->service_browser, service->family);
                if (r < 0)
                        log_error_errno(r, "Failed to revisit cache for family %s, ignoring: %m",
                                        af_to_name(service->family));

                return 0;
        }

        /* Advance the schedule first: failing to issue this maintenance query should not also cost the
         * remaining ones. Note that the event may well be dispatched late, hence schedule from the
         * current time rather than from the time the source was armed for. */
        r = mdns_service_arm_maintenance(service, now(CLOCK_BOOTTIME), service->rr_ttl_state + 1);
        if (r < 0)
                return 0;

        /* Create a new DNS query */
        r = dns_query_new(
                        service->service_browser->manager,
                        &q,
                        service->service_browser->question_utf8,
                        service->service_browser->question_idna,
                        /* question_bypass= */ NULL,
                        service->ifindex,
                        service->service_browser->flags);
        if (r < 0) {
                log_error_errno(r, "Failed to create mDNS query for maintenance, ignoring: %m");
                return 0;
        }

        q->complete = mdns_maintenance_query_complete;
        q->service_browser_request = dns_service_browser_ref(service->service_browser);
        q->dnsservice_request = dnssd_discovered_service_ref(service);

        /* Perform the query */
        r = dns_query_go(q);
        if (r < 0) {
                log_error_errno(r, "Failed to send mDNS maintenance query, ignoring: %m");
                return 0;
        }

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
                .lifetime = mdns_maintenance_lifetime(rr, until, usec),
                .query = NULL,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT,
        };
        if (!s->rr)
                return log_oom();

        r = mdns_service_arm_maintenance(s, usec, DNS_RECORD_TTL_STATE_80_PERCENT);
        if (r < 0)
                return r;

        LIST_PREPEND(dns_services, sb->dns_services, s);

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
        service->lifetime = mdns_maintenance_lifetime(rr, until, t);

        /* Update the 80% TTL maintenance event based on new record received
         * from the network. RFC 6762 section 5.2  */
        if (!service->schedule_event)
                return 0;

        /* The record was refreshed, hence the maintenance schedule starts over at 80% of the new
         * lifetime. Note that event_reset_time() re-enables the source, which matters because it is
         * one-shot, i.e. it is left disabled once the 100% query has been issued, and merely setting a
         * new time would not bring it back. */
        return mdns_service_arm_maintenance(service, t, DNS_RECORD_TTL_STATE_80_PERCENT);
}

static int mdns_answer_item_ifindex(DnsServiceBrowser *sb, DnsAnswerItem *item) {
        assert(sb);
        assert(item);

        return item->ifindex > 0 ? item->ifindex : sb->ifindex;
}

static int dns_service_matches(
                DnssdDiscoveredService *service,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex) {

        int r;

        assert(service);
        assert(rr);

        r = dns_resource_record_equal(service->rr, rr);
        if (r <= 0)
                return r;

        return service->family == owner_family && service->ifindex == ifindex;
}

int dns_service_match_and_update(
                DnssdDiscoveredService *services,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until) {

        usec_t t = now(CLOCK_BOOTTIME);
        int r;

        /* Check if a discovered service matching the given resource record, owner family, and ifindex exists
         * in the list. If found, update the service's expiration time if the new 'until' is later, unless the
         * TTL is <= 1 (goodbye packet). Return positive if a matching service is found, zero otherwise. */

        LIST_FOREACH(dns_services, service, services) {
                r = dns_service_matches(service, rr, owner_family, ifindex);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (rr->ttl <= 1)
                        return 1;

                if (service->until < until) {
                        r = mdns_service_update(service, rr, t, until);
                        if (r < 0)
                                /* The service was matched and its expiry updated either way, and the
                                 * failure has already been logged. Do not propagate it: the caller
                                 * treats a negative return as fatal for the whole reconciliation walk
                                 * and answers the browse subscription with an error, which is far out
                                 * of proportion to one service losing its maintenance schedule. */
                                log_debug_errno(r, "Failed to update mDNS maintenance, ignoring: %m");
                }

                return 1;
        }

        return 0;
}

int mdns_answer_contains_service(
                DnsServiceBrowser *sb,
                DnsAnswer *answer,
                DnssdDiscoveredService *service) {

        DnsAnswerItem *item;
        int r;

        assert(sb);
        assert(service);

        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                r = dns_service_matches(
                                service,
                                item->rr,
                                service->family,
                                mdns_answer_item_ifindex(sb, item));
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
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
                int ifindex = mdns_answer_item_ifindex(sb, item);

                r = dns_service_match_and_update(sb->dns_services, item->rr, owner_family, ifindex, item->until);
                if (r < 0) {
                        log_error_errno(r, "Failed to match DNS service: %m");
                        goto finish;
                }
                if (r > 0)
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

                r = mdns_answer_contains_service(sb, answer, service);
                if (r < 0) {
                        log_error_errno(r, "Failed to match DNS answer against service list: %m");
                        goto finish;
                }
                if (r > 0)
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
                                SD_JSON_BUILD_PAIR_STRING("name", strempty(name)),
                                SD_JSON_BUILD_PAIR_STRING("type", strempty(type)),
                                SD_JSON_BUILD_PAIR_STRING("domain", strempty(domain)),
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

        /* ifindex=0 means "all interfaces". Collect the cached answers from
         * every matching mDNS scope into a single combined answer and reconcile
         * once. Reconciling per-scope would be wrong: mdns_manage_services_answer()
         * derives removals by diffing the browser's global service list against
         * the answer it is handed, so a single scope's answer would spuriously
         * "remove" (and then, on the next scope/pass, re-"add") services that are
         * still present on other interfaces — resulting in a continuous
         * added/removed event flap for services seen on more than the current
         * scope. */
        if (sb->ifindex == 0) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *combined = NULL;

                LIST_FOREACH(scopes, scope, sb->manager->dns_scopes) {
                        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
                        DnsAnswerItem *item;

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

                        /* Merge preserving each item's ifindex, flags, rrsig and
                         * cache-expiry 'until'. (dns_answer_extend()/merge() would
                         * reset 'until' to USEC_INFINITY, which would skew the RFC
                         * 6762 §5.2 TTL-maintenance schedule that
                         * mdns_manage_services_answer() derives from item->until.) */
                        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                                r = dns_answer_add_extend_full(&combined, item->rr, item->ifindex,
                                                               item->flags, item->rrsig, item->until);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to merge mDNS cache answer from scope %s: %m",
                                                               dns_scope_ifname(scope) ?: "global");
                        }
                }

                r = mdns_manage_services_answer(sb, combined, owner_family);
                if (r < 0)
                        return log_error_errno(r, "Failed to manage mDNS services after cache lookup for all interfaces: %m");

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

        /* If the varlink connection has a userdata, then that means the previous query has not been finished. */
        if (!sd_varlink_get_userdata(sb->link)) {

                /* Enable the answer from the cache for the very first query */
                if (sb->delay == 0)
                        SET_FLAG(sb->flags, SD_RESOLVED_NO_CACHE, false);

                /* Set the flag indicating that the query is continuous.
                 * RFC 6762 Section 5.2 outlines timing requirements for continuous queries. */
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
        }

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

        /* Refuse multiple requests. */
        if (hashmap_contains(m->dns_service_browsers, link))
                return -EBUSY;

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

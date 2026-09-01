/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-rr.h"
#include "resolved-dns-browse-services.h"
#include "resolved-manager.h"
#include "tests.h"
#include "time-util.h"

static DnsResourceRecord *new_test_service_rr(uint32_t ttl) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local");
        ASSERT_NOT_NULL(rr);

        rr->ttl = ttl;
        rr->ptr.name = strdup("Same Service._http._tcp.local");
        ASSERT_NOT_NULL(rr->ptr.name);

        return rr;
}

TEST(dns_service_match_and_update_goodbye_and_expiry) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .until = 10,
        };

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 100));
        ASSERT_EQ(service.until, (usec_t) 100);

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 75));
        ASSERT_EQ(service.until, (usec_t) 100);

        rr = dns_resource_record_unref(rr);
        ASSERT_NOT_NULL(rr = new_test_service_rr(1));
        service.rr = rr;
        service.until = 10;

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 200));
        ASSERT_EQ(service.until, (usec_t) 10);
}

TEST(dns_service_match_and_update_ifindex) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_OK_ZERO(dns_service_match_and_update(&service, rr, AF_INET, 3, 100));
        ASSERT_EQ(service.until, (usec_t) 0);

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 100));
        ASSERT_EQ(service.until, (usec_t) 100);
}

TEST(dns_service_match_and_update_ifindex_list) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnssdDiscoveredService *services = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service2 = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .until = 10,
        };
        DnssdDiscoveredService service3 = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 3,
                .until = 20,
        };

        LIST_PREPEND(dns_services, services, &service3);
        LIST_PREPEND(dns_services, services, &service2);

        ASSERT_OK_POSITIVE(dns_service_match_and_update(services, rr, AF_INET, 3, 100));
        ASSERT_EQ(service2.until, (usec_t) 10);
        ASSERT_EQ(service3.until, (usec_t) 100);
}

TEST(dns_service_match_and_update_error) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *other = NULL;

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, ".."));
        ASSERT_NOT_NULL(other = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, ".."));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_ERROR(dns_service_match_and_update(&service, other, AF_INET, 2, 100), EINVAL);
}

TEST(mdns_answer_contains_service_ifindex) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer2 = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer3 = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));
        ASSERT_NOT_NULL(answer2 = dns_answer_new(0));
        ASSERT_NOT_NULL(answer3 = dns_answer_new(0));
        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnsServiceBrowser sb_all = {
                .ifindex = 0,
        };
        DnsServiceBrowser sb_scoped = {
                .ifindex = 2,
        };
        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sb_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer2, rr, 0, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sb_scoped, answer2, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer3, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_scoped, answer3, &service));

        sb_scoped.ifindex = 3;
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_scoped, answer2, &service));
}

/* The maintenance schedule is derived from a service, its browser and the browser's manager, hence
 * every test below needs the same three objects wired up around an event loop. */
typedef struct ServiceFixture {
        sd_event *event;
        DnsResourceRecord *rr;
        Manager manager;
        DnsServiceBrowser sb;
        DnssdDiscoveredService service;
} ServiceFixture;

static void service_fixture_done(ServiceFixture *f) {
        assert(f);

        LIST_FOREACH(dns_services, service, f->sb.dns_services)
                dns_remove_service(&f->sb, service);

        f->service.schedule_event = sd_event_source_disable_unref(f->service.schedule_event);
        f->rr = dns_resource_record_unref(f->rr);
        f->event = sd_event_unref(f->event);
}

/* If 'create_source' the service is given a maintenance event source up front, as one that has already
 * been scheduled once has. Its callback is left unset: event_reset_time() does not replace the callback
 * of an existing source, so a test that wants the real one dispatched has to let the schedule create
 * the source itself. */
static void service_fixture_init(ServiceFixture *f, uint32_t ttl, bool create_source) {
        assert(f);

        ASSERT_OK(sd_event_default(&f->event));
        ASSERT_NOT_NULL(f->rr = new_test_service_rr(ttl));

        f->manager.event = f->event;
        f->sb.manager = &f->manager;

        f->service = (DnssdDiscoveredService) {
                .rr = f->rr,
                .service_browser = &f->sb,
                .family = AF_INET,
                .ifindex = 2,
        };

        if (create_source)
                ASSERT_OK(sd_event_add_time(f->event, &f->service.schedule_event,
                                            CLOCK_BOOTTIME, 0, 0, NULL, NULL));
}

/* Arms the maintenance source and returns the time it ended up armed at. */
static usec_t arm_maintenance(DnssdDiscoveredService *service, usec_t usec, DnsRecordTTLState ttl_state) {
        usec_t next;

        ASSERT_OK(mdns_service_arm_maintenance(service, usec, ttl_state));
        ASSERT_OK(sd_event_source_get_time(service->schedule_event, &next));

        return next;
}

/* Updates the service and returns the time its maintenance source ended up armed at. */
static usec_t update_service(ServiceFixture *f, DnsResourceRecord *rr, usec_t t, usec_t until) {
        usec_t next;

        ASSERT_OK(mdns_service_update(&f->service, rr, t, until));
        ASSERT_OK(sd_event_source_get_time(f->service.schedule_event, &next));

        return next;
}

TEST(mdns_service_update_restarts_schedule) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next;
        int enabled;

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ true);
        f.service.until = 10 * USEC_PER_MINUTE;

        /* The event source is one-shot, i.e. it is disabled once the 100% maintenance query has been
         * issued. A refreshed record must restart the schedule at 80% and re-arm the source. */
        ASSERT_OK(sd_event_source_set_enabled(f.service.schedule_event, SD_EVENT_OFF));
        f.service.rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;

        next = update_service(&f, f.rr, /* t= */ 0, 20 * USEC_PER_MINUTE);
        ASSERT_EQ(f.service.until, 20 * USEC_PER_MINUTE);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);

        ASSERT_OK(sd_event_source_get_enabled(f.service.schedule_event, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_ONESHOT);

        /* The source must be armed at 80% of the new lifetime, plus at most 2% of it of jitter. */
        ASSERT_LE(20 * USEC_PER_MINUTE - 24 * USEC_PER_SEC, next);
        ASSERT_LT(next, 20 * USEC_PER_MINUTE - 24 * USEC_PER_SEC + 2400 * USEC_PER_MSEC);
}

TEST(mdns_service_update_reads_new_ttl) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *refreshed = NULL;
        usec_t next;

        service_fixture_init(&f, /* ttl= */ 1000, /* create_source= */ true);
        ASSERT_NOT_NULL(refreshed = new_test_service_rr(100));

        /* dns_resource_record_equal() ignores the TTL, hence the record a service is refreshed with
         * legitimately carries a different one than the copy the service holds, and the new schedule
         * has to be derived from the incoming record. */
        next = update_service(&f, refreshed, /* t= */ 0, 600 * USEC_PER_SEC);
        ASSERT_EQ(f.service.rr->ttl, UINT32_C(100));
        ASSERT_LE(580 * USEC_PER_SEC, next);
        ASSERT_LT(next, 582 * USEC_PER_SEC);
}

TEST(mdns_service_update_large_ttl) {
        /* TTLs are 32-bit values taken off the network. With a TTL of 2^31 s both 20 * ttl and 2 * ttl
         * wrap when evaluated in 32-bit arithmetic: the former makes the 80% point come out as 'until'
         * itself, i.e. the maintenance query is scheduled after the record has already expired, and the
         * latter leaves a zero jitter range, which random_u64_range() answers with a value from the
         * full 64-bit range. Pick an 'until' that leaves the whole TTL to run, so that the lifetime the
         * schedule is derived from is the TTL itself and both bounds below are meaningful. */
        uint32_t ttl = UINT32_C(1) << 31;
        usec_t until = (usec_t) ttl * USEC_PER_SEC;
        usec_t offset = 20 * until / 100;
        usec_t range = 2 * until / 100;

        for (unsigned i = 0; i < 5; i++) {
                _cleanup_(service_fixture_done) ServiceFixture f = {};
                usec_t next;

                service_fixture_init(&f, ttl, /* create_source= */ true);

                next = update_service(&f, f.rr, /* t= */ 0, until);
                ASSERT_LE(until - offset, next);
                ASSERT_LT(next, until - offset + range);
        }
}

TEST(mdns_service_update_short_window) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next;

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ true);

        /* 'until' is capped by the cache while the record's TTL is not, and a service may also be
         * picked up in the middle of a record's lifetime. Here only 5 of the 120 s are left, so the
         * maintenance points have to be laid out over those 5 s: deriving them from the TTL instead
         * would put every one of them in the past and the jitter past 'until', where no query is sent
         * anymore. */
        next = update_service(&f, f.rr, /* t= */ 5 * USEC_PER_SEC, 10 * USEC_PER_SEC);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_LE(9 * USEC_PER_SEC, next);
        ASSERT_LT(next, 9 * USEC_PER_SEC + 100 * USEC_PER_MSEC);
}

TEST(mdns_service_update_expired) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ true);

        /* Nothing is left of the lifetime, so there is no maintenance query to schedule anymore, just a
         * prompt cache revisit, and no jitter on top of it. */
        ASSERT_EQ(update_service(&f, f.rr, /* t= */ 10 * USEC_PER_SEC, 5 * USEC_PER_SEC), 11 * USEC_PER_SEC);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
}

TEST(mdns_service_update_zero_ttl) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};

        service_fixture_init(&f, /* ttl= */ 0, /* create_source= */ true);

        /* A zero TTL leaves no lifetime to spread maintenance points over: all five would coincide with
         * 'until', so go straight to the cache revisit there. In particular do not ask
         * random_u64_range() for a zero range, which yields an arbitrary 64-bit value rather than
         * none. */
        ASSERT_EQ(update_service(&f, f.rr, /* t= */ 0, 10 * USEC_PER_MINUTE), 10 * USEC_PER_MINUTE);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
}

TEST(mdns_service_update_infinite_until) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ true);

        /* USEC_INFINITY is sd-event's "never fires" value, and it is what dns_answer_add_extend() and
         * friends default 'until' to. Arming the source with it would leave the service maintained by a
         * dead timer, with no query and no cache revisit ever dropping it, so fall back to a prompt
         * revisit instead. */
        ASSERT_EQ(update_service(&f, f.rr, 5 * USEC_PER_SEC, USEC_INFINITY), 6 * USEC_PER_SEC);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
}

TEST(mdns_maintenance_schedule_skips_elapsed) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next;

        service_fixture_init(&f, /* ttl= */ 100, /* create_source= */ true);

        /* A lifetime of 100 s ending at 'until' puts the maintenance points at 80, 85, 90, 95 and
         * 100 s, and allows for up to 2 s of jitter. */
        f.service.until = 100 * USEC_PER_SEC;
        f.service.lifetime = 100 * USEC_PER_SEC;

        /* Nothing has elapsed yet: schedule the state we are asked for. */
        next = arm_maintenance(&f.service, /* usec= */ 0, DNS_RECORD_TTL_STATE_90_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_90_PERCENT);
        ASSERT_LE(90 * USEC_PER_SEC, next);
        ASSERT_LT(next, 92 * USEC_PER_SEC);

        /* The 80% point is in the past. Arming the source there would only make it fire immediately, so
         * skip ahead to 85% - and no further, the remaining queries are still to be made. */
        next = arm_maintenance(&f.service, 82 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_LE(85 * USEC_PER_SEC, next);
        ASSERT_LT(next, 87 * USEC_PER_SEC);

        /* A point exactly MDNS_MAINTENANCE_MIN_GAP_USEC ahead is still scheduled, rather than skipped
         * along with the elapsed ones. */
        next = arm_maintenance(&f.service, 89 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_90_PERCENT);
        ASSERT_LE(90 * USEC_PER_SEC, next);
        ASSERT_LT(next, 92 * USEC_PER_SEC);

        /* Three points have elapsed, so the schedule lands on the fourth. */
        next = arm_maintenance(&f.service, 92 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_95_PERCENT);
        ASSERT_LE(95 * USEC_PER_SEC, next);
        ASSERT_LT(next, 97 * USEC_PER_SEC);

        /* Every query point is in the past, only the cache revisit at 'until' is left. It gets no
         * jitter, which would push it past the expiry it is meant to clean up after. */
        next = arm_maintenance(&f.service, 99 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_EQ(next, 100 * USEC_PER_SEC);

        /* 'until' itself has passed, hence revisit the cache promptly instead. */
        next = arm_maintenance(&f.service, 101 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_EQ(next, 102 * USEC_PER_SEC);
}

TEST(mdns_maintenance_schedule_bounds_the_gap) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next;

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ true);

        /* Only 5 s of the record's lifetime are left, which puts the five maintenance points 250 ms
         * apart at 9.00, 9.25, 9.50, 9.75 and 10.00 s, with at most 100 ms of jitter to spread them.
         * Sending four maintenance queries inside 750 ms is pointless - none of them can be answered
         * and re-cached before 'until' - and costs a full reconciliation of the browser's service list
         * each. Points closer than MDNS_MAINTENANCE_MIN_GAP_USEC are therefore skipped like elapsed
         * ones, so that the schedule degrades to fewer queries rather than to a burst of them. */
        f.service.until = 10 * USEC_PER_SEC;
        f.service.lifetime = 5 * USEC_PER_SEC;

        next = arm_maintenance(&f.service, 5 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_LE(9 * USEC_PER_SEC, next);
        ASSERT_LT(next, 9 * USEC_PER_SEC + 100 * USEC_PER_MSEC);

        /* Continuing from the 80% point just dispatched: the 85%, 90% and 95% points are all within a
         * second, hence the next event is the cache revisit at 'until' rather than three more
         * queries. */
        next = arm_maintenance(&f.service, 9 * USEC_PER_SEC, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_EQ(next, 10 * USEC_PER_SEC);

        /* With less than a second of the window left not even the revisit at 'until' is far enough
         * ahead, and the schedule falls through to a prompt one. */
        next = arm_maintenance(&f.service, 9500 * USEC_PER_MSEC, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_EQ(next, 10500 * USEC_PER_MSEC);
}

TEST(dns_add_new_service_schedules_maintenance) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next, until;

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ false);

        /* A service may be picked up anywhere in a record's cached lifetime, hence the schedule of a
         * newly added service is bounded by what is left of it rather than derived from the raw TTL:
         * only 100 of the record's 120 s are still to run here. */
        until = usec_add(now(CLOCK_BOOTTIME), 100 * USEC_PER_SEC);

        ASSERT_OK(dns_add_new_service(&f.sb, f.rr, AF_INET, 2, until));
        ASSERT_NOT_NULL(f.sb.dns_services);

        DnssdDiscoveredService *s = f.sb.dns_services;
        ASSERT_EQ(s->until, until);
        ASSERT_LE(s->lifetime, 100 * USEC_PER_SEC);
        ASSERT_GT(s->lifetime, 99 * USEC_PER_SEC);
        ASSERT_EQ(s->rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);

        /* 80% of at most 100 s before 'until', plus at most 2% of it of jitter. */
        ASSERT_NOT_NULL(s->schedule_event);
        ASSERT_OK(sd_event_source_get_time(s->schedule_event, &next));
        ASSERT_LE(until - 20 * USEC_PER_SEC, next);
        ASSERT_LT(next, until - 17 * USEC_PER_SEC);
}

TEST(mdns_maintenance_query_revisits_cache_at_100_percent) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next, t;
        int enabled;

        service_fixture_init(&f, /* ttl= */ 120, /* create_source= */ false);

        /* No mDNS scope exists for this ifindex, hence the cache revisit the 100% event performs is a
         * no-op here. What is being pinned is that the event does not send a maintenance query and does
         * not schedule another one: it is the last event of the schedule. */
        f.sb.ifindex = 3;

        t = now(CLOCK_BOOTTIME);
        f.service.until = usec_sub_unsigned(t, 10 * USEC_PER_SEC);

        /* Nothing is left of the lifetime, so the schedule collapses to the cache revisit; arm it in
         * the past so that the event loop dispatches it right away. */
        next = arm_maintenance(&f.service, usec_sub_unsigned(t, 2 * USEC_PER_SEC),
                               DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_EQ(next, usec_sub_unsigned(t, USEC_PER_SEC));

        ASSERT_OK_POSITIVE(sd_event_run(f.event, 0));

        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);
        ASSERT_OK(sd_event_source_get_enabled(f.service.schedule_event, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_OFF);
}

TEST(mdns_maintenance_query_advances_schedule) {
        _cleanup_(service_fixture_done) ServiceFixture f = {};
        usec_t next, t;
        int enabled;

        service_fixture_init(&f, /* ttl= */ 100, /* create_source= */ false);

        /* The browser carries no question, hence the maintenance query the event tries to issue fails
         * to be created. That is what is being pinned here: the schedule is advanced before the query
         * is attempted and the failure is swallowed, so that a query that cannot be sent does not also
         * cost the remaining maintenance points - the source is one-shot, and returning an error from
         * the handler would disable it again and take the manager's event loop down with it. */
        t = now(CLOCK_BOOTTIME);
        f.service.until = usec_add(t, 10 * USEC_PER_SEC);
        f.service.lifetime = 100 * USEC_PER_SEC;

        /* The maintenance points sit at 10 and 5 s before 't', at 't' itself, and at 5 and 10 s after
         * it. Arm the source for the 80% point, 10 s in the past, so that the event loop dispatches it
         * right away - 30 s after the time it was scheduled from. */
        next = arm_maintenance(&f.service, usec_sub_unsigned(t, 30 * USEC_PER_SEC),
                               DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_LE(usec_sub_unsigned(t, 10 * USEC_PER_SEC), next);
        ASSERT_LT(next, usec_sub_unsigned(t, 8 * USEC_PER_SEC));

        ASSERT_OK_POSITIVE(sd_event_run(f.event, 0));

        /* Rescheduling from the stale time the source was armed for would put the next point at 85%,
         * 5 s in the past. Scheduling from the current time skips both the 85% and the 90% point and
         * lands on 95%. */
        ASSERT_EQ(f.service.rr_ttl_state, DNS_RECORD_TTL_STATE_95_PERCENT);
        ASSERT_OK(sd_event_source_get_time(f.service.schedule_event, &next));
        ASSERT_LE(usec_add(t, 5 * USEC_PER_SEC), next);
        ASSERT_LT(next, usec_add(t, 7 * USEC_PER_SEC));

        /* And the source is still armed, rather than left disabled by the failed query. */
        ASSERT_OK(sd_event_source_get_enabled(f.service.schedule_event, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_ONESHOT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (c) 2022 Koninklijke Philips N.V. */

#pragma once
#include "resolved-manager.h"
#include "resolved-varlink.h"
#include "varlink.h"

typedef struct mDnsServiceSubscriber mDnsServiceSubscriber;
typedef struct mDnsServices mDnsServices;
typedef struct mDnsGoodbyeParams mDnsGoodbyeParams;

typedef int (*query_schedul_handler)(sd_event_source *s, uint64_t usec, void *userdata);

struct mDnsServices {
        unsigned n_ref;
        DnsResourceRecord *rr;
        int family;
        LIST_FIELDS(mDnsServices, mdns_services);
};

struct mDnsServiceSubscriber {
        unsigned n_ref;
        Manager *m;
        Varlink *link;
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;
        uint64_t flags;
        sd_event_source *schedule_event;
        usec_t delay;
        DnsResourceKey *key;
        int ifindex;
        uint64_t token;
        LIST_HEAD(mDnsServices, mdns_services);
};

struct mDnsGoodbyeParams {
        mDnsServiceSubscriber *ss;
        int owner_family;
};

mDnsServiceSubscriber *mdns_service_subscriber_free(mDnsServiceSubscriber *ss);
void mdns_remove_service(mDnsServiceSubscriber *ss, mDnsServices *service);
mDnsServices *mdns_service_free(mDnsServices *service);
mDnsGoodbyeParams *mdns_goodbye_params_free(mDnsGoodbyeParams *p);

mDnsServiceSubscriber* mdns_service_subscriber_ref(mDnsServiceSubscriber *ss);
mDnsServiceSubscriber* mdns_service_subscriber_unref(mDnsServiceSubscriber *ss);

mDnsServices* mdns_service_ref(mDnsServices *service);
mDnsServices* mdns_service_unref(mDnsServices *service);


DEFINE_TRIVIAL_CLEANUP_FUNC(mDnsServiceSubscriber*, mdns_service_subscriber_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(mDnsServices*, mdns_service_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(mDnsGoodbyeParams*, mdns_goodbye_params_free);

bool mdns_service_contains(mDnsServices *services, DnsResourceRecord *rr, int owner_family);
void mdns_manage_services_answer(mDnsServiceSubscriber *ss, DnsAnswer *answer, int owner_family);
int mdns_add_new_service(mDnsServiceSubscriber *ss, DnsResourceRecord *rr, int owner_family);


void mdns_subscriber_lookup_cache(mDnsServiceSubscriber *ss, int owner_family);
int mdns_subscribe_browse_service(Manager *m,
                Varlink *link,
                const char *domain,
                const char * name,
                const char * type,
                const char * ifname,
                const uint64_t token);
int mdns_unsubscribe_browse_service(Manager *m, Varlink *link, uint64_t token);
void mdns_notify_subscribers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family, bool has_goodbye);

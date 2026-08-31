/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)
/* RFC 6762 section 10.1: the records of a goodbye packet expire one second after it was received.
 * This bounds how far ahead the goodbye timer looks: both the arm on receipt and the callback's
 * re-arm only take on an expiry that falls within it. */
#define MDNS_GOODBYE_DELAY (1 * USEC_PER_SEC)
/* And the shortest interval between two goodbye passes. Each pass prunes the cache and reconciles
 * every browse subscriber against it, and the records driving it arrive as unauthenticated
 * multicast: without a floor, goodbyes for records expiring microseconds apart would buy a pass
 * each. The floor delays a removal by at most this much, on top of the accuracy the timer is armed
 * with (sd-event's 250ms default) -- neither compounds, and both are well inside the window. */
#define MDNS_GOODBYE_MIN_INTERVAL (MDNS_GOODBYE_DELAY / 4)

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

/* Exposed for testing only. */
bool mdns_answer_rewrite_goodbye_ttls(DnsAnswer *answer);
void mdns_goodbye_arm_on_receipt(DnsScope *scope);
/* 's' must be the scope's own goodbye source: the handler may release it, so a direct caller has to
 * hold a reference of its own to keep it alive across the call. */
int mdns_goodbye_callback(sd_event_source *s, uint64_t usec, void *userdata);

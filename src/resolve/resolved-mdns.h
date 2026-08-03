/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)
/* RFC 6762 section 10.1: the records of a goodbye packet expire one second after it was received.
 * This bounds how far ahead the goodbye timer looks: both the arm on receipt and the callback's
 * re-arm only take on an expiry that falls within it. */
#define MDNS_GOODBYE_DELAY (1 * USEC_PER_SEC)

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

/* Exposed for testing only. */
void mdns_goodbye_arm_on_receipt(DnsScope *scope);
int mdns_goodbye_callback(sd_event_source *s, uint64_t usec, void *userdata);

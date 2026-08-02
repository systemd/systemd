/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)
/* RFC 6762 section 10.1: the records of a goodbye packet expire one second after it was received.
 * This bounds how far ahead the goodbye timer looks: both the arm on receipt and the callback's
 * re-arm only take on an expiry that falls within it. */
#define MDNS_GOODBYE_DELAY (1 * USEC_PER_SEC)
/* Lower bound on the interval between two goodbye passes, so a burst of goodbyes cannot drive one
 * prune-and-reconcile pass per record. Delays a removal by at most this much. */
#define MDNS_GOODBYE_MIN_INTERVAL (MDNS_GOODBYE_DELAY / 4)

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

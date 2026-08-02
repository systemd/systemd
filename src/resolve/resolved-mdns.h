/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)
/* RFC 6762 section 10.1: the records of a goodbye packet expire one second after it was received. The
 * timer armed on receipt and the callback's lookahead when it re-arms both use this. */
#define MDNS_GOODBYE_DELAY (1 * USEC_PER_SEC)

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

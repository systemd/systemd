/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)

/* RFC 6762 § 17: "Even when fragmentation is used, a Multicast DNS packet, including IP and UDP
 * headers, MUST NOT exceed 9000 bytes." */
#define MDNS_PACKET_FRAGMENTED_SIZE_MAX 9000U

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

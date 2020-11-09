/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "time-util.h"

/* Input + Output: The various protocols we can use */
#define SD_RESOLVED_DNS             (UINT64_C(1) << 0)
#define SD_RESOLVED_LLMNR_IPV4      (UINT64_C(1) << 1)
#define SD_RESOLVED_LLMNR_IPV6      (UINT64_C(1) << 2)
#define SD_RESOLVED_MDNS_IPV4       (UINT64_C(1) << 3)
#define SD_RESOLVED_MDNS_IPV6       (UINT64_C(1) << 4)

/* Input: Don't follow CNAMEs/DNAMEs */
#define SD_RESOLVED_NO_CNAME        (UINT64_C(1) << 5)

/* Input: When doing service (SRV) resolving, don't resolve associated mDNS-style TXT records */
#define SD_RESOLVED_NO_TXT          (UINT64_C(1) << 6)

/* Input: When doing service (SRV) resolving, don't resolve A/AAA RR for included hostname */
#define SD_RESOLVED_NO_ADDRESS      (UINT64_C(1) << 7)

/* Input: Don't apply search domain logic to request */
#define SD_RESOLVED_NO_SEARCH       (UINT64_C(1) << 8)

/* Output: Result is authenticated */
#define SD_RESOLVED_AUTHENTICATED   (UINT64_C(1) << 9)

#define SD_RESOLVED_LLMNR           (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)
#define SD_RESOLVED_MDNS            (SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6)
#define SD_RESOLVED_PROTOCOLS_ALL   (SD_RESOLVED_MDNS|SD_RESOLVED_LLMNR|SD_RESOLVED_DNS)

#define SD_RESOLVED_QUERY_TIMEOUT_USEC (120 * USEC_PER_SEC)

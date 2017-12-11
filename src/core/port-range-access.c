/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack
  Copyright 2017 Intel Corporation.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "bpf-firewall.h"
#include "extract-word.h"
#include "port-range-access.h"
#include "parse-util.h"
#include "string-util.h"
#include "socket-protocol-list.h"

static int create_series(
                uint16_t range_start,
                uint16_t range_end,
                unsigned char protocol,
                PortRangeAccessItem **list) {
        uint biggest_exp = 1, biggest_block = 0;
        uint numbers = range_end - range_start + 1;
        uint next_candidate, best_candidate;
        uint16_t mask;
        PortRangeAccessItem *a;
        int i, r;

        /*
         * We want to use prefix matching to allow for fast port range
         * processing in kernel. This function finds the biggest prefix that is
         * fully contained within the port range. It then calls itself
         * recursively for the non-covered parts of the range.
         *
         * For example typical ephemeral ports:
         *   32768-61000 -> [ 32768/2 49152/3 57344/5 59392/6 60416/7 60928/10 60992/13 61000/16 ]
         */

        a = new0(PortRangeAccessItem, 1);
        if (!a)
                return -ENOMEM;

        a->protocol = protocol;

        if (range_start == range_end) {
                a->prefixlen = 16;
                a->port = range_start;
                LIST_APPEND(items, *list, a);
                return 0;
        }

        /*
         * Variable numbers is the inclusive range length. Count how many
         * potential prefixes we could fit in the inclusive range. Biggest
         * exponent will be at least 2.
         */

        while (biggest_block <= numbers)
                biggest_block = 1 << biggest_exp++;

        /* Find the largest block that will fit (in prefix sense) into the range. */
        for (i = biggest_exp-2; i >= 0; i--) {

                uint16_t block = 1 << i;

                if ((range_start % block) == 0)
                        next_candidate = range_start;
                else
                        next_candidate = range_start + block - (range_start % block);

                best_candidate = next_candidate;

                mask = ~(0xffff << i);

                if (!((next_candidate | mask) > range_end))
                        break;
        }

        a->prefixlen = 16-i;
        a->port = best_candidate;
        LIST_APPEND(items, *list, a);

        if (best_candidate == range_start) {
                if (!((best_candidate | mask) == range_end)) {
                        /*
                         * There is more address space at the end of the
                         * address range.
                         */
                        r = create_series((best_candidate | mask) + 1, range_end, protocol, list);
                        if (r < 0)
                                return r;
                }
                /* Else we cover the whole range. */
        } else if ((best_candidate | mask) == range_end) {
                /*
                 * There is more address space at the beginning of the
                 * address range.
                 */
                r = create_series(range_start, best_candidate - 1, protocol, list);
                if (r < 0)
                        return r;
        } else {
                /*
                 * There is more address space at both beginning and end of
                 * the address range.
                 */
                r = create_series(range_start, best_candidate - 1, protocol, list);
                if (r < 0)
                        return r;
                r = create_series((best_candidate | mask) + 1, range_end, protocol, list);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_port_range_access(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        /*
         * The port ranges are defined as LPM BPF entries for access speed and
         * memory reasons. Parse the following (space-separated) items:
         *  1. single ports: "80" -> [ 80/16 ]
         *  2. port ranges:  "1000-2000" -> [ 1000/13 1008/12 1024/7 1536/8 1792/9 1920/10 1984/12 2000/16 ]
         *  3. keywords:     "any" -> [ 0/0 ]
         */

        PortRangeAccessItem **list = data;
        const char *p;
        int r;
        char *protocol_sep = NULL;
        unsigned char protocol = 0;

        if (isempty(rvalue)) {
                *list = port_range_access_free_all(*list);
                return 0;
        }

        p = rvalue;

        for (;;) {
                PortRangeAccessItem *a = NULL;
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                protocol_sep = strchr(word, '/');
                if (protocol_sep) {
                        protocol = socket_protocol_from_name(protocol_sep+1);
                        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax, ignoring: %s", rvalue);
                                break;
                        }
                        *protocol_sep = '\0';
                } else {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                if (streq(word, "any")) {
                        /* "any" is a shortcut for 0/0. */

                        a = new0(PortRangeAccessItem, 1);
                        if (!a)
                                return log_oom();

                        a->prefixlen = 0;
                        a->port = 0;
                        a->protocol = protocol;
                        LIST_APPEND(items, *list, a);
                } else {
                        char *sep;

                        /*
                         * Check if this is a range. Range example: "1000-2000".
                         */
                        sep = strchr(word, '-');

                        if (sep) {
                                int len = sep-word;
                                char range_start[len+1];
                                uint16_t port_start, port_end;

                                memcpy(range_start, word, len);
                                range_start[len] = '\0';

                                r = parse_ip_port(range_start, &port_start);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                                        break;
                                }
                                r = parse_ip_port(sep+1, &port_end);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                                        break;
                                }

                                /*
                                 * Calculate the prefix matches for the range if
                                 * it survives a sanity check.
                                 */

                                if (port_start > port_end) {
                                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax, ignoring: %s", rvalue);
                                        break;
                                }

                                r = create_series(port_start, port_end, protocol, list);
                                if (r < 0)
                                        return log_oom();
                        } else {
                                uint16_t port;

                                r = parse_ip_port(word, &port);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                                        break;
                                }

                                a = new0(PortRangeAccessItem, 1);
                                if (!a)
                                        return log_oom();

                                a->prefixlen = 16;
                                a->port = port;
                                a->protocol = protocol;
                                LIST_APPEND(items, *list, a);
                        }
                }
        }

        if (*list) {
                r = bpf_firewall_supported();
                if (r < 0)
                        return r;
                if (r == 0) {
                        static bool warned = false;

                        log_full(warned ? LOG_DEBUG : LOG_WARNING,
                                 "File %s:%u configures an IP firewall (%s=%s), but the local system does not support BPF/cgroup based firewalling.\n"
                                 "Proceeding WITHOUT firewalling in effect! (This warning is only shown for the first loaded unit using IP firewalling.)", filename, line, lvalue, rvalue);

                        warned = true;
                }
        }

        return 0;
}

PortRangeAccessItem* port_range_access_free_all(PortRangeAccessItem *first) {
        PortRangeAccessItem *next, *p = first;

        while (p) {
                next = p->items_next;
                free(p);

                p = next;
        }

        return NULL;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <stdbool.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "vlan-util.h"

static bool is_bit_set(unsigned bit, uint32_t scope) {
        assert(bit < sizeof(scope)*8);
        return scope & (UINT32_C(1) << bit);
}

static void set_bit(unsigned nr, uint32_t *addr) {
        if (nr < BRIDGE_VLAN_BITMAP_MAX)
                addr[nr / 32] |= (UINT32_C(1) << (nr % 32));
}

static int find_next_bit(int i, uint32_t x) {
        int j;

        if (i >= 32)
                return -1;

        /* find first bit */
        if (i < 0)
                return BUILTIN_FFS_U32(x);

        /* mask off prior finds to get next */
        j = __builtin_ffs(x >> i);
        return j ? j + i : 0;
}

int bridge_vlan_append_info(
                const Link *link,
                sd_netlink_message *req,
                uint16_t pvid,
                const uint32_t *br_vid_bitmap,
                const uint32_t *br_untagged_bitmap) {

        struct bridge_vlan_info br_vlan;
        bool done, untagged = false;
        uint16_t begin, end;
        int r, cnt;

        assert(link);
        assert(req);
        assert(br_vid_bitmap);
        assert(br_untagged_bitmap);

        cnt = 0;

        begin = end = UINT16_MAX;
        for (int k = 0; k < BRIDGE_VLAN_BITMAP_LEN; k++) {
                uint32_t untagged_map = br_untagged_bitmap[k];
                uint32_t vid_map = br_vid_bitmap[k];
                unsigned base_bit = k * 32;
                int i = -1;

                done = false;
                do {
                        int j = find_next_bit(i, vid_map);
                        if (j > 0) {
                                /* first hit of any bit */
                                if (begin == UINT16_MAX && end == UINT16_MAX) {
                                        begin = end = j - 1 + base_bit;
                                        untagged = is_bit_set(j - 1, untagged_map);
                                        goto next;
                                }

                                /* this bit is a continuation of prior bits */
                                if (j - 2 + base_bit == end && untagged == is_bit_set(j - 1, untagged_map) && (uint16_t)j - 1 + base_bit != pvid && (uint16_t)begin != pvid) {
                                        end++;
                                        goto next;
                                }
                        } else
                                done = true;

                        if (begin != UINT16_MAX) {
                                cnt++;
                                if (done && k < BRIDGE_VLAN_BITMAP_LEN - 1)
                                        break;

                                br_vlan.flags = 0;
                                if (untagged)
                                        br_vlan.flags |= BRIDGE_VLAN_INFO_UNTAGGED;

                                if (begin == end) {
                                        br_vlan.vid = begin;

                                        if (begin == pvid)
                                                br_vlan.flags |= BRIDGE_VLAN_INFO_PVID;

                                        r = sd_netlink_message_append_data(req, IFLA_BRIDGE_VLAN_INFO, &br_vlan, sizeof(br_vlan));
                                        if (r < 0)
                                                return r;
                                } else {
                                        br_vlan.vid = begin;
                                        br_vlan.flags |= BRIDGE_VLAN_INFO_RANGE_BEGIN;

                                        r = sd_netlink_message_append_data(req, IFLA_BRIDGE_VLAN_INFO, &br_vlan, sizeof(br_vlan));
                                        if (r < 0)
                                                return r;

                                        br_vlan.vid = end;
                                        br_vlan.flags &= ~BRIDGE_VLAN_INFO_RANGE_BEGIN;
                                        br_vlan.flags |= BRIDGE_VLAN_INFO_RANGE_END;

                                        r = sd_netlink_message_append_data(req, IFLA_BRIDGE_VLAN_INFO, &br_vlan, sizeof(br_vlan));
                                        if (r < 0)
                                                return r;
                                }

                                if (done)
                                        break;
                        }
                        if (j > 0) {
                                begin = end = j - 1 + base_bit;
                                untagged = is_bit_set(j - 1, untagged_map);
                        }

                next:
                        i = j;
                } while (!done);
        }

        assert(cnt > 0);
        return cnt;
}

void network_adjust_bridge_vlan(Network *network) {
        assert(network);

        if (!network->use_br_vlan)
                return;

        /* pvid might not be in br_vid_bitmap yet */
        if (network->pvid)
                set_bit(network->pvid, network->br_vid_bitmap);
}

int config_parse_brvlan_pvid(
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

        Network *network = userdata;
        uint16_t pvid;
        int r;

        r = parse_vlanid(rvalue, &pvid);
        if (r < 0)
                return r;

        network->pvid = pvid;
        network->use_br_vlan = true;

        return 0;
}

int config_parse_brvlan_vlan(
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

        Network *network = userdata;
        uint16_t vid, vid_end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_vid_range(rvalue, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse VLAN, ignoring: %s", rvalue);
                return 0;
        }

        for (; vid <= vid_end; vid++)
                set_bit(vid, network->br_vid_bitmap);

        network->use_br_vlan = true;
        return 0;
}

int config_parse_brvlan_untagged(
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

        Network *network = userdata;
        uint16_t vid, vid_end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_vid_range(rvalue, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Could not parse VLAN: %s", rvalue);
                return 0;
        }

        for (; vid <= vid_end; vid++) {
                set_bit(vid, network->br_vid_bitmap);
                set_bit(vid, network->br_untagged_bitmap);
        }

        network->use_br_vlan = true;
        return 0;
}

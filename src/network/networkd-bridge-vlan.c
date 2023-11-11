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

static bool is_bit_set(unsigned nr, const uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        return addr[nr / 32] & (UINT32_C(1) << (nr % 32));
}

static void set_bit(unsigned nr, uint32_t *addr) {
        if (nr < BRIDGE_VLAN_BITMAP_MAX)
                addr[nr / 32] |= (UINT32_C(1) << (nr % 32));
}

static int add_single(sd_netlink_message *m, uint16_t id, bool untagged, bool is_pvid) {
        assert(m);
        assert(id < BRIDGE_VLAN_BITMAP_MAX);
        return sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                              &(struct bridge_vlan_info) {
                                                      .vid = id,
                                                      .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                               (is_pvid ? BRIDGE_VLAN_INFO_PVID : 0),
                                              },
                                              sizeof(struct bridge_vlan_info));
}

static int add_range(sd_netlink_message *m, uint16_t begin, uint16_t end, bool untagged) {
        int r;

        assert(m);
        assert(begin <= end);
        assert(end < BRIDGE_VLAN_BITMAP_MAX);

        if (begin == end)
                return add_single(m, begin, untagged, /* is_pvid = */ false);

        r = sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                           &(struct bridge_vlan_info) {
                                                   .vid = begin,
                                                   .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                            BRIDGE_VLAN_INFO_RANGE_BEGIN,
                                           },
                                           sizeof(struct bridge_vlan_info));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                           &(struct bridge_vlan_info) {
                                                   .vid = end,
                                                   .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                            BRIDGE_VLAN_INFO_RANGE_END,
                                           },
                                           sizeof(struct bridge_vlan_info));
        if (r < 0)
                return r;

        return 0;
}

static int bridge_vlan_append_set_info(Link *link, sd_netlink_message *m) {
        uint16_t begin = UINT16_MAX;
        bool untagged;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {

                if (k > 0 && k == link->network->pvid) {
                        /* PVID needs to be sent alone. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        untagged = is_bit_set(k, link->network->br_untagged_bitmap);
                        r = add_single(m, k, untagged, /* is_pvid = */ true);
                        if (r < 0)
                                return r;

                        continue;
                }

                if (!is_bit_set(k, link->network->br_vid_bitmap)) {
                        /* This bit is not set. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX) {
                        bool u;

                        assert(begin < k);

                        u = is_bit_set(k, link->network->br_untagged_bitmap);
                        if (untagged == u)
                                continue;

                        /* Tagging flag is changed from the previous bits. Finish them. */
                        r = add_range(m, begin, k - 1, untagged);
                        if (r < 0)
                                return r;

                        begin = k;
                        untagged = u;
                        continue;
                }

                /* This is the starting point of a new bit sequence. Save the position and the tagging flag. */
                begin = k;
                untagged = is_bit_set(k, link->network->br_untagged_bitmap);
        }

        /* No pending bit sequence.
         * Why? There is a trick. The conf parsers below only accepts vlan ID in the range 0…4094, but in
         * the above loop, we run 0…4095. */
        assert_cc(BRIDGE_VLAN_BITMAP_MAX > VLANID_MAX);
        assert(begin == UINT16_MAX);
        return 0;
}

int bridge_vlan_set_message(Link *link, sd_netlink_message *m) {
        int r;

        assert(link);
        assert(m);

        r = sd_rtnl_message_link_set_family(m, AF_BRIDGE);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_AF_SPEC);
        if (r < 0)
                return r;

        if (link->master_ifindex <= 0) {
                /* master needs BRIDGE_FLAGS_SELF flag */
                r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_FLAGS, BRIDGE_FLAGS_SELF);
                if (r < 0)
                        return r;
        }

        r = bridge_vlan_append_set_info(link, m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
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

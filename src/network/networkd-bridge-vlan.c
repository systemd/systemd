/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <linux/if_bridge.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-util.h"
#include "vlan-util.h"

#define BRIDGE_VLAN_TUNNEL_ID_MAX ((1u << 24) - 1)

static bool is_bit_set(unsigned nr, const uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        return addr[nr / 32] & (UINT32_C(1) << (nr % 32));
}

static void set_bit(unsigned nr, uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        addr[nr / 32] |= (UINT32_C(1) << (nr % 32));
}

static int add_single(sd_netlink_message *m, uint16_t id, bool untagged, bool is_pvid, char **str) {
        assert(m);
        assert(id < BRIDGE_VLAN_BITMAP_MAX);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u%s%s%s%s%s", id,
                                                 (untagged || is_pvid) ? "(" : "",
                                                 untagged ? "untagged" : "",
                                                 (untagged && is_pvid) ? "," : "",
                                                 is_pvid ? "pvid" : "",
                                                 (untagged || is_pvid) ? ")" : "");

        return sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                              &(struct bridge_vlan_info) {
                                                      .vid = id,
                                                      .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                               (is_pvid ? BRIDGE_VLAN_INFO_PVID : 0),
                                              },
                                              sizeof(struct bridge_vlan_info));
}

static int add_range(sd_netlink_message *m, uint16_t begin, uint16_t end, bool untagged, char **str) {
        int r;

        assert(m);
        assert(begin <= end);
        assert(end < BRIDGE_VLAN_BITMAP_MAX);

        if (begin == end)
                return add_single(m, begin, untagged, /* is_pvid= */ false, str);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u-%u%s", begin, end, untagged ? "(untagged)" : "");

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

static uint16_t link_get_pvid(Link *link, bool *ret_untagged) {
        assert(link);
        assert(link->network);

        if (vlanid_is_valid(link->network->bridge_vlan_pvid)) {
                if (ret_untagged)
                        *ret_untagged = is_bit_set(link->network->bridge_vlan_pvid,
                                                   link->network->bridge_vlan_untagged_bitmap);
                return link->network->bridge_vlan_pvid;
        }

        if (link->network->bridge_vlan_pvid == BRIDGE_VLAN_KEEP_PVID) {
                if (ret_untagged)
                        *ret_untagged = link->bridge_vlan_pvid_is_untagged;
                return link->bridge_vlan_pvid;
        }

        if (ret_untagged)
                *ret_untagged = false;
        return UINT16_MAX;
}

static int bridge_vlan_append_set_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        uint16_t pvid, begin = UINT16_MAX;
        bool untagged, pvid_is_untagged;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        pvid = link_get_pvid(link, &pvid_is_untagged);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {

                if (k == pvid) {
                        /* PVID needs to be sent alone. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        r = add_single(m, pvid, pvid_is_untagged, /* is_pvid= */ true, &str);
                        if (r < 0)
                                return r;

                        continue;
                }

                if (!is_bit_set(k, link->network->bridge_vlan_bitmap)) {
                        /* This bit is not set. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX) {
                        bool u;

                        assert(begin < k);

                        u = is_bit_set(k, link->network->bridge_vlan_untagged_bitmap);
                        if (untagged == u)
                                continue;

                        /* Tagging flag is changed from the previous bits. Finish them. */
                        r = add_range(m, begin, k - 1, untagged, &str);
                        if (r < 0)
                                return r;

                        begin = k;
                        untagged = u;
                        continue;
                }

                /* This is the starting point of a new bit sequence. Save the position and the tagging flag. */
                begin = k;
                untagged = is_bit_set(k, link->network->bridge_vlan_untagged_bitmap);
        }

        /* No pending bit sequence.
         * Why? There is a trick. The conf parsers below only accepts vlan ID in the range 0…4094, but in
         * the above loop, we run 0…4095. */
        assert_cc(BRIDGE_VLAN_BITMAP_MAX > VLANID_MAX);
        assert(begin == UINT16_MAX);

        log_link_debug(link, "Setting Bridge VLAN IDs: %s", strna(str));
        return 0;
}

static int bridge_vlan_append_del_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        uint16_t pvid, begin = UINT16_MAX;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        pvid = link_get_pvid(link, NULL);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {

                if (k == pvid ||
                    !is_bit_set(k, link->bridge_vlan_bitmap) ||
                    is_bit_set(k, link->network->bridge_vlan_bitmap)) {
                        /* This bit is not necessary to be removed. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, /* untagged= */ false, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX)
                        continue;

                /* This is the starting point of a new bit sequence. Save the position. */
                begin = k;
        }

        /* No pending bit sequence. */
        assert(begin == UINT16_MAX);

        log_link_debug(link, "Removing Bridge VLAN IDs: %s", strna(str));
        return 0;
}

static int add_tunnel_single(sd_netlink_message *m, uint16_t vid, uint32_t tunnel_id, char **str) {
        int r;

        assert(m);
        assert(vid < BRIDGE_VLAN_BITMAP_MAX);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u=%"PRIu32, vid, tunnel_id);

        r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, 0);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m);
}

static int add_tunnel_range(
                sd_netlink_message *m,
                uint16_t vid_begin,
                uint16_t vid_end,
                uint32_t tunnel_id_begin,
                uint32_t tunnel_id_end,
                char **str) {

        int r;

        assert(m);
        assert(vid_begin <= vid_end);
        assert(vid_end < BRIDGE_VLAN_BITMAP_MAX);

        if (vid_begin == vid_end)
                return add_tunnel_single(m, vid_begin, tunnel_id_begin, str);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u-%u=%"PRIu32"-%"PRIu32,
                                                 vid_begin, vid_end, tunnel_id_begin, tunnel_id_end);

        r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id_begin);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid_begin);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, BRIDGE_VLAN_INFO_RANGE_BEGIN);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id_end);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid_end);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, BRIDGE_VLAN_INFO_RANGE_END);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m);
}

static int bridge_vlan_flush_tunnel_range(
                sd_netlink_message *m,
                uint16_t begin,
                uint16_t end,
                const uint32_t *tunnel_id,
                char **str) {

        assert(m);
        assert(begin <= end);
        assert(tunnel_id);

        return add_tunnel_range(m, begin, end, tunnel_id[begin], tunnel_id[end], str);
}

static int bridge_vlan_append_tunnel_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        uint16_t begin = UINT16_MAX;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        if (memeqzero(link->network->bridge_vlan_tunnel_bitmap, sizeof(link->network->bridge_vlan_tunnel_bitmap)))
                return 0;

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {
                if (!is_bit_set(k, link->network->bridge_vlan_tunnel_bitmap)) {
                        /* No tunnel mapping for this VID. Finish pending range. */
                        if (begin != UINT16_MAX) {
                                r = bridge_vlan_flush_tunnel_range(m, begin, k - 1, link->network->bridge_vlan_tunnel_id, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX) {
                        /* Check if tunnel IDs are contiguous with the range start */
                        uint32_t expected_tunnel_id = link->network->bridge_vlan_tunnel_id[begin] + (k - begin);
                        if (link->network->bridge_vlan_tunnel_id[k] != expected_tunnel_id) {
                                /* Non-contiguous tunnel IDs, flush previous range and start new one */
                                r = bridge_vlan_flush_tunnel_range(m, begin, k - 1, link->network->bridge_vlan_tunnel_id, &str);
                                if (r < 0)
                                        return r;

                                begin = k;
                        }

                        continue;
                }

                /* Start of a new range */
                begin = k;
        }

        /* No pending range - same trick as bridge_vlan_append_set_info */
        assert_cc(BRIDGE_VLAN_BITMAP_MAX > VLANID_MAX);
        assert(begin == UINT16_MAX);

        log_link_debug(link, "Setting Bridge VLAN tunnel mappings: %s", strna(str));
        return 0;
}

int bridge_vlan_set_message(Link *link, sd_netlink_message *m, bool is_set) {
        int r;

        assert(link);
        assert(m);

        r = sd_rtnl_message_link_set_family(m, AF_BRIDGE);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_AF_SPEC);
        if (r < 0)
                return r;

        if (link->master_ifindex <= 0 || streq_ptr(link->kind, "bridge")) {
                /* If the setting is requested in a .network file for a bridge master (or a physical master)
                 * interface, then BRIDGE_FLAGS_SELF flag needs to be set. */
                r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_FLAGS, BRIDGE_FLAGS_SELF);
                if (r < 0)
                        return r;
        }

        if (is_set) {
                r = bridge_vlan_append_set_info(link, m);
                if (r < 0)
                        return r;

                r = bridge_vlan_append_tunnel_info(link, m);
                if (r < 0)
                        return r;
        } else {
                r = bridge_vlan_append_del_info(link, m);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int link_update_bridge_vlan(Link *link, sd_netlink_message *m) {
        _cleanup_free_ void *data = NULL;
        size_t len;
        uint16_t begin = UINT16_MAX;
        int r, family;

        assert(link);
        assert(m);

        r = sd_rtnl_message_get_family(m, &family);
        if (r < 0)
                return r;

        if (family != AF_BRIDGE)
                return 0;

        r = sd_netlink_message_read_data(m, IFLA_AF_SPEC, &len, &data);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        memzero(link->bridge_vlan_bitmap, sizeof(link->bridge_vlan_bitmap));

        for (struct rtattr *rta = data; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                struct bridge_vlan_info *p;

                if (RTA_TYPE(rta) != IFLA_BRIDGE_VLAN_INFO)
                        continue;
                if (RTA_PAYLOAD(rta) != sizeof(struct bridge_vlan_info))
                        continue;

                p = RTA_DATA(rta);

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_RANGE_BEGIN)) {
                        begin = p->vid;
                        continue;
                }

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_RANGE_END)) {
                        for (uint16_t k = begin; k <= p->vid; k++)
                                set_bit(k, link->bridge_vlan_bitmap);

                        begin = UINT16_MAX;
                        continue;
                }

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_PVID)) {
                        link->bridge_vlan_pvid = p->vid;
                        link->bridge_vlan_pvid_is_untagged = FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_UNTAGGED);
                }

                set_bit(p->vid, link->bridge_vlan_bitmap);
                begin = UINT16_MAX;
        }

        return 0;
}

void network_adjust_bridge_vlan(Network *network) {
        assert(network);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {
                if (is_bit_set(k, network->bridge_vlan_untagged_bitmap))
                        set_bit(k, network->bridge_vlan_bitmap);

                /* Ensure VLANs with tunnel mappings are also in the VLAN bitmap */
                if (is_bit_set(k, network->bridge_vlan_tunnel_bitmap))
                        set_bit(k, network->bridge_vlan_bitmap);
        }

        if (vlanid_is_valid(network->bridge_vlan_pvid))
                set_bit(network->bridge_vlan_pvid, network->bridge_vlan_bitmap);
}

int config_parse_bridge_vlan_id(
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

        uint16_t v, *id = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *id = BRIDGE_VLAN_KEEP_PVID;
                return 0;
        }

        if (parse_boolean(rvalue) == 0) {
                *id = BRIDGE_VLAN_REMOVE_PVID;
                return 0;
        }

        r = parse_vlanid(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        *id = v;
        return 0;
}

int config_parse_bridge_vlan_id_range(
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

        uint32_t *bitmap = ASSERT_PTR(data);
        uint16_t vid, vid_end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                memzero(bitmap, BRIDGE_VLAN_BITMAP_LEN * sizeof(uint32_t));
                return 0;
        }

        r = parse_vid_range(rvalue, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        for (; vid <= vid_end; vid++)
                set_bit(vid, bitmap);

        return 0;
}

int config_parse_bridge_vlan_tunnel_id(
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

        Network *network = ASSERT_PTR(userdata);
        _cleanup_free_ char *vid_str = NULL;
        uint32_t tunnel_id, tunnel_id_end;
        uint16_t vid, vid_end;
        unsigned lower, upper;
        const char *p;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                memzero(network->bridge_vlan_tunnel_bitmap, sizeof(network->bridge_vlan_tunnel_bitmap));
                memzero(network->bridge_vlan_tunnel_id, sizeof(network->bridge_vlan_tunnel_id));
                return 0;
        }

        /* Format: VID=TUNNELID or VID_RANGE=TUNNELID_RANGE (e.g., "100=10100" or "10-20=10010-10020") */
        p = strchr(rvalue, '=');
        if (!p) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse %s=, expected VID=TUNNELID format, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        vid_str = strndup(rvalue, p - rvalue);
        if (!vid_str)
                return log_oom();

        p++; /* skip '=' */

        r = parse_vid_range(vid_str, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse VLAN ID in %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        /* Parse tunnel ID range */
        r = parse_range(p, &lower, &upper);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse tunnel ID in %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        tunnel_id = lower;
        tunnel_id_end = upper;

        if (tunnel_id > tunnel_id_end) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid tunnel ID range (start > end) in %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (tunnel_id == 0 || tunnel_id > BRIDGE_VLAN_TUNNEL_ID_MAX || tunnel_id_end > BRIDGE_VLAN_TUNNEL_ID_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Tunnel ID out of range in %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        if ((vid_end - vid) != (tunnel_id_end - tunnel_id)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "VLAN ID range and tunnel ID range must have the same size in %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        for (uint16_t v = vid; v <= vid_end; v++) {
                set_bit(v, network->bridge_vlan_tunnel_bitmap);
                network->bridge_vlan_tunnel_id[v] = tunnel_id + (v - vid);
        }

        return 0;
}

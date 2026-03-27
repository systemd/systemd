/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_bridge.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "hashmap.h"
#include "netlink-util.h"
#include "networkd-bridge-vlan-tunnel.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "vlan-util.h"

#define STATIC_BRIDGE_VLAN_TUNNEL_ENTRIES_PER_NETWORK_MAX 1024U

/* Maximum VNI value for VXLAN (2^24 - 1) */
#define VXLAN_VNI_MAX ((1u << 24) - 1)

static BridgeVLANTunnel* bridge_vlan_tunnel_free(BridgeVLANTunnel *tunnel) {
        if (!tunnel)
                return NULL;

        if (tunnel->network) {
                assert(tunnel->section);
                hashmap_remove(tunnel->network->bridge_vlan_tunnel_entries_by_section, tunnel->section);
        }

        config_section_free(tunnel->section);
        return mfree(tunnel);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(BridgeVLANTunnel, bridge_vlan_tunnel_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                bridge_vlan_tunnel_hash_ops_by_section,
                ConfigSection, config_section_hash_func, config_section_compare_func,
                BridgeVLANTunnel, bridge_vlan_tunnel_free);

static int bridge_vlan_tunnel_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                BridgeVLANTunnel **ret) {

        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(bridge_vlan_tunnel_freep) BridgeVLANTunnel *tunnel = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        tunnel = hashmap_get(network->bridge_vlan_tunnel_entries_by_section, n);
        if (tunnel) {
                *ret = TAKE_PTR(tunnel);
                return 0;
        }

        if (hashmap_size(network->bridge_vlan_tunnel_entries_by_section) >= STATIC_BRIDGE_VLAN_TUNNEL_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        tunnel = new(BridgeVLANTunnel, 1);
        if (!tunnel)
                return -ENOMEM;

        *tunnel = (BridgeVLANTunnel) {
                .network = network,
                .section = TAKE_PTR(n),
                .vlan_id = UINT16_MAX,
                .vlan_id_end = UINT16_MAX,
                .tunnel_id = UINT32_MAX,
                .tunnel_id_end = UINT32_MAX,
        };

        r = hashmap_ensure_put(&network->bridge_vlan_tunnel_entries_by_section, &bridge_vlan_tunnel_hash_ops_by_section, tunnel->section, tunnel);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(tunnel);
        return 0;
}

void network_drop_invalid_bridge_vlan_tunnel_entries(Network *network) {
        BridgeVLANTunnel *tunnel;

        assert(network);

        HASHMAP_FOREACH(tunnel, network->bridge_vlan_tunnel_entries_by_section) {
                if (section_is_invalid(tunnel->section)) {
                        bridge_vlan_tunnel_free(tunnel);
                        continue;
                }

                if (!vlanid_is_valid(tunnel->vlan_id)) {
                        log_warning("%s:%u: [BridgeVLANTunnel] section without valid VLAN=, ignoring.",
                                    tunnel->section->filename, tunnel->section->line);
                        bridge_vlan_tunnel_free(tunnel);
                        continue;
                }

                if (tunnel->tunnel_id == UINT32_MAX) {
                        log_warning("%s:%u: [BridgeVLANTunnel] section without TunnelID=, ignoring.",
                                    tunnel->section->filename, tunnel->section->line);
                        bridge_vlan_tunnel_free(tunnel);
                        continue;
                }

                /* For ranges, the VLAN and tunnel ID spans must match. */
                if ((tunnel->vlan_id_end != UINT16_MAX && tunnel->vlan_id != tunnel->vlan_id_end) ||
                    (tunnel->tunnel_id_end != UINT32_MAX && tunnel->tunnel_id != tunnel->tunnel_id_end)) {
                        uint32_t vlan_span = tunnel->vlan_id_end - tunnel->vlan_id;
                        uint32_t tunnel_span = tunnel->tunnel_id_end - tunnel->tunnel_id;

                        if (vlan_span != tunnel_span) {
                                log_warning("%s:%u: [BridgeVLANTunnel] VLAN= and TunnelID= ranges must have the same span, ignoring.",
                                            tunnel->section->filename, tunnel->section->line);
                                bridge_vlan_tunnel_free(tunnel);
                                continue;
                        }
                }
        }
}

static int bridge_vlan_tunnel_add_single(sd_netlink_message *m, uint16_t vid, uint32_t tunnel_id, uint16_t flags, char **str) {
        int r;

        assert(m);

        if (str && DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "vid=%u->tunid=%u", vid, tunnel_id);

        r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, flags);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int bridge_vlan_tunnel_append_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        BridgeVLANTunnel *tunnel;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        HASHMAP_FOREACH(tunnel, link->network->bridge_vlan_tunnel_entries_by_section) {
                if (!vlanid_is_valid(tunnel->vlan_id) || tunnel->tunnel_id == UINT32_MAX)
                        continue;

                if (tunnel->vlan_id == tunnel->vlan_id_end || tunnel->vlan_id_end == UINT16_MAX) {
                        r = bridge_vlan_tunnel_add_single(m, tunnel->vlan_id, tunnel->tunnel_id, 0, &str);
                        if (r < 0)
                                return r;
                } else {
                        if (DEBUG_LOGGING)
                                (void) strextendf_with_separator(&str, ",", "vid=%u-%u->tunid=%u-%u",
                                                                 tunnel->vlan_id, tunnel->vlan_id_end,
                                                                 tunnel->tunnel_id, tunnel->tunnel_id_end);

                        r = bridge_vlan_tunnel_add_single(m, tunnel->vlan_id, tunnel->tunnel_id,
                                                          BRIDGE_VLAN_INFO_RANGE_BEGIN, NULL);
                        if (r < 0)
                                return r;

                        r = bridge_vlan_tunnel_add_single(m, tunnel->vlan_id_end, tunnel->tunnel_id_end,
                                                          BRIDGE_VLAN_INFO_RANGE_END, NULL);
                        if (r < 0)
                                return r;
                }
        }

        log_link_debug(link, "Setting Bridge VLAN tunnel mappings: %s", strna(str));
        return 0;
}

bool link_has_bridge_vlan_tunnel(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        return !hashmap_isempty(link->network->bridge_vlan_tunnel_entries_by_section);
}

int config_parse_bridge_vlan_tunnel_vlan(
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

        _cleanup_(bridge_vlan_tunnel_free_or_set_invalidp) BridgeVLANTunnel *tunnel = NULL;
        Network *network = ASSERT_PTR(userdata);
        uint16_t vid, vid_end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = bridge_vlan_tunnel_new_static(network, filename, section_line, &tunnel);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                tunnel->vlan_id = UINT16_MAX;
                tunnel->vlan_id_end = UINT16_MAX;
                TAKE_PTR(tunnel);
                return 0;
        }

        r = parse_vid_range(rvalue, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        tunnel->vlan_id = vid;
        tunnel->vlan_id_end = vid_end;
        TAKE_PTR(tunnel);
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

        _cleanup_(bridge_vlan_tunnel_free_or_set_invalidp) BridgeVLANTunnel *tunnel = NULL;
        Network *network = ASSERT_PTR(userdata);
        unsigned lower, upper;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = bridge_vlan_tunnel_new_static(network, filename, section_line, &tunnel);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                tunnel->tunnel_id = UINT32_MAX;
                tunnel->tunnel_id_end = UINT32_MAX;
                TAKE_PTR(tunnel);
                return 0;
        }

        r = parse_range(rvalue, &lower, &upper);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (lower > VXLAN_VNI_MAX || upper > VXLAN_VNI_MAX || lower > upper) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid tunnel ID range, ignoring: %s", rvalue);
                return 0;
        }

        tunnel->tunnel_id = lower;
        tunnel->tunnel_id_end = upper;
        TAKE_PTR(tunnel);
        return 0;
}

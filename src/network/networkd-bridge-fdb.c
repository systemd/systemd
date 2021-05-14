/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if.h>

#include "alloc-util.h"
#include "bridge.h"
#include "netlink-util.h"
#include "networkd-bridge-fdb.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-table.h"
#include "vlan-util.h"
#include "vxlan.h"

#define STATIC_BRIDGE_FDB_ENTRIES_PER_NETWORK_MAX 1024U

/* remove and FDB entry. */
BridgeFDB *bridge_fdb_free(BridgeFDB *fdb) {
        if (!fdb)
                return NULL;

        if (fdb->network) {
                assert(fdb->section);
                hashmap_remove(fdb->network->bridge_fdb_entries_by_section, fdb->section);
        }

        network_config_section_free(fdb->section);
        return mfree(fdb);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(BridgeFDB, bridge_fdb_free);

/* create a new FDB entry or get an existing one. */
static int bridge_fdb_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                BridgeFDB **ret) {

        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(bridge_fdb_freep) BridgeFDB *fdb = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        /* search entry in hashmap first. */
        fdb = hashmap_get(network->bridge_fdb_entries_by_section, n);
        if (fdb) {
                *ret = TAKE_PTR(fdb);
                return 0;
        }

        if (hashmap_size(network->bridge_fdb_entries_by_section) >= STATIC_BRIDGE_FDB_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        /* allocate space for and FDB entry. */
        fdb = new(BridgeFDB, 1);
        if (!fdb)
                return -ENOMEM;

        /* init FDB structure. */
        *fdb = (BridgeFDB) {
                .network = network,
                .section = TAKE_PTR(n),
                .vni = VXLAN_VID_MAX + 1,
                .ntf_flags = NEIGHBOR_CACHE_ENTRY_FLAGS_SELF,
        };

        r = hashmap_ensure_put(&network->bridge_fdb_entries_by_section, &network_config_hash_ops, fdb->section, fdb);
        if (r < 0)
                return r;

        /* return allocated FDB structure. */
        *ret = TAKE_PTR(fdb);

        return 0;
}

static int set_fdb_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add FDB entry");
                link_enter_failed(link);
                return 1;
        }

        return 1;
}

/* send a request to the kernel to add a FDB entry in its static MAC table. */
static int bridge_fdb_configure(Link *link, BridgeFDB *fdb) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(fdb);

        /* create new RTM message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH, link->ifindex, AF_BRIDGE);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_flags(req, fdb->ntf_flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set neighbor flags: %m");

        /* only NUD_PERMANENT state supported. */
        r = sd_rtnl_message_neigh_set_state(req, NUD_NOARP | NUD_PERMANENT);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set neighbor state: %m");

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &fdb->mac_addr, sizeof(fdb->mac_addr));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_LLADDR attribute: %m");

        /* VLAN Id is optional. We'll add VLAN Id only if it's specified. */
        if (fdb->vlan_id > 0) {
                r = sd_netlink_message_append_u16(req, NDA_VLAN, fdb->vlan_id);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_VLAN attribute: %m");
        }

        if (in_addr_is_set(fdb->family, &fdb->destination_addr)) {
                r = netlink_message_append_in_addr_union(req, NDA_DST, fdb->family, &fdb->destination_addr);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");
        }

        if (fdb->vni <= VXLAN_VID_MAX) {
                r = sd_netlink_message_append_u32(req, NDA_VNI, fdb->vni);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_VNI attribute: %m");
        }

        /* send message to the kernel to update its internal static MAC table. */
        r = netlink_call_async(link->manager->rtnl, NULL, req, set_fdb_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 1;
}

int link_set_bridge_fdb(Link *link) {
        BridgeFDB *fdb;
        int r;

        assert(link);
        assert(link->network);

        HASHMAP_FOREACH(fdb, link->network->bridge_fdb_entries_by_section) {
                r = bridge_fdb_configure(link, fdb);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to add MAC entry to static MAC table: %m");
        }

        return 0;
}

void network_drop_invalid_bridge_fdb_entries(Network *network) {
        BridgeFDB *fdb;

        assert(network);

        HASHMAP_FOREACH(fdb, network->bridge_fdb_entries_by_section)
                if (section_is_invalid(fdb->section))
                        bridge_fdb_free(fdb);
}

/* parse the HW address from config files. */
int config_parse_fdb_hwaddr(
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

        _cleanup_(bridge_fdb_free_or_set_invalidp) BridgeFDB *fdb = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_fdb_new_static(network, filename, section_line, &fdb);
        if (r < 0)
                return log_oom();

        r = ether_addr_from_string(rvalue, &fdb->mac_addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Not a valid MAC address, ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(fdb);
        return 0;
}

/* parse the VLAN Id from config files. */
int config_parse_fdb_vlan_id(
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

        _cleanup_(bridge_fdb_free_or_set_invalidp) BridgeFDB *fdb = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_fdb_new_static(network, filename, section_line, &fdb);
        if (r < 0)
                return log_oom();

        r = config_parse_vlanid(unit, filename, line, section,
                                section_line, lvalue, ltype,
                                rvalue, &fdb->vlan_id, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(fdb);
        return 0;
}

int config_parse_fdb_destination(
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

        _cleanup_(bridge_fdb_free_or_set_invalidp) BridgeFDB *fdb = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_fdb_new_static(network, filename, section_line, &fdb);
        if (r < 0)
                return log_oom();

        r = in_addr_from_string_auto(rvalue, &fdb->family, &fdb->destination_addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "FDB destination IP address is invalid, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        TAKE_PTR(fdb);
        return 0;
}

int config_parse_fdb_vxlan_vni(
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

        _cleanup_(bridge_fdb_free_or_set_invalidp) BridgeFDB *fdb = NULL;
        Network *network = userdata;
        uint32_t vni;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_fdb_new_static(network, filename, section_line, &fdb);
        if (r < 0)
                return log_oom();

        r = safe_atou32(rvalue, &vni);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse VXLAN Network Identifier (VNI), ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        if (vni > VXLAN_VID_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "FDB invalid VXLAN Network Identifier (VNI), ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        fdb->vni = vni;

        TAKE_PTR(fdb);
        return 0;
}

static const char* const ntf_flags_table[_NEIGHBOR_CACHE_ENTRY_FLAGS_MAX] = {
        [NEIGHBOR_CACHE_ENTRY_FLAGS_USE] = "use",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_SELF] = "self",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_MASTER] = "master",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_ROUTER] = "router",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(ntf_flags, NeighborCacheEntryFlags);

int config_parse_fdb_ntf_flags(
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

        _cleanup_(bridge_fdb_free_or_set_invalidp) BridgeFDB *fdb = NULL;
        Network *network = userdata;
        NeighborCacheEntryFlags f;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_fdb_new_static(network, filename, section_line, &fdb);
        if (r < 0)
                return log_oom();

        f = ntf_flags_from_string(rvalue);
        if (f < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, f,
                           "FDB failed to parse AssociatedWith=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        fdb->ntf_flags = f;

        TAKE_PTR(fdb);
        return 0;
}

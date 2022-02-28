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
#include "networkd-queue.h"
#include "networkd-util.h"
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

        config_section_free(fdb->section);

        free(fdb->outgoing_ifname);
        return mfree(fdb);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(BridgeFDB, bridge_fdb_free);

/* create a new FDB entry or get an existing one. */
static int bridge_fdb_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                BridgeFDB **ret) {

        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(bridge_fdb_freep) BridgeFDB *fdb = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
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

        r = hashmap_ensure_put(&network->bridge_fdb_entries_by_section, &config_section_hash_ops, fdb->section, fdb);
        if (r < 0)
                return r;

        /* return allocated FDB structure. */
        *ret = TAKE_PTR(fdb);

        return 0;
}

static int bridge_fdb_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add bridge FDB entry");
                link_enter_failed(link);
                return 0;
        }

        if (link->static_bridge_fdb_messages == 0) {
                log_link_debug(link, "Bridge FDB entries set");
                link->static_bridge_fdb_configured = true;
                link_check_ready(link);
        }

        return 0;
}

/* send a request to the kernel to add a FDB entry in its static MAC table. */
static int bridge_fdb_configure_message(const BridgeFDB *fdb, Link *link, sd_netlink_message *req) {
        int r;

        assert(fdb);
        assert(link);

        r = sd_rtnl_message_neigh_set_flags(req, fdb->ntf_flags);
        if (r < 0)
                return r;

        /* only NUD_PERMANENT state supported. */
        r = sd_rtnl_message_neigh_set_state(req, NUD_NOARP | NUD_PERMANENT);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &fdb->mac_addr, sizeof(fdb->mac_addr));
        if (r < 0)
                return r;

        /* VLAN Id is optional. We'll add VLAN Id only if it's specified. */
        if (fdb->vlan_id > 0) {
                r = sd_netlink_message_append_u16(req, NDA_VLAN, fdb->vlan_id);
                if (r < 0)
                        return r;
        }

        if (fdb->outgoing_ifindex > 0) {
                r = sd_netlink_message_append_u32(req, NDA_IFINDEX, fdb->outgoing_ifindex);
                if (r < 0)
                        return r;
        }

        if (in_addr_is_set(fdb->family, &fdb->destination_addr)) {
                r = netlink_message_append_in_addr_union(req, NDA_DST, fdb->family, &fdb->destination_addr);
                if (r < 0)
                        return r;
        }

        if (fdb->vni <= VXLAN_VID_MAX) {
                r = sd_netlink_message_append_u32(req, NDA_VNI, fdb->vni);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int bridge_fdb_configure(BridgeFDB *fdb, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(fdb);
        assert(link);
        assert(link->manager);
        assert(req);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH, link->ifindex, AF_BRIDGE);
        if (r < 0)
                return r;

        r = bridge_fdb_configure_message(fdb, link, m);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool bridge_fdb_is_ready_to_configure(BridgeFDB *fdb, Link *link) {
        Link *out = NULL;

        assert(fdb);
        assert(link);
        assert(link->manager);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (fdb->outgoing_ifname) {
                if (link_get_by_name(link->manager, fdb->outgoing_ifname, &out) < 0)
                        return false;

                fdb->outgoing_ifindex = out->ifindex;
        } else if (fdb->outgoing_ifindex > 0) {
                if (link_get_by_index(link->manager, fdb->outgoing_ifindex, &out) < 0)
                        return false;
        }
        if (out && !link_is_ready_to_configure(out, false))
                return false;

        return true;
}

static int bridge_fdb_process_request(Request *req, Link *link, void *userdata) {
        BridgeFDB *fdb = ASSERT_PTR(userdata);
        int r;

        assert(req);
        assert(link);

        if (!bridge_fdb_is_ready_to_configure(fdb, link))
                return 0;

        r = bridge_fdb_configure(fdb, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure bridge FDB: %m");

        return 1;
}

int link_request_static_bridge_fdb(Link *link) {
        BridgeFDB *fdb;
        int r;

        assert(link);
        assert(link->network);

        link->static_bridge_fdb_configured = false;

        HASHMAP_FOREACH(fdb, link->network->bridge_fdb_entries_by_section) {
                r = link_queue_request_full(link, REQUEST_TYPE_BRIDGE_FDB,
                                            fdb, NULL,
                                            trivial_hash_func,
                                            trivial_compare_func,
                                            bridge_fdb_process_request,
                                            &link->static_bridge_fdb_messages,
                                            bridge_fdb_configure_handler,
                                            NULL);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to request static bridge FDB entry: %m");
        }

        if (link->static_bridge_fdb_messages == 0) {
                link->static_bridge_fdb_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting bridge FDB entries");
                link_set_state(link, LINK_STATE_CONFIGURING);
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

        r = parse_ether_addr(rvalue, &fdb->mac_addr);
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

int config_parse_fdb_interface(
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

        if (isempty(rvalue)) {
                fdb->outgoing_ifname = mfree(fdb->outgoing_ifname);
                fdb->outgoing_ifindex = 0;
                TAKE_PTR(fdb);
                return 0;
        }

        r = parse_ifindex(rvalue);
        if (r > 0) {
                fdb->outgoing_ifname = mfree(fdb->outgoing_ifname);
                fdb->outgoing_ifindex = r;
                TAKE_PTR(fdb);
                return 0;
        }

        if (!ifname_valid_full(rvalue, IFNAME_VALID_ALTERNATIVE)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid interface name in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        r = free_and_strdup(&fdb->outgoing_ifname, rvalue);
        if (r < 0)
                return log_oom();
        fdb->outgoing_ifindex = 0;

        TAKE_PTR(fdb);
        return 0;
}

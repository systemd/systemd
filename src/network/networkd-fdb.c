/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netdev/bridge.h"
#include "netdev/vxlan.h"
#include "netlink-util.h"
#include "networkd-fdb.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "string-util.h"
#include "string-table.h"
#include "util.h"
#include "vlan-util.h"

#define STATIC_FDB_ENTRIES_PER_NETWORK_MAX 1024U

static const char* const fdb_ntf_flags_table[_NEIGHBOR_CACHE_ENTRY_FLAGS_MAX] = {
        [NEIGHBOR_CACHE_ENTRY_FLAGS_USE] = "use",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_SELF] = "self",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_MASTER] = "master",
        [NEIGHBOR_CACHE_ENTRY_FLAGS_ROUTER] = "router",
};

DEFINE_STRING_TABLE_LOOKUP(fdb_ntf_flags, NeighborCacheEntryFlags);

/* create a new FDB entry or get an existing one. */
static int fdb_entry_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                FdbEntry **ret) {

        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(fdb_entry_freep) FdbEntry *fdb_entry = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        /* search entry in hashmap first. */
        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                fdb_entry = hashmap_get(network->fdb_entries_by_section, n);
                if (fdb_entry) {
                        *ret = TAKE_PTR(fdb_entry);

                        return 0;
                }
        }

        if (network->n_static_fdb_entries >= STATIC_FDB_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        /* allocate space for and FDB entry. */
        fdb_entry = new(FdbEntry, 1);
        if (!fdb_entry)
                return -ENOMEM;

        /* init FDB structure. */
        *fdb_entry = (FdbEntry) {
                .network = network,
                .vni = VXLAN_VID_MAX + 1,
                .fdb_ntf_flags = NEIGHBOR_CACHE_ENTRY_FLAGS_SELF,
        };

        LIST_PREPEND(static_fdb_entries, network->static_fdb_entries, fdb_entry);
        network->n_static_fdb_entries++;

        if (filename) {
                fdb_entry->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->fdb_entries_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->fdb_entries_by_section, fdb_entry->section, fdb_entry);
                if (r < 0)
                        return r;
        }

        /* return allocated FDB structure. */
        *ret = TAKE_PTR(fdb_entry);

        return 0;
}

static int set_fdb_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not add FDB entry: %m");
                link_enter_failed(link);
                return 1;
        }

        return 1;
}

/* send a request to the kernel to add a FDB entry in its static MAC table. */
int fdb_entry_configure(Link *link, FdbEntry *fdb_entry) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(fdb_entry);

        /* create new RTM message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH, link->ifindex, PF_BRIDGE);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_neigh_set_flags(req, fdb_entry->fdb_ntf_flags);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* only NUD_PERMANENT state supported. */
        r = sd_rtnl_message_neigh_set_state(req, NUD_NOARP | NUD_PERMANENT);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &fdb_entry->mac_addr, sizeof(fdb_entry->mac_addr));
        if (r < 0)
                return rtnl_log_create_error(r);

        /* VLAN Id is optional. We'll add VLAN Id only if it's specified. */
        if (fdb_entry->vlan_id > 0) {
                r = sd_netlink_message_append_u16(req, NDA_VLAN, fdb_entry->vlan_id);
                if (r < 0)
                        return rtnl_log_create_error(r);
        }

        if (!in_addr_is_null(fdb_entry->family, &fdb_entry->destination_addr)) {
                r = netlink_message_append_in_addr_union(req, NDA_DST, fdb_entry->family, &fdb_entry->destination_addr);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");
        }

        if (fdb_entry->vni <= VXLAN_VID_MAX) {
                r = sd_netlink_message_append_u32(req, NDA_VNI, fdb_entry->vni);
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

/* remove and FDB entry. */
void fdb_entry_free(FdbEntry *fdb_entry) {
        if (!fdb_entry)
                return;

        if (fdb_entry->network) {
                LIST_REMOVE(static_fdb_entries, fdb_entry->network->static_fdb_entries, fdb_entry);
                assert(fdb_entry->network->n_static_fdb_entries > 0);
                fdb_entry->network->n_static_fdb_entries--;

                if (fdb_entry->section)
                        hashmap_remove(fdb_entry->network->fdb_entries_by_section, fdb_entry->section);
        }

        network_config_section_free(fdb_entry->section);
        free(fdb_entry);
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

        Network *network = userdata;
        _cleanup_(fdb_entry_free_or_set_invalidp) FdbEntry *fdb_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, filename, section_line, &fdb_entry);
        if (r < 0)
                return log_oom();

        r = ether_addr_from_string(rvalue, &fdb_entry->mac_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Not a valid MAC address, ignoring assignment: %s", rvalue);
                return 0;
        }

        fdb_entry = NULL;

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

        Network *network = userdata;
        _cleanup_(fdb_entry_free_or_set_invalidp) FdbEntry *fdb_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, filename, section_line, &fdb_entry);
        if (r < 0)
                return log_oom();

        r = config_parse_vlanid(unit, filename, line, section,
                                section_line, lvalue, ltype,
                                rvalue, &fdb_entry->vlan_id, userdata);
        if (r < 0)
                return r;

        fdb_entry = NULL;

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

        _cleanup_(fdb_entry_free_or_set_invalidp) FdbEntry *fdb_entry = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, filename, section_line, &fdb_entry);
        if (r < 0)
                return log_oom();

        r = in_addr_from_string_auto(rvalue, &fdb_entry->family, &fdb_entry->destination_addr);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "FDB destination IP address is invalid, ignoring assignment: %s",
                                  rvalue);

        fdb_entry = NULL;

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

        _cleanup_(fdb_entry_free_or_set_invalidp) FdbEntry *fdb_entry = NULL;
        Network *network = userdata;
        uint32_t vni;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, filename, section_line, &fdb_entry);
        if (r < 0)
                return log_oom();

        r = safe_atou32(rvalue, &vni);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse VXLAN Network Identifier (VNI), ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        if (vni > VXLAN_VID_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "FDB invalid VXLAN Network Identifier (VNI), ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        fdb_entry->vni = vni;
        fdb_entry = NULL;

        return 0;
}

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

        _cleanup_(fdb_entry_free_or_set_invalidp) FdbEntry *fdb_entry = NULL;
        Network *network = userdata;
        NeighborCacheEntryFlags f;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, filename, section_line, &fdb_entry);
        if (r < 0)
                return log_oom();

        f = fdb_ntf_flags_from_string(rvalue);
        if (f < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "FDB failed to parse AssociatedWith=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        fdb_entry->fdb_ntf_flags = f;
        fdb_entry = NULL;

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/if_bridge.h>

#include "netlink-util.h"
#include "networkd-bridge-mdb.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "string-util.h"
#include "vlan-util.h"

#define STATIC_BRIDGE_MDB_ENTRIES_PER_NETWORK_MAX 1024U

/* remove MDB entry. */
BridgeMDB *bridge_mdb_free(BridgeMDB *mdb) {
        if (!mdb)
                return NULL;

        if (mdb->network) {
                assert(mdb->section);
                hashmap_remove(mdb->network->bridge_mdb_entries_by_section, mdb->section);
        }

        config_section_free(mdb->section);

        return mfree(mdb);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(BridgeMDB, bridge_mdb_free);

/* create a new MDB entry or get an existing one. */
static int bridge_mdb_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                BridgeMDB **ret) {

        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(bridge_mdb_freep) BridgeMDB *mdb = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        /* search entry in hashmap first. */
        mdb = hashmap_get(network->bridge_mdb_entries_by_section, n);
        if (mdb) {
                *ret = TAKE_PTR(mdb);
                return 0;
        }

        if (hashmap_size(network->bridge_mdb_entries_by_section) >= STATIC_BRIDGE_MDB_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        /* allocate space for an MDB entry. */
        mdb = new(BridgeMDB, 1);
        if (!mdb)
                return -ENOMEM;

        /* init MDB structure. */
        *mdb = (BridgeMDB) {
                .network = network,
                .section = TAKE_PTR(n),
        };

        r = hashmap_ensure_put(&network->bridge_mdb_entries_by_section, &config_section_hash_ops, mdb->section, mdb);
        if (r < 0)
                return r;

        /* return allocated MDB structure. */
        *ret = TAKE_PTR(mdb);
        return 0;
}

static int bridge_mdb_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r == -EINVAL && streq_ptr(link->kind, "bridge") && link->master_ifindex <= 0) {
                /* To configure bridge MDB entries on bridge master, 1bc844ee0faa1b92e3ede00bdd948021c78d7088 (v5.4) is required. */
                if (!link->manager->bridge_mdb_on_master_not_supported) {
                        log_link_warning_errno(link, r, "Kernel seems not to support bridge MDB entries on bridge master, ignoring: %m");
                        link->manager->bridge_mdb_on_master_not_supported = true;
                }
        } else if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add MDB entry");
                link_enter_failed(link);
                return 1;
        }

        if (link->static_bridge_mdb_messages == 0) {
                link->static_bridge_mdb_configured = true;
                link_check_ready(link);
        }

        return 1;
}

/* send a request to the kernel to add an MDB entry */
static int bridge_mdb_configure(BridgeMDB *mdb, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct br_mdb_entry entry;
        int r;

        assert(mdb);
        assert(link);
        assert(link->manager);
        assert(req);

        if (DEBUG_LOGGING)
                log_link_debug(link, "Configuring bridge MDB entry: MulticastGroupAddress=%s, VLANId=%u",
                               IN_ADDR_TO_STRING(mdb->family, &mdb->group_addr), mdb->vlan_id);

        entry = (struct br_mdb_entry) {
                /* If MDB entry is added on bridge master, then the state must be MDB_TEMPORARY.
                 * See br_mdb_add_group() in net/bridge/br_mdb.c of kernel. */
                .state = link->master_ifindex <= 0 ? MDB_TEMPORARY : MDB_PERMANENT,
                .ifindex = link->ifindex,
                .vid = mdb->vlan_id,
        };

        switch (mdb->family) {
        case AF_INET:
                entry.addr.u.ip4 = mdb->group_addr.in.s_addr;
                entry.addr.proto = htobe16(ETH_P_IP);
                break;

        case AF_INET6:
                entry.addr.u.ip6 = mdb->group_addr.in6;
                entry.addr.proto = htobe16(ETH_P_IPV6);
                break;

        default:
                assert_not_reached();
        }

        r = sd_rtnl_message_new_mdb(link->manager->rtnl, &m, RTM_NEWMDB,
                                    link->master_ifindex > 0 ? link->master_ifindex : link->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, MDBA_SET_ENTRY, &entry, sizeof(entry));
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool bridge_mdb_is_ready_to_configure(Link *link) {
        Link *master;

        assert(link);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (!link->master_set)
                return false;

        if (link->master_ifindex <= 0 && streq_ptr(link->kind, "bridge"))
                return true; /* The interface is bridge master. */

        if (link_get_master(link, &master) < 0)
                return false;

        if (!streq_ptr(master->kind, "bridge"))
                return false;

        if (!IN_SET(master->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (master->set_flags_messages > 0)
                return false;

        if (!link_has_carrier(master))
                return false;

        return true;
}

static int bridge_mdb_process_request(Request *req, Link *link, void *userdata) {
        BridgeMDB *mdb = ASSERT_PTR(userdata);
        int r;

        assert(req);
        assert(link);

        if (!bridge_mdb_is_ready_to_configure(link))
                return 0;

        r = bridge_mdb_configure(mdb, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure bridge MDB: %m");

        return 1;
}

int link_request_static_bridge_mdb(Link *link) {
        BridgeMDB *mdb;
        int r;

        assert(link);
        assert(link->manager);

        link->static_bridge_mdb_configured = false;

        if (!link->network)
                return 0;

        if (hashmap_isempty(link->network->bridge_mdb_entries_by_section))
                goto finish;

        HASHMAP_FOREACH(mdb, link->network->bridge_mdb_entries_by_section) {
                r = link_queue_request_full(link, REQUEST_TYPE_BRIDGE_MDB,
                                            mdb, NULL,
                                            trivial_hash_func,
                                            trivial_compare_func,
                                            bridge_mdb_process_request,
                                            &link->static_bridge_mdb_messages,
                                            bridge_mdb_configure_handler,
                                            NULL);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to request MDB entry to multicast group database: %m");
        }

finish:
        if (link->static_bridge_mdb_messages == 0) {
                link->static_bridge_mdb_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting bridge MDB entries.");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int bridge_mdb_verify(BridgeMDB *mdb) {
        if (section_is_invalid(mdb->section))
                return -EINVAL;

        if (mdb->family == AF_UNSPEC)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [BridgeMDB] section without MulticastGroupAddress= field configured. "
                                         "Ignoring [BridgeMDB] section from line %u.",
                                         mdb->section->filename, mdb->section->line);

        if (!in_addr_is_multicast(mdb->family, &mdb->group_addr))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: MulticastGroupAddress= is not a multicast address. "
                                         "Ignoring [BridgeMDB] section from line %u.",
                                         mdb->section->filename, mdb->section->line);

        if (mdb->family == AF_INET) {
                if (in4_addr_is_local_multicast(&mdb->group_addr.in))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: MulticastGroupAddress= is a local multicast address. "
                                                 "Ignoring [BridgeMDB] section from line %u.",
                                                 mdb->section->filename, mdb->section->line);
        } else {
                if (in6_addr_is_link_local_all_nodes(&mdb->group_addr.in6))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: MulticastGroupAddress= is the multicast all nodes address. "
                                                 "Ignoring [BridgeMDB] section from line %u.",
                                                 mdb->section->filename, mdb->section->line);
        }

        return 0;
}

void network_drop_invalid_bridge_mdb_entries(Network *network) {
        BridgeMDB *mdb;

        assert(network);

        HASHMAP_FOREACH(mdb, network->bridge_mdb_entries_by_section)
                if (bridge_mdb_verify(mdb) < 0)
                        bridge_mdb_free(mdb);
}

/* parse the VLAN Id from config files. */
int config_parse_mdb_vlan_id(
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

        _cleanup_(bridge_mdb_free_or_set_invalidp) BridgeMDB *mdb = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_mdb_new_static(network, filename, section_line, &mdb);
        if (r < 0)
                return log_oom();

        r = config_parse_vlanid(unit, filename, line, section,
                                section_line, lvalue, ltype,
                                rvalue, &mdb->vlan_id, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(mdb);
        return 0;
}

/* parse the multicast group from config files. */
int config_parse_mdb_group_address(
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

        _cleanup_(bridge_mdb_free_or_set_invalidp) BridgeMDB *mdb = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = bridge_mdb_new_static(network, filename, section_line, &mdb);
        if (r < 0)
                return log_oom();

        r = in_addr_from_string_auto(rvalue, &mdb->family, &mdb->group_addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Cannot parse multicast group address: %m");
                return 0;
        }

        TAKE_PTR(mdb);
        return 0;
}

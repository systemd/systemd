/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-mdb.h"
#include "networkd-network.h"
#include "string-util.h"
#include "vlan-util.h"

#define STATIC_MDB_ENTRIES_PER_NETWORK_MAX 1024U

/* remove MDB entry. */
MdbEntry *mdb_entry_free(MdbEntry *mdb_entry) {
        if (!mdb_entry)
                return NULL;

        if (mdb_entry->network) {
                assert(mdb_entry->section);
                hashmap_remove(mdb_entry->network->mdb_entries_by_section, mdb_entry->section);
        }

        network_config_section_free(mdb_entry->section);

        return mfree(mdb_entry);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(MdbEntry, mdb_entry_free);

/* create a new MDB entry or get an existing one. */
static int mdb_entry_new_static(
                Network *network,
                const char *filename,
                unsigned section_line,
                MdbEntry **ret) {

        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(mdb_entry_freep) MdbEntry *mdb_entry = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        /* search entry in hashmap first. */
        mdb_entry = hashmap_get(network->mdb_entries_by_section, n);
        if (mdb_entry) {
                *ret = TAKE_PTR(mdb_entry);
                return 0;
        }

        if (hashmap_size(network->mdb_entries_by_section) >= STATIC_MDB_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        /* allocate space for an MDB entry. */
        mdb_entry = new(MdbEntry, 1);
        if (!mdb_entry)
                return -ENOMEM;

        /* init MDB structure. */
        *mdb_entry = (MdbEntry) {
                .network = network,
                .section = TAKE_PTR(n),
        };

        r = hashmap_ensure_put(&network->mdb_entries_by_section, &network_config_hash_ops, mdb_entry->section, mdb_entry);
        if (r < 0)
                return r;

        /* return allocated MDB structure. */
        *ret = TAKE_PTR(mdb_entry);
        return 0;
}

static int set_mdb_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->bridge_mdb_messages > 0);

        link->bridge_mdb_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r == -EINVAL && streq_ptr(link->kind, "bridge") && (!link->network || !link->network->bridge)) {
                /* To configure bridge MDB entries on bridge master, 1bc844ee0faa1b92e3ede00bdd948021c78d7088 (v5.4) is required. */
                if (!link->manager->bridge_mdb_on_master_not_supported) {
                        log_link_warning_errno(link, r, "Kernel seems not to support configuring bridge MDB entries on bridge master, ignoring: %m");
                        link->manager->bridge_mdb_on_master_not_supported = true;
                }
        } else if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add MDB entry");
                link_enter_failed(link);
                return 1;
        }

        if (link->bridge_mdb_messages == 0) {
                link->bridge_mdb_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_get_bridge_master_ifindex(Link *link) {
        assert(link);

        if (link->network && link->network->bridge)
                return link->network->bridge->ifindex;

        if (streq_ptr(link->kind, "bridge"))
                return link->ifindex;

        return 0;
}

/* send a request to the kernel to add an MDB entry */
static int mdb_entry_configure(Link *link, MdbEntry *mdb_entry) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        struct br_mdb_entry entry;
        int master, r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(mdb_entry);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *a = NULL;

                (void) in_addr_to_string(mdb_entry->family, &mdb_entry->group_addr, &a);
                log_link_debug(link, "Configuring bridge MDB entry: MulticastGroupAddress=%s, VLANId=%u",
                               strna(a), mdb_entry->vlan_id);
        }

        master = link_get_bridge_master_ifindex(link);
        if (master <= 0)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(EINVAL), "Invalid bridge master ifindex %i", master);

        entry = (struct br_mdb_entry) {
                /* If MDB entry is added on bridge master, then the state must be MDB_TEMPORARY.
                 * See br_mdb_add_group() in net/bridge/br_mdb.c of kernel. */
                .state = master == link->ifindex ? MDB_TEMPORARY : MDB_PERMANENT,
                .ifindex = link->ifindex,
                .vid = mdb_entry->vlan_id,
        };

        /* create new RTM message */
        r = sd_rtnl_message_new_mdb(link->manager->rtnl, &req, RTM_NEWMDB, master);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWMDB message: %m");

        switch (mdb_entry->family) {
        case AF_INET:
                entry.addr.u.ip4 = mdb_entry->group_addr.in.s_addr;
                entry.addr.proto = htobe16(ETH_P_IP);
                break;

        case AF_INET6:
                entry.addr.u.ip6 = mdb_entry->group_addr.in6;
                entry.addr.proto = htobe16(ETH_P_IPV6);
                break;

        default:
                assert_not_reached("Invalid address family");
        }

        r = sd_netlink_message_append_data(req, MDBA_SET_ENTRY, &entry, sizeof(entry));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append MDBA_SET_ENTRY attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, set_mdb_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 1;
}

int link_set_bridge_mdb(Link *link) {
        MdbEntry *mdb_entry;
        int r;

        assert(link);
        assert(link->manager);

        if (link->bridge_mdb_messages != 0) {
                log_link_debug(link, "MDB entries are configuring.");
                return 0;
        }

        link->bridge_mdb_configured = false;

        if (!link->network)
                return 0;

        if (hashmap_isempty(link->network->mdb_entries_by_section))
                goto finish;

        if (!link_has_carrier(link))
                return log_link_debug(link, "Link does not have carrier yet, setting MDB entries later.");

        if (link->network->bridge) {
                Link *master;

                r = link_get(link->manager, link->network->bridge->ifindex, &master);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to get Link object for Bridge=%s", link->network->bridge->ifname);

                if (!link_has_carrier(master))
                        return log_link_debug(link, "Bridge interface %s does not have carrier yet, setting MDB entries later.", link->network->bridge->ifname);

        } else if (!streq_ptr(link->kind, "bridge")) {
                log_link_warning(link, "Link is neither a bridge master nor a bridge port, ignoring [BridgeMDB] sections.");
                goto finish;
        } else if (link->manager->bridge_mdb_on_master_not_supported) {
                log_link_debug(link, "Kernel seems not to support configuring bridge MDB entries on bridge master, ignoring [BridgeMDB] sections.");
                goto finish;
        }

        HASHMAP_FOREACH(mdb_entry, link->network->mdb_entries_by_section) {
                r = mdb_entry_configure(link, mdb_entry);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to add MDB entry to multicast group database: %m");

                link->bridge_mdb_messages++;
        }

finish:
        if (link->bridge_mdb_messages == 0) {
                link->bridge_mdb_configured = true;
                link_check_ready(link);
        }

        return 0;
}

static int mdb_entry_verify(MdbEntry *mdb_entry) {
        if (section_is_invalid(mdb_entry->section))
                return -EINVAL;

        if (mdb_entry->family == AF_UNSPEC)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [BridgeMDB] section without MulticastGroupAddress= field configured. "
                                         "Ignoring [BridgeMDB] section from line %u.",
                                         mdb_entry->section->filename, mdb_entry->section->line);

        if (!in_addr_is_multicast(mdb_entry->family, &mdb_entry->group_addr))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: MulticastGroupAddress= is not a multicast address. "
                                         "Ignoring [BridgeMDB] section from line %u.",
                                         mdb_entry->section->filename, mdb_entry->section->line);

        if (mdb_entry->family == AF_INET) {
                if (in4_addr_is_local_multicast(&mdb_entry->group_addr.in))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: MulticastGroupAddress= is a local multicast address. "
                                                 "Ignoring [BridgeMDB] section from line %u.",
                                                 mdb_entry->section->filename, mdb_entry->section->line);
        } else {
                if (in6_addr_is_link_local_all_nodes(&mdb_entry->group_addr.in6))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: MulticastGroupAddress= is the multicast all nodes address. "
                                                 "Ignoring [BridgeMDB] section from line %u.",
                                                 mdb_entry->section->filename, mdb_entry->section->line);
        }

        return 0;
}

void network_drop_invalid_mdb_entries(Network *network) {
        MdbEntry *mdb_entry;

        assert(network);

        HASHMAP_FOREACH(mdb_entry, network->mdb_entries_by_section)
                if (mdb_entry_verify(mdb_entry) < 0)
                        mdb_entry_free(mdb_entry);
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

        _cleanup_(mdb_entry_free_or_set_invalidp) MdbEntry *mdb_entry = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = mdb_entry_new_static(network, filename, section_line, &mdb_entry);
        if (r < 0)
                return log_oom();

        r = config_parse_vlanid(unit, filename, line, section,
                                section_line, lvalue, ltype,
                                rvalue, &mdb_entry->vlan_id, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(mdb_entry);
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

        _cleanup_(mdb_entry_free_or_set_invalidp) MdbEntry *mdb_entry = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = mdb_entry_new_static(network, filename, section_line, &mdb_entry);
        if (r < 0)
                return log_oom();

        r = in_addr_from_string_auto(rvalue, &mdb_entry->family, &mdb_entry->group_addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Cannot parse multicast group address: %m");
                return 0;
        }

        TAKE_PTR(mdb_entry);
        return 0;
}

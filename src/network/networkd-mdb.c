/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-mdb.h"
#include "vlan-util.h"

#define STATIC_MDB_ENTRIES_PER_NETWORK_MAX 1024U

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
        assert(!!filename == (section_line > 0));

        /* search entry in hashmap first. */
        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                mdb_entry = hashmap_get(network->mdb_entries_by_section, n);
                if (mdb_entry) {
                        *ret = TAKE_PTR(mdb_entry);
                        return 0;
                }
        }

        if (network->n_static_mdb_entries >= STATIC_MDB_ENTRIES_PER_NETWORK_MAX)
                return -E2BIG;

        /* allocate space for an MDB entry. */
        mdb_entry = new(MdbEntry, 1);
        if (!mdb_entry)
                return -ENOMEM;

        /* init MDB structure. */
        *mdb_entry = (MdbEntry) {
                .network = network,
        };

        LIST_PREPEND(static_mdb_entries, network->static_mdb_entries, mdb_entry);
        network->n_static_mdb_entries++;

        if (filename) {
                mdb_entry->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->mdb_entries_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->mdb_entries_by_section, mdb_entry->section, mdb_entry);
                if (r < 0)
                        return r;
        }

        /* return allocated MDB structure. */
        *ret = TAKE_PTR(mdb_entry);

        return 0;
}

/* remove and MDB entry. */
MdbEntry *mdb_entry_free(MdbEntry *mdb_entry) {
        if (!mdb_entry)
                return NULL;

        if (mdb_entry->network) {
                LIST_REMOVE(static_mdb_entries, mdb_entry->network->static_mdb_entries, mdb_entry);
                assert(mdb_entry->network->n_static_mdb_entries > 0);
                mdb_entry->network->n_static_mdb_entries--;

                if (mdb_entry->section)
                        hashmap_remove(mdb_entry->network->mdb_entries_by_section, mdb_entry->section);
        }

        network_config_section_free(mdb_entry->section);

        return mfree(mdb_entry);
}

static int set_mdb_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add MDB entry");
                link_enter_failed(link);
                return 1;
        }

        return 1;
}

/* send a request to the kernel to add an MDB entry */
int mdb_entry_configure(Link *link, MdbEntry *mdb_entry) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        struct br_mdb_entry entry;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(mdb_entry);

        entry = (struct br_mdb_entry) {
                .state = MDB_PERMANENT,
                .ifindex = link->ifindex,
                .vid = mdb_entry->vlan_id,
        };

        /* create new RTM message */
        r = sd_rtnl_message_new_mdb(link->manager->rtnl, &req, RTM_NEWMDB, link->network->bridge->ifindex);
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

        mdb_entry = NULL;

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

        mdb_entry = NULL;

        return 0;
}

int mdb_entry_verify(MdbEntry *mdb_entry) {
        if (section_is_invalid(mdb_entry->section))
                return -EINVAL;

        if (in_addr_is_multicast(mdb_entry->family, &mdb_entry->group_addr) <= 0) {
                log_error("No valid MulticastGroupAddress= assignment in this section");
                return -EINVAL;
        }

        return 0;
}

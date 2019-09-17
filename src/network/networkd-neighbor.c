/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "set.h"

void neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return;

        if (neighbor->network) {
                LIST_REMOVE(neighbors, neighbor->network->neighbors, neighbor);
                assert(neighbor->network->n_neighbors > 0);
                neighbor->network->n_neighbors--;

                if (neighbor->section)
                        hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
        }

        network_config_section_free(neighbor->section);

        if (neighbor->link) {
                set_remove(neighbor->link->neighbors, neighbor);
                set_remove(neighbor->link->neighbors_foreign, neighbor);
        }

        free(neighbor);
}

static int neighbor_new_static(Network *network, const char *filename, unsigned section_line, Neighbor **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(neighbor_freep) Neighbor *neighbor = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                neighbor = hashmap_get(network->neighbors_by_section, n);
                if (neighbor) {
                        *ret = TAKE_PTR(neighbor);

                        return 0;
                }
        }

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .network = network,
                .family = AF_UNSPEC,
        };

        LIST_APPEND(neighbors, network->neighbors, neighbor);
        network->n_neighbors++;

        if (filename) {
                neighbor->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->neighbors_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->neighbors_by_section, neighbor->section, neighbor);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(neighbor);

        return 0;
}

static int neighbor_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->neighbor_messages > 0);

        link->neighbor_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                /* Neighbor may not exist yet. So, do not enter failed state here. */
                log_link_warning_errno(link, r, "Could not set neighbor, ignoring: %m");

        if (link->neighbor_messages == 0) {
                log_link_debug(link, "Neighbors set");
                link->neighbors_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int neighbor_configure(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH,
                                          link->ifindex, neighbor->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_state(req, NUD_PERMANENT);
        if (r < 0)
                return log_error_errno(r, "Could not set state: %m");

        r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Could not set flags: %m");

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &neighbor->lladdr, neighbor->lladdr_size);
        if (r < 0)
                return log_error_errno(r, "Could not append NDA_LLADDR attribute: %m");

        r = netlink_message_append_in_addr_union(req, NDA_DST, neighbor->family, &neighbor->in_addr);
        if (r < 0)
                return log_error_errno(r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback ?: neighbor_configure_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link->neighbor_messages++;
        link_ref(link);

        r = neighbor_add(link, neighbor->family, &neighbor->in_addr, &neighbor->lladdr, neighbor->lladdr_size, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add neighbor: %m");

        return 0;
}

static int neighbor_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                /* Neighbor may not exist because it already got deleted, ignore that. */
                log_link_warning_errno(link, r, "Could not remove neighbor: %m");

        return 1;
}

int neighbor_remove(Neighbor *neighbor, Link *link, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_DELNEIGH,
                                          link->ifindex, neighbor->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_DELNEIGH message: %m");

        r = netlink_message_append_in_addr_union(req, NDA_DST, neighbor->family, &neighbor->in_addr);
        if (r < 0)
                return log_error_errno(r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback ?: neighbor_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state) {
        assert(neighbor);

        siphash24_compress(&neighbor->family, sizeof(neighbor->family), state);
        siphash24_compress(&neighbor->lladdr_size, sizeof(neighbor->lladdr_size), state);

        switch (neighbor->family) {
        case AF_INET:
        case AF_INET6:
                /* Equality of neighbors are given by the pair (addr,lladdr) */
                siphash24_compress(&neighbor->in_addr, FAMILY_ADDRESS_SIZE(neighbor->family), state);
                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }

        siphash24_compress(&neighbor->lladdr, neighbor->lladdr_size, state);
}

static int neighbor_compare_func(const Neighbor *a, const Neighbor *b) {
        int r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        r = CMP(a->lladdr_size, b->lladdr_size);
        if (r != 0)
                return r;

        switch (a->family) {
        case AF_INET:
        case AF_INET6:
                r = memcmp(&a->in_addr, &b->in_addr, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;
        }

        return memcmp(&a->lladdr, &b->lladdr, a->lladdr_size);
}

DEFINE_PRIVATE_HASH_OPS(neighbor_hash_ops, Neighbor, neighbor_hash_func, neighbor_compare_func);

int neighbor_get(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret) {
        Neighbor neighbor, *existing;

        assert(link);
        assert(addr);
        assert(lladdr);

        neighbor = (Neighbor) {
                .family = family,
                .in_addr = *addr,
                .lladdr = *lladdr,
                .lladdr_size = lladdr_size,
        };

        existing = set_get(link->neighbors, &neighbor);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link->neighbors_foreign, &neighbor);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static int neighbor_add_internal(Link *link, Set **neighbors, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret) {
        _cleanup_(neighbor_freep) Neighbor *neighbor = NULL;
        int r;

        assert(link);
        assert(neighbors);
        assert(addr);
        assert(lladdr);

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .family = family,
                .in_addr = *addr,
                .lladdr = *lladdr,
                .lladdr_size = lladdr_size,
        };

        r = set_ensure_allocated(neighbors, &neighbor_hash_ops);
        if (r < 0)
                return r;

        r = set_put(*neighbors, neighbor);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        neighbor->link = link;

        if (ret)
                *ret = neighbor;

        neighbor = NULL;

        return 0;
}

int neighbor_add(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret) {
        Neighbor *neighbor;
        int r;

        r = neighbor_get(link, family, addr, lladdr, lladdr_size, &neighbor);
        if (r == -ENOENT) {
                /* Neighbor doesn't exist, make a new one */
                r = neighbor_add_internal(link, &link->neighbors, family, addr, lladdr, lladdr_size, &neighbor);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Neighbor is foreign, claim it as recognized */
                r = set_ensure_allocated(&link->neighbors, &neighbor_hash_ops);
                if (r < 0)
                        return r;

                r = set_put(link->neighbors, neighbor);
                if (r < 0)
                        return r;

                set_remove(link->neighbors_foreign, neighbor);
        } else if (r == 1) {
                /* Neighbor already exists */
        } else
                return r;

        if (ret)
                *ret = neighbor;
        return 0;
}

int neighbor_add_foreign(Link *link, int family, const union in_addr_union *addr, const union lladdr_union *lladdr, size_t lladdr_size, Neighbor **ret) {
        return neighbor_add_internal(link, &link->neighbors_foreign, family, addr, lladdr, lladdr_size, ret);
}

bool neighbor_equal(const Neighbor *n1, const Neighbor *n2) {
        if (n1 == n2)
                return true;

        if (!n1 || !n2)
                return false;

        return neighbor_compare_func(n1, n2) == 0;
}

int neighbor_section_verify(Neighbor *neighbor) {
        if (section_is_invalid(neighbor->section))
                return -EINVAL;

        if (neighbor->family == AF_UNSPEC)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Neighbor section without Address= configured. "
                                         "Ignoring [Neighbor] section from line %u.",
                                         neighbor->section->filename, neighbor->section->line);

        if (neighbor->lladdr_size == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Neighbor section without LinkLayerAddress= configured. "
                                         "Ignoring [Neighbor] section from line %u.",
                                         neighbor->section->filename, neighbor->section->line);

        return 0;
}

int config_parse_neighbor_address(
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
        _cleanup_(neighbor_free_or_set_invalidp) Neighbor *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = neighbor_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(rvalue, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Neighbor Address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);

        return 0;
}

int config_parse_neighbor_lladdr(
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
        _cleanup_(neighbor_free_or_set_invalidp) Neighbor *n = NULL;
        int family, r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = neighbor_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = ether_addr_from_string(rvalue, &n->lladdr.mac);
        if (r >= 0)
                n->lladdr_size = sizeof(n->lladdr.mac);
        else {
                r = in_addr_from_string_auto(rvalue, &family, &n->lladdr.ip);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Neighbor LinkLayerAddress= is invalid, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
                n->lladdr_size = family == AF_INET ? sizeof(n->lladdr.ip.in) : sizeof(n->lladdr.ip.in6);
        }

        TAKE_PTR(n);

        return 0;
}

int config_parse_neighbor_hwaddr(
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
        _cleanup_(neighbor_free_or_set_invalidp) Neighbor *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = neighbor_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = ether_addr_from_string(rvalue, &n->lladdr.mac);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Neighbor MACAddress= is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->lladdr_size = sizeof(n->lladdr.mac);
        TAKE_PTR(n);

        return 0;
}

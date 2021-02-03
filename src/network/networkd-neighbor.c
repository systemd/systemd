/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "set.h"

Neighbor *neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return NULL;

        if (neighbor->network) {
                assert(neighbor->section);
                hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
        }

        network_config_section_free(neighbor->section);

        if (neighbor->link) {
                set_remove(neighbor->link->neighbors, neighbor);
                set_remove(neighbor->link->neighbors_foreign, neighbor);
        }

        return mfree(neighbor);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(Neighbor, neighbor_free);

static int neighbor_new_static(Network *network, const char *filename, unsigned section_line, Neighbor **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(neighbor_freep) Neighbor *neighbor = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        neighbor = hashmap_get(network->neighbors_by_section, n);
        if (neighbor) {
                *ret = TAKE_PTR(neighbor);
                return 0;
        }

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .network = network,
                .family = AF_UNSPEC,
                .section = TAKE_PTR(n),
        };

        r = hashmap_ensure_put(&network->neighbors_by_section, &network_config_hash_ops, neighbor->section, neighbor);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(neighbor);
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

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(neighbor_hash_ops, Neighbor, neighbor_hash_func, neighbor_compare_func, neighbor_free);

static int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret) {
        Neighbor *existing;

        assert(link);
        assert(in);

        existing = set_get(link->neighbors, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link->neighbors_foreign, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static int neighbor_add_internal(Link *link, Set **neighbors, const Neighbor *in, Neighbor **ret) {
        _cleanup_(neighbor_freep) Neighbor *neighbor = NULL;
        int r;

        assert(link);
        assert(neighbors);
        assert(in);

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .family = in->family,
                .in_addr = in->in_addr,
                .lladdr = in->lladdr,
                .lladdr_size = in->lladdr_size,
        };

        r = set_ensure_put(neighbors, &neighbor_hash_ops, neighbor);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        neighbor->link = link;

        if (ret)
                *ret = neighbor;

        TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_add(Link *link, const Neighbor *in, Neighbor **ret) {
        bool is_new = false;
        Neighbor *neighbor;
        int r;

        r = neighbor_get(link, in, &neighbor);
        if (r == -ENOENT) {
                /* Neighbor doesn't exist, make a new one */
                r = neighbor_add_internal(link, &link->neighbors, in, &neighbor);
                if (r < 0)
                        return r;
                is_new = true;
        } else if (r == 0) {
                /* Neighbor is foreign, claim it as recognized */
                r = set_ensure_put(&link->neighbors, &neighbor_hash_ops, neighbor);
                if (r < 0)
                        return r;

                set_remove(link->neighbors_foreign, neighbor);
        } else if (r == 1) {
                /* Neighbor already exists */
                ;
        } else
                return r;

        if (ret)
                *ret = neighbor;
        return is_new;
}

static int neighbor_add_foreign(Link *link, const Neighbor *in, Neighbor **ret) {
        return neighbor_add_internal(link, &link->neighbors_foreign, in, ret);
}

static bool neighbor_equal(const Neighbor *n1, const Neighbor *n2) {
        if (n1 == n2)
                return true;

        if (!n1 || !n2)
                return false;

        return neighbor_compare_func(n1, n2) == 0;
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
                log_link_message_warning_errno(link, m, r, "Could not set neighbor, ignoring");

        if (link->neighbor_messages == 0) {
                log_link_debug(link, "Neighbors set");
                link->neighbors_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int neighbor_configure(Neighbor *neighbor, Link *link) {
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
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_state(req, NUD_PERMANENT);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set state: %m");

        r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set flags: %m");

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &neighbor->lladdr, neighbor->lladdr_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_LLADDR attribute: %m");

        r = netlink_message_append_in_addr_union(req, NDA_DST, neighbor->family, &neighbor->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, neighbor_configure_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link->neighbor_messages++;
        link_ref(link);

        r = neighbor_add(link, neighbor, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add neighbor: %m");

        return r;
}

int link_set_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        if (link->neighbor_messages != 0) {
                log_link_debug(link, "Neighbors are configuring.");
                return 0;
        }

        link->neighbors_configured = false;

        HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                r = neighbor_configure(neighbor, link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set neighbor: %m");
        }

        if (link->neighbor_messages == 0) {
                link->neighbors_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting neighbors");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

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
                log_link_message_warning_errno(link, m, r, "Could not remove neighbor");

        return 1;
}

static int neighbor_remove(Neighbor *neighbor, Link *link) {
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
                return log_link_error_errno(link, r, "Could not allocate RTM_DELNEIGH message: %m");

        r = netlink_message_append_in_addr_union(req, NDA_DST, neighbor->family, &neighbor->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, neighbor_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static bool link_is_neighbor_configured(Link *link, Neighbor *neighbor) {
        Neighbor *net_neighbor;

        assert(link);
        assert(neighbor);

        if (!link->network)
                return false;

        HASHMAP_FOREACH(net_neighbor, link->network->neighbors_by_section)
                if (neighbor_equal(net_neighbor, neighbor))
                        return true;

        return false;
}

int link_drop_foreign_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);

        SET_FOREACH(neighbor, link->neighbors_foreign)
                if (link_is_neighbor_configured(link, neighbor)) {
                        r = neighbor_add(link, neighbor, NULL);
                        if (r < 0)
                                return r;
                } else {
                        r = neighbor_remove(neighbor, link);
                        if (r < 0)
                                return r;
                }

        return 0;
}

int link_drop_neighbors(Link *link) {
        Neighbor *neighbor;
        int k, r = 0;

        assert(link);

        SET_FOREACH(neighbor, link->neighbors) {
                k = neighbor_remove(neighbor, link);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int manager_rtnl_process_neighbor_lladdr(sd_netlink_message *message, union lladdr_union *lladdr, size_t *size, char **str) {
        int r;

        assert(message);
        assert(lladdr);
        assert(size);
        assert(str);

        *str = NULL;

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->ip.in6), &lladdr->ip.in6);
        if (r >= 0) {
                *size = sizeof(lladdr->ip.in6);
                if (in_addr_to_string(AF_INET6, &lladdr->ip, str) < 0)
                        log_warning_errno(r, "Could not print lower address: %m");
                return r;
        }

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->mac), &lladdr->mac);
        if (r >= 0) {
                *size = sizeof(lladdr->mac);
                *str = new(char, ETHER_ADDR_TO_STRING_MAX);
                if (!*str) {
                        log_oom();
                        return r;
                }
                ether_addr_to_string(&lladdr->mac, *str);
                return r;
        }

        r = sd_netlink_message_read(message, NDA_LLADDR, sizeof(lladdr->ip.in), &lladdr->ip.in);
        if (r >= 0) {
                *size = sizeof(lladdr->ip.in);
                if (in_addr_to_string(AF_INET, &lladdr->ip, str) < 0)
                        log_warning_errno(r, "Could not print lower address: %m");
                return r;
        }

        return r;
}

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(neighbor_freep) Neighbor *tmp = NULL;
        _cleanup_free_ char *addr_str = NULL, *lladdr_str = NULL;
        Neighbor *neighbor = NULL;
        uint16_t type, state;
        int ifindex, r;
        Link *link;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive neighbor message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEIGH, RTM_DELNEIGH)) {
                log_warning("rtnl: received unexpected message type %u when processing neighbor, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_neigh_get_state(message, &state);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received neighbor message with invalid state, ignoring: %m");
                return 0;
        } else if (!FLAGS_SET(state, NUD_PERMANENT)) {
                log_debug("rtnl: received non-static neighbor, ignoring.");
                return 0;
        }

        r = sd_rtnl_message_neigh_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received neighbor message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will get the neighbor again, so just
                 * ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received neighbor for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        tmp = new0(Neighbor, 1);

        r = sd_rtnl_message_neigh_get_family(message, &tmp->family);
        if (r < 0) {
                log_link_warning(link, "rtnl: received neighbor message without family, ignoring.");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_link_debug(link, "rtnl: received neighbor message with invalid family '%i', ignoring.", tmp->family);
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, NDA_DST, tmp->family, &tmp->in_addr);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                return 0;
        }

        if (in_addr_to_string(tmp->family, &tmp->in_addr, &addr_str) < 0)
                log_link_warning_errno(link, r, "Could not print address: %m");

        r = manager_rtnl_process_neighbor_lladdr(message, &tmp->lladdr, &tmp->lladdr_size, &lladdr_str);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message with invalid lladdr, ignoring: %m");
                return 0;
        }

        (void) neighbor_get(link, tmp, &neighbor);

        switch (type) {
        case RTM_NEWNEIGH:
                if (neighbor)
                        log_link_debug(link, "Received remembered neighbor: %s->%s",
                                       strnull(addr_str), strnull(lladdr_str));
                else {
                        /* A neighbor appeared that we did not request */
                        r = neighbor_add_foreign(link, tmp, NULL);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign neighbor %s->%s, ignoring: %m",
                                                       strnull(addr_str), strnull(lladdr_str));
                                return 0;
                        } else
                                log_link_debug(link, "Remembering foreign neighbor: %s->%s",
                                               strnull(addr_str), strnull(lladdr_str));
                }

                break;

        case RTM_DELNEIGH:
                if (neighbor) {
                        log_link_debug(link, "Forgetting neighbor: %s->%s",
                                       strnull(addr_str), strnull(lladdr_str));
                        (void) neighbor_free(neighbor);
                } else
                        log_link_debug(link, "Kernel removed a neighbor we don't remember: %s->%s, ignoring.",
                                       strnull(addr_str), strnull(lladdr_str));

                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static int neighbor_section_verify(Neighbor *neighbor) {
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

void network_drop_invalid_neighbors(Network *network) {
        Neighbor *neighbor;

        assert(network);

        HASHMAP_FOREACH(neighbor, network->neighbors_by_section)
                if (neighbor_section_verify(neighbor) < 0)
                        neighbor_free(neighbor);
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
                return log_oom();

        r = in_addr_from_string_auto(rvalue, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Neighbor Address is invalid, ignoring assignment: %s", rvalue);
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
                return log_oom();

        r = ether_addr_from_string(rvalue, &n->lladdr.mac);
        if (r >= 0)
                n->lladdr_size = sizeof(n->lladdr.mac);
        else {
                r = in_addr_from_string_auto(rvalue, &family, &n->lladdr.ip);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
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
                return log_oom();

        r = ether_addr_from_string(rvalue, &n->lladdr.mac);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Neighbor MACAddress= is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->lladdr_size = sizeof(n->lladdr.mac);
        TAKE_PTR(n);

        return 0;
}

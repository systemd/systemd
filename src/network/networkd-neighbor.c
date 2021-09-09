/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "set.h"

Neighbor *neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return NULL;

        if (neighbor->network) {
                assert(neighbor->section);
                hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
        }

        network_config_section_free(neighbor->section);

        if (neighbor->link)
                set_remove(neighbor->link->neighbors, neighbor);

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
                .source = NETWORK_CONFIG_SOURCE_STATIC,
        };

        r = hashmap_ensure_put(&network->neighbors_by_section, &network_config_hash_ops, neighbor->section, neighbor);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_dup(const Neighbor *neighbor, Neighbor **ret) {
        _cleanup_(neighbor_freep) Neighbor *dest = NULL;

        assert(neighbor);
        assert(ret);

        dest = newdup(Neighbor, neighbor, 1);
        if (!dest)
                return -ENOMEM;

        /* Unset all pointers */
        dest->link = NULL;
        dest->network = NULL;
        dest->section = NULL;

        *ret = TAKE_PTR(dest);
        return 0;
}

void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state) {
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

int neighbor_compare_func(const Neighbor *a, const Neighbor *b) {
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
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

static int neighbor_add(Link *link, Neighbor *neighbor) {
        int r;

        assert(link);
        assert(neighbor);

        r = set_ensure_put(&link->neighbors, &neighbor_hash_ops, neighbor);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        neighbor->link = link;
        return 0;
}

static void log_neighbor_debug(const Neighbor *neighbor, const char *str, const Link *link) {
        _cleanup_free_ char *state = NULL, *lladdr = NULL, *dst = NULL;

        assert(neighbor);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(neighbor->state, &state);
        if (neighbor->lladdr_size == sizeof(struct ether_addr))
                (void) ether_addr_to_string_alloc(&neighbor->lladdr.mac, &lladdr);
        else if (neighbor->lladdr_size == sizeof(struct in_addr))
                (void) in_addr_to_string(AF_INET, &neighbor->lladdr.ip, &lladdr);
        else if (neighbor->lladdr_size == sizeof(struct in6_addr))
                (void) in_addr_to_string(AF_INET6, &neighbor->lladdr.ip, &lladdr);

        (void) in_addr_to_string(neighbor->family, &neighbor->in_addr, &dst);

        log_link_debug(link,
                       "%s %s neighbor (%s): lladdr: %s, dst: %s",
                       str, strna(network_config_source_to_string(neighbor->source)), strna(state),
                       strna(lladdr), strna(dst));
}

static int neighbor_configure(
                Neighbor *neighbor,
                Link *link,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(callback);

        log_neighbor_debug(neighbor, "Configuring", link);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH,
                                      link->ifindex, neighbor->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_state(req, NUD_PERMANENT);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set state: %m");

        r = sd_netlink_message_append_data(req, NDA_LLADDR, &neighbor->lladdr, neighbor->lladdr_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_LLADDR attribute: %m");

        r = netlink_message_append_in_addr_union(req, NDA_DST, neighbor->family, &neighbor->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        neighbor_enter_configuring(neighbor);
        return r;
}

static int static_neighbor_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->static_neighbor_messages > 0);

        link->static_neighbor_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set neighbor");
                link_enter_failed(link);
                return 1;
        }

        if (link->static_neighbor_messages == 0) {
                log_link_debug(link, "Neighbors set");
                link->static_neighbors_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_request_neighbor(
                Link *link,
                const Neighbor *neighbor,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        Neighbor *existing;
        int r;

        assert(link);
        assert(neighbor);
        assert(neighbor->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (neighbor_get(link, neighbor, &existing) < 0) {
                _cleanup_(neighbor_freep) Neighbor *tmp = NULL;

                r = neighbor_dup(neighbor, &tmp);
                if (r < 0)
                        return r;

                r = neighbor_add(link, tmp);
                if (r < 0)
                        return r;

                existing = TAKE_PTR(tmp);
        } else
                existing->source = neighbor->source;

        log_neighbor_debug(existing, "Requesting", link);
        r = link_queue_request(link, REQUEST_TYPE_NEIGHBOR, existing, false,
                               message_counter, netlink_handler, ret);
        if (r <= 0)
                return r;

        neighbor_enter_requesting(existing);
        return 1;
}

int link_request_static_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->static_neighbors_configured = false;

        HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                r = link_request_neighbor(link, neighbor, &link->static_neighbor_messages,
                                          static_neighbor_configure_handler, NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request neighbor: %m");
        }

        if (link->static_neighbor_messages == 0) {
                link->static_neighbors_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Requesting neighbors");
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

static int neighbor_remove(Neighbor *neighbor) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        Link *link;
        int r;

        assert(neighbor);
        assert(neighbor->link);
        assert(neighbor->link->manager);
        assert(neighbor->link->manager->rtnl);

        link = neighbor->link;

        log_neighbor_debug(neighbor, "Removing", link);

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

        neighbor_enter_removing(neighbor);
        return 0;
}

int link_drop_foreign_neighbors(Link *link) {
        Neighbor *neighbor;
        int k, r = 0;

        assert(link);
        assert(link->network);

        /* First, mark all neighbors. */
        SET_FOREACH(neighbor, link->neighbors) {
                /* Do not remove neighbors we configured. */
                if (neighbor->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                neighbor_mark(neighbor);
        }

        /* Next, unmark requested neighbors. They will be configured later. */
        HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                Neighbor *existing;

                if (neighbor_get(link, neighbor, &existing) >= 0)
                        neighbor_unmark(existing);
        }

        SET_FOREACH(neighbor, link->neighbors) {
                if (!neighbor_is_marked(neighbor))
                        continue;

                k = neighbor_remove(neighbor);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

int link_drop_neighbors(Link *link) {
        Neighbor *neighbor;
        int k, r = 0;

        assert(link);

        SET_FOREACH(neighbor, link->neighbors) {
                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                k = neighbor_remove(neighbor);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

int request_process_neighbor(Request *req) {
        int r;

        assert(req);
        assert(req->link);
        assert(req->neighbor);
        assert(req->type == REQUEST_TYPE_NEIGHBOR);

        if (!link_is_ready_to_configure(req->link, false))
                return 0;

        r = neighbor_configure(req->neighbor, req->link, req->netlink_handler);
        if (r < 0)
                return r;

        return 1;
}

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(neighbor_freep) Neighbor *tmp = NULL;
        _cleanup_free_ void *lladdr = NULL;
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

        r = link_get_by_index(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will get the neighbor again. Also,
                 * kernel sends messages about neighbors after a link is removed. So, just ignore it. */
                log_debug("rtnl: received neighbor for link '%d' we don't know about, ignoring.", ifindex);
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

        r = sd_netlink_message_read_data(message, NDA_LLADDR, &tmp->lladdr_size, &lladdr);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message without valid lladdr, ignoring: %m");
                return 0;
        } else if (!IN_SET(tmp->lladdr_size, sizeof(struct ether_addr), sizeof(struct in_addr), sizeof(struct in6_addr))) {
                log_link_warning(link, "rtnl: received neighbor message with invalid lladdr size (%zu), ignoring: %m", tmp->lladdr_size);
                return 0;
        }
        memcpy(&tmp->lladdr, lladdr, tmp->lladdr_size);

        (void) neighbor_get(link, tmp, &neighbor);

        switch (type) {
        case RTM_NEWNEIGH:
                if (neighbor) {
                        neighbor_enter_configured(neighbor);
                        log_neighbor_debug(tmp, "Received remembered", link);
                } else {
                        neighbor_enter_configured(tmp);
                        log_neighbor_debug(tmp, "Remembering", link);
                        r = neighbor_add(link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign neighbor, ignoring: %m");
                                return 0;
                        }
                        TAKE_PTR(tmp);
                }

                break;

        case RTM_DELNEIGH:
                if (neighbor) {
                        neighbor_enter_removed(neighbor);
                        if (neighbor->state == 0) {
                                log_neighbor_debug(neighbor, "Forgetting", link);
                                neighbor_free(neighbor);
                        } else
                                log_neighbor_debug(neighbor, "Removed", link);
                } else
                        log_neighbor_debug(tmp, "Kernel removed unknown", link);

                break;

        default:
                assert_not_reached();
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

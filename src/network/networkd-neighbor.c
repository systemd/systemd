/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "errno-util.h"
#include "hashmap.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "ordered-set.h"
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-util.h"

static Neighbor* neighbor_detach_impl(Neighbor *neighbor) {
        assert(neighbor);
        assert(!neighbor->link || !neighbor->network);

        if (neighbor->network) {
                assert(neighbor->section);
                ordered_hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
                neighbor->network = NULL;
                return neighbor;
        }

        if (neighbor->link) {
                set_remove(neighbor->link->neighbors, neighbor);
                neighbor->link = NULL;
                return neighbor;
        }

        return NULL;
}

static void neighbor_detach(Neighbor *neighbor) {
        neighbor_unref(neighbor_detach_impl(neighbor));
}

static Neighbor* neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return NULL;

        neighbor_detach_impl(neighbor);

        config_section_free(neighbor->section);
        return mfree(neighbor);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Neighbor, neighbor, neighbor_free);
DEFINE_SECTION_CLEANUP_FUNCTIONS(Neighbor, neighbor_unref);

static void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state);
static int neighbor_compare_func(const Neighbor *a, const Neighbor *b);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        neighbor_hash_ops_detach,
        Neighbor,
        neighbor_hash_func,
        neighbor_compare_func,
        neighbor_detach);

DEFINE_PRIVATE_HASH_OPS(
        neighbor_hash_ops,
        Neighbor,
        neighbor_hash_func,
        neighbor_compare_func);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        neighbor_section_hash_ops,
        ConfigSection,
        config_section_hash_func,
        config_section_compare_func,
        Neighbor,
        neighbor_detach);

static int neighbor_new(Neighbor **ret) {
        Neighbor *neighbor;

        assert(ret);

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .n_ref = 1,
        };

        *ret = TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_new_static(Network *network, const char *filename, unsigned section_line, Neighbor **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(neighbor_unrefp) Neighbor *neighbor = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        neighbor = ordered_hashmap_get(network->neighbors_by_section, n);
        if (neighbor) {
                *ret = TAKE_PTR(neighbor);
                return 0;
        }

        r = neighbor_new(&neighbor);
        if (r < 0)
                return r;

        neighbor->network = network;
        neighbor->section = TAKE_PTR(n);
        neighbor->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = ordered_hashmap_ensure_put(&network->neighbors_by_section, &neighbor_section_hash_ops, neighbor->section, neighbor);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_dup(const Neighbor *neighbor, Neighbor **ret) {
        _cleanup_(neighbor_unrefp) Neighbor *dest = NULL;

        assert(neighbor);
        assert(ret);

        dest = newdup(Neighbor, neighbor, 1);
        if (!dest)
                return -ENOMEM;

        /* Clear the reference counter and all pointers */
        dest->n_ref = 1;
        dest->link = NULL;
        dest->network = NULL;
        dest->section = NULL;

        *ret = TAKE_PTR(dest);
        return 0;
}

static void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state) {
        assert(neighbor);

        siphash24_compress_typesafe(neighbor->dst_addr.family, state);

        if (!IN_SET(neighbor->dst_addr.family, AF_INET, AF_INET6))
                /* treat any other address family as AF_UNSPEC */
                return;

        /* Equality of neighbors are given by the destination address.
         * See neigh_lookup() in the kernel. */
        in_addr_hash_func(&neighbor->dst_addr.address, neighbor->dst_addr.family, state);
}

static int neighbor_compare_func(const Neighbor *a, const Neighbor *b) {
        int r;

        r = CMP(a->dst_addr.family, b->dst_addr.family);
        if (r != 0)
                return r;

        if (!IN_SET(a->dst_addr.family, AF_INET, AF_INET6))
                /* treat any other address family as AF_UNSPEC */
                return 0;

        return memcmp(&a->dst_addr.address, &b->dst_addr.address, FAMILY_ADDRESS_SIZE(a->dst_addr.family));
}

static int neighbor_get_request(Link *link, const Neighbor *neighbor, Request **ret) {
        Request *req;

        assert(link);
        assert(link->manager);
        assert(neighbor);

        req = ordered_set_get(
                        link->manager->request_queue,
                        &(Request) {
                                .link = link,
                                .type = REQUEST_TYPE_NEIGHBOR,
                                .userdata = (void*) neighbor,
                                .hash_func = (hash_func_t) neighbor_hash_func,
                                .compare_func = (compare_func_t) neighbor_compare_func,
                        });
        if (!req)
                return -ENOENT;

        if (ret)
                *ret = req;
        return 0;
}

int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret) {
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

static int neighbor_attach(Link *link, Neighbor *neighbor) {
        int r;

        assert(link);
        assert(neighbor);
        assert(!neighbor->link);

        r = set_ensure_put(&link->neighbors, &neighbor_hash_ops_detach, neighbor);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        neighbor->link = link;
        neighbor_ref(neighbor);
        return 0;
}

static void log_neighbor_debug(const Neighbor *neighbor, const char *str, const Link *link) {
        _cleanup_free_ char *state = NULL;

        assert(neighbor);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(neighbor->state, &state);

        log_link_debug(link,
                       "%s %s neighbor (%s): lladdr: %s, dst: %s",
                       str, strna(network_config_source_to_string(neighbor->source)), strna(state),
                       HW_ADDR_TO_STR(&neighbor->ll_addr),
                       IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address));
}

static void neighbor_forget(Link *link, Neighbor *neighbor, const char *msg) {
        assert(link);
        assert(neighbor);
        assert(msg);

        Request *req;
        if (neighbor_get_request(link, neighbor, &req) >= 0)
                neighbor_enter_removed(req->userdata);

        if (!neighbor->link && neighbor_get(link, neighbor, &neighbor) < 0)
                return;

        neighbor_enter_removed(neighbor);
        log_neighbor_debug(neighbor, "Forgetting", link);
        neighbor_detach(neighbor);
}

static int neighbor_configure(Neighbor *neighbor, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        log_neighbor_debug(neighbor, "Configuring", link);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH,
                                      link->ifindex, neighbor->dst_addr.family);
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_state(m, NUD_PERMANENT);
        if (r < 0)
                return r;

        r = netlink_message_append_hw_addr(m, NDA_LLADDR, &neighbor->ll_addr);
        if (r < 0)
                return r;

        r = netlink_message_append_in_addr_union(m, NDA_DST, neighbor->dst_addr.family, &neighbor->dst_addr.address);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int neighbor_process_request(Request *req, Link *link, Neighbor *neighbor) {
        Neighbor *existing;
        int r;

        assert(req);
        assert(link);
        assert(neighbor);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = neighbor_configure(neighbor, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure neighbor: %m");

        neighbor_enter_configuring(neighbor);
        if (neighbor_get(link, neighbor, &existing) >= 0)
                neighbor_enter_configuring(existing);

        return 1;
}

static int static_neighbor_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Neighbor *neighbor) {
        int r;

        assert(m);
        assert(link);

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

static int link_request_neighbor(Link *link, const Neighbor *neighbor) {
        _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
        Neighbor *existing = NULL;
        int r;

        assert(link);
        assert(neighbor);
        assert(neighbor->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (neighbor->ll_addr.length != link->hw_addr.length) {
                log_link_debug(link,
                               "The link layer address length (%zu) for neighbor %s does not match with "
                               "the hardware address length (%zu), ignoring the setting.",
                               neighbor->ll_addr.length,
                               IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                               link->hw_addr.length);
                return 0;
        }

        if (neighbor_get_request(link, neighbor, NULL) >= 0)
                return 0; /* already requested, skipping. */

        r = neighbor_dup(neighbor, &tmp);
        if (r < 0)
                return r;

        if (neighbor_get(link, neighbor, &existing) >= 0)
                /* Copy state for logging below. */
                tmp->state = existing->state;

        log_neighbor_debug(tmp, "Requesting", link);
        r = link_queue_request_safe(link, REQUEST_TYPE_NEIGHBOR,
                                    tmp,
                                    neighbor_unref,
                                    neighbor_hash_func,
                                    neighbor_compare_func,
                                    neighbor_process_request,
                                    &link->static_neighbor_messages,
                                    static_neighbor_configure_handler,
                                    NULL);
        if (r <= 0)
                return r;

        neighbor_enter_requesting(tmp);
        if (existing)
                neighbor_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

int link_request_static_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->static_neighbors_configured = false;

        ORDERED_HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                r = link_request_neighbor(link, neighbor);
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

static int neighbor_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, RemoveRequest *rreq) {
        int r;

        assert(m);
        assert(rreq);

        Link *link = ASSERT_PTR(rreq->link);
        Neighbor *neighbor = ASSERT_PTR(rreq->userdata);

        if (link->state == LINK_STATE_LINGER)
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                /* Neighbor may not exist because it already got deleted, ignore that. */
                log_link_message_full_errno(link, m,
                                            (r == -ESRCH || !neighbor->link) ? LOG_DEBUG : LOG_WARNING,
                                            r, "Could not remove neighbor");

                /* If the neighbor cannot be removed, then assume the neighbor is already removed. */
                neighbor_forget(link, neighbor, "Forgetting");
        }

        return 1;
}

int neighbor_remove(Neighbor *neighbor, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        /* If the neighbor is remembered, then use the remembered object. */
        (void) neighbor_get(link, neighbor, &neighbor);

        log_neighbor_debug(neighbor, "Removing", link);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_DELNEIGH,
                                      link->ifindex, neighbor->dst_addr.family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_DELNEIGH message: %m");

        r = netlink_message_append_in_addr_union(m, NDA_DST, neighbor->dst_addr.family, &neighbor->dst_addr.address);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

        r = link_remove_request_add(link, neighbor, neighbor, link->manager->rtnl, m, neighbor_remove_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not queue rtnetlink message: %m");

        neighbor_enter_removing(neighbor);
        return 0;
}

int link_drop_unmanaged_neighbors(Link *link) {
        Neighbor *neighbor;
        int r = 0;

        assert(link);
        assert(link->network);

        /* First, mark all neighbors. */
        SET_FOREACH(neighbor, link->neighbors) {
                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                if (!link_should_mark_config(link, /* only_static = */ false, neighbor->source, RTPROT_STATIC))
                        continue;

                neighbor_mark(neighbor);
        }

        /* Next, unmark requested neighbors. They will be configured later. */
        ORDERED_HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                Neighbor *existing;

                if (neighbor_get(link, neighbor, &existing) >= 0)
                        neighbor_unmark(existing);
        }

        /* Finally, remove all marked neighbors. */
        SET_FOREACH(neighbor, link->neighbors) {
                if (!neighbor_is_marked(neighbor))
                        continue;

                RET_GATHER(r, neighbor_remove(neighbor, link));
        }

        return r;
}

int link_drop_static_neighbors(Link *link) {
        Neighbor *neighbor;
        int r = 0;

        assert(link);

        SET_FOREACH(neighbor, link->neighbors) {
                /* Do not touch nexthops managed by kernel or other tools. */
                if (neighbor->source != NETWORK_CONFIG_SOURCE_STATIC)
                        continue;

                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                RET_GATHER(r, neighbor_remove(neighbor, link));
        }

        return r;
}

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive neighbor message, ignoring");

                return 0;
        }

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEIGH, RTM_DELNEIGH)) {
                log_warning("rtnl: received unexpected message type %u when processing neighbor, ignoring.", type);
                return 0;
        }

        uint16_t state;
        r = sd_rtnl_message_neigh_get_state(message, &state);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received neighbor message with invalid state, ignoring: %m");
                return 0;
        } else if (!FLAGS_SET(state, NUD_PERMANENT))
                /* Currently, we are interested in only static neighbors. */
                return 0;

        int ifindex;
        r = sd_rtnl_message_neigh_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received neighbor message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        Link *link;
        r = link_get_by_index(m, ifindex, &link);
        if (r < 0)
                /* when enumerating we might be out of sync, but we will get the neighbor again. Also,
                 * kernel sends messages about neighbors after a link is removed. So, just ignore it. */
                return 0;

        _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
        r = neighbor_new(&tmp);
        if (r < 0)
                return log_oom();

        /* First, retrieve the fundamental information about the neighbor. */
        r = sd_rtnl_message_neigh_get_family(message, &tmp->dst_addr.family);
        if (r < 0) {
                log_link_warning(link, "rtnl: received neighbor message without family, ignoring.");
                return 0;
        }
        if (tmp->dst_addr.family == AF_BRIDGE) /* Currently, we do not support it. */
                return 0;
        if (!IN_SET(tmp->dst_addr.family, AF_INET, AF_INET6)) {
                log_link_debug(link, "rtnl: received neighbor message with invalid family '%i', ignoring.", tmp->dst_addr.family);
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, NDA_DST, tmp->dst_addr.family, &tmp->dst_addr.address);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                return 0;
        }

        /* Then, find the managed Neighbor object corresponding to the netlink notification. */
        Neighbor *neighbor = NULL;
        (void) neighbor_get(link, tmp, &neighbor);

        if (type == RTM_DELNEIGH) {
                if (neighbor)
                        neighbor_forget(link, neighbor, "Forgetting removed");
                else
                        log_neighbor_debug(tmp, "Kernel removed unknown", link);
                return 0;
        }

        /* If we did not know the neighbor, then save it. */
        bool is_new = false;
        if (!neighbor) {
                r = neighbor_attach(link, tmp);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to save received neighbor, ignoring: %m");
                        return 0;
                }
                neighbor = tmp;
                is_new = true;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        Request *req = NULL;
        (void) neighbor_get_request(link, tmp, &req);
        if (req && req->waiting_reply) {
                Neighbor *n = ASSERT_PTR(req->userdata);

                neighbor->source = n->source;
        }

        /* Then, update miscellaneous info. */
        r = netlink_message_read_hw_addr(message, NDA_LLADDR, &neighbor->ll_addr);
        if (r < 0 && r != -ENODATA)
                log_link_debug_errno(link, r, "rtnl: received neighbor message without valid link layer address, ignoring: %m");

        neighbor_enter_configured(neighbor);
        if (req)
                neighbor_enter_configured(req->userdata);

        log_neighbor_debug(neighbor, is_new ? "Remembering" : "Received remembered", link);
        return 1;
}

#define log_neighbor_section(neighbor, fmt, ...)                        \
        ({                                                              \
                const Neighbor *_neighbor = (neighbor);                 \
                log_section_warning_errno(                              \
                                _neighbor ? _neighbor->section : NULL,  \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [Neighbor] section.",    \
                                ##__VA_ARGS__);                         \
        })

static int neighbor_section_verify(Neighbor *neighbor) {
        if (section_is_invalid(neighbor->section))
                return -EINVAL;

        if (neighbor->dst_addr.family == AF_UNSPEC)
                return log_neighbor_section(neighbor, "Neighbor section without Address= configured.");

        if (neighbor->dst_addr.family == AF_INET6 && !socket_ipv6_is_supported())
                return log_neighbor_section(neighbor, "Neighbor section with an IPv6 destination address configured, but the kernel does not support IPv6.");

        if (neighbor->ll_addr.length == 0)
                return log_neighbor_section(neighbor, "Neighbor section without LinkLayerAddress= configured.");

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        trivial_hash_ops_neighbor_detach,
        void,
        trivial_hash_func,
        trivial_compare_func,
        Neighbor,
        neighbor_detach);

int network_drop_invalid_neighbors(Network *network) {
        _cleanup_set_free_ Set *neighbors = NULL, *duplicated_neighbors = NULL;
        Neighbor *neighbor;
        int r;

        assert(network);

        ORDERED_HASHMAP_FOREACH(neighbor, network->neighbors_by_section) {
                Neighbor *dup;

                if (neighbor_section_verify(neighbor) < 0) {
                        /* Drop invalid [Neighbor] sections. Note that neighbor_detach() will drop the
                         * neighbor from neighbors_by_section. */
                        neighbor_detach(neighbor);
                        continue;
                }

                /* Always use the setting specified later. So, remove the previously assigned setting. */
                dup = set_remove(neighbors, neighbor);
                if (dup) {
                        log_warning("%s: Duplicated neighbor settings for %s is specified at line %u and %u, "
                                    "dropping the neighbor setting specified at line %u.",
                                    dup->section->filename,
                                    IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                                    neighbor->section->line,
                                    dup->section->line, dup->section->line);

                        /* Do not call nexthop_detach() for 'dup' now, as we can remove only the current
                         * entry in the loop. We will drop the nexthop from nexthops_by_section later. */
                        r = set_ensure_put(&duplicated_neighbors, &trivial_hash_ops_neighbor_detach, dup);
                        if (r < 0)
                                return log_oom();
                        assert(r > 0);
                }

                /* Use neighbor_hash_ops, instead of neighbor_hash_ops_detach. Otherwise, the Neighbor objects
                 * will be detached. */
                r = set_ensure_put(&neighbors, &neighbor_hash_ops, neighbor);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

        return 0;
}

int config_parse_neighbor_section(
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

        static const ConfigSectionParser table[_NEIGHBOR_CONF_PARSER_MAX] = {
                [NEIGHBOR_DESTINATION_ADDRESS] = { .parser = config_parse_in_addr_data, .ltype = 0, .offset = offsetof(Neighbor, dst_addr), },
                [NEIGHBOR_LINK_LAYER_ADDRESS]  = { .parser = config_parse_hw_addr,      .ltype = 0, .offset = offsetof(Neighbor, ll_addr),  },
        };

        _cleanup_(neighbor_unref_or_set_invalidp) Neighbor *neighbor = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = neighbor_new_static(network, filename, section_line, &neighbor);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, neighbor);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(neighbor);
        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc.
 */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/nexthop.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"

static void nexthop_detach_from_group_members(NextHop *nexthop) {
        assert(nexthop);
        assert(nexthop->manager);
        assert(nexthop->id > 0);

        struct nexthop_grp *nhg;
        HASHMAP_FOREACH(nhg, nexthop->group) {
                NextHop *nh;

                if (nexthop_get_by_id(nexthop->manager, nhg->id, &nh) < 0)
                        continue;

                set_remove(nh->nexthops, UINT32_TO_PTR(nexthop->id));
        }
}

static void nexthop_attach_to_group_members(NextHop *nexthop) {
        int r;

        assert(nexthop);
        assert(nexthop->manager);
        assert(nexthop->id > 0);

        struct nexthop_grp *nhg;
        HASHMAP_FOREACH(nhg, nexthop->group) {
                NextHop *nh;

                r = nexthop_get_by_id(nexthop->manager, nhg->id, &nh);
                if (r < 0) {
                        if (nexthop->manager->manage_foreign_nexthops)
                                log_debug_errno(r, "Nexthop (id=%"PRIu32") has unknown group member (%"PRIu32"), ignoring.",
                                                nexthop->id, nhg->id);
                        continue;
                }

                r = set_ensure_put(&nh->nexthops, NULL, UINT32_TO_PTR(nexthop->id));
                if (r < 0)
                        log_debug_errno(r, "Failed to save nexthop ID (%"PRIu32") to group member (%"PRIu32"), ignoring: %m",
                                        nexthop->id, nhg->id);
        }
}

static NextHop* nexthop_detach_impl(NextHop *nexthop) {
        assert(nexthop);
        assert(!nexthop->manager || !nexthop->network);

        if (nexthop->network) {
                assert(nexthop->section);
                ordered_hashmap_remove(nexthop->network->nexthops_by_section, nexthop->section);
                nexthop->network = NULL;
                return nexthop;
        }

        if (nexthop->manager) {
                assert(nexthop->id > 0);

                nexthop_detach_from_group_members(nexthop);

                hashmap_remove(nexthop->manager->nexthops_by_id, UINT32_TO_PTR(nexthop->id));
                nexthop->manager = NULL;
                return nexthop;
        }

        return NULL;
}

static void nexthop_detach(NextHop *nexthop) {
        nexthop_unref(nexthop_detach_impl(nexthop));
}

static NextHop* nexthop_free(NextHop *nexthop) {
        if (!nexthop)
                return NULL;

        nexthop_detach_impl(nexthop);

        config_section_free(nexthop->section);
        hashmap_free(nexthop->group);
        set_free(nexthop->nexthops);
        set_free(nexthop->routes);

        return mfree(nexthop);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(NextHop, nexthop, nexthop_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                nexthop_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                NextHop,
                nexthop_detach);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                nexthop_section_hash_ops,
                ConfigSection,
                config_section_hash_func,
                config_section_compare_func,
                NextHop,
                nexthop_detach);

int nexthop_new(NextHop **ret) {
        _cleanup_(nexthop_unrefp) NextHop *nexthop = NULL;

        nexthop = new(NextHop, 1);
        if (!nexthop)
                return -ENOMEM;

        *nexthop = (NextHop) {
                .n_ref = 1,
                .onlink = -1,
        };

        *ret = TAKE_PTR(nexthop);

        return 0;
}

static int nexthop_new_static(Network *network, const char *filename, unsigned section_line, NextHop **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(nexthop_unrefp) NextHop *nexthop = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        nexthop = ordered_hashmap_get(network->nexthops_by_section, n);
        if (nexthop) {
                *ret = TAKE_PTR(nexthop);
                return 0;
        }

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop->protocol = RTPROT_STATIC;
        nexthop->network = network;
        nexthop->section = TAKE_PTR(n);
        nexthop->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = ordered_hashmap_ensure_put(&network->nexthops_by_section, &nexthop_section_hash_ops, nexthop->section, nexthop);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nexthop);
        return 0;
}

static void nexthop_hash_func(const NextHop *nexthop, struct siphash *state) {
        assert(nexthop);
        assert(state);

        siphash24_compress_typesafe(nexthop->id, state);
}

static int nexthop_compare_func(const NextHop *a, const NextHop *b) {
        assert(a);
        assert(b);

        return CMP(a->id, b->id);
}

static int nexthop_compare_full(const NextHop *a, const NextHop *b) {
        int r;

        assert(a);
        assert(b);

        /* This compares detailed configs, except for ID and ifindex. */

        r = CMP(a->protocol, b->protocol);
        if (r != 0)
                return r;

        r = CMP(a->flags, b->flags);
        if (r != 0)
                return r;

        r = CMP(hashmap_size(a->group), hashmap_size(b->group));
        if (r != 0)
                return r;

        if (!hashmap_isempty(a->group)) {
                struct nexthop_grp *ga;

                HASHMAP_FOREACH(ga, a->group) {
                        struct nexthop_grp *gb;

                        gb = hashmap_get(b->group, UINT32_TO_PTR(ga->id));
                        if (!gb)
                                return CMP(ga, gb);

                        r = CMP(ga->weight, gb->weight);
                        if (r != 0)
                                return r;
                }
        }

        r = CMP(a->blackhole, b->blackhole);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        if (IN_SET(a->family, AF_INET, AF_INET6)) {
                r = memcmp(&a->gw.address, &b->gw.address, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;
        }

        return 0;
}

static int nexthop_dup(const NextHop *src, NextHop **ret) {
        _cleanup_(nexthop_unrefp) NextHop *dest = NULL;
        struct nexthop_grp *nhg;
        int r;

        assert(src);
        assert(ret);

        dest = newdup(NextHop, src, 1);
        if (!dest)
                return -ENOMEM;

        /* clear the reference counter and all pointers */
        dest->n_ref = 1;
        dest->manager = NULL;
        dest->network = NULL;
        dest->section = NULL;
        dest->group = NULL;
        dest->nexthops = NULL;
        dest->routes = NULL;

        HASHMAP_FOREACH(nhg, src->group) {
                _cleanup_free_ struct nexthop_grp *g = NULL;

                g = newdup(struct nexthop_grp, nhg, 1);
                if (!g)
                        return -ENOMEM;

                r = hashmap_ensure_put(&dest->group, &trivial_hash_ops_value_free, UINT32_TO_PTR(g->id), g);
                if (r < 0)
                        return r;
                if (r > 0)
                        TAKE_PTR(g);
        }

        *ret = TAKE_PTR(dest);
        return 0;
}

static bool nexthop_bound_to_link(const NextHop *nexthop) {
        assert(nexthop);
        return !nexthop->blackhole && hashmap_isempty(nexthop->group);
}

int nexthop_get_by_id(Manager *manager, uint32_t id, NextHop **ret) {
        NextHop *nh;

        assert(manager);

        if (id == 0)
                return -EINVAL;

        nh = hashmap_get(manager->nexthops_by_id, UINT32_TO_PTR(id));
        if (!nh)
                return -ENOENT;

        if (ret)
                *ret = nh;
        return 0;
}

static int nexthop_get(Link *link, const NextHop *in, NextHop **ret) {
        NextHop *nexthop;
        int ifindex;

        assert(link);
        assert(link->manager);
        assert(in);

        if (in->id > 0)
                return nexthop_get_by_id(link->manager, in->id, ret);

        /* If ManageForeignNextHops=no, nexthop with id == 0 should be already filtered by
         * nexthop_section_verify(). */
        assert(link->manager->manage_foreign_nexthops);

        ifindex = nexthop_bound_to_link(in) ? link->ifindex : 0;

        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id) {
                if (nexthop->ifindex != ifindex)
                        continue;
                if (nexthop_compare_full(nexthop, in) != 0)
                        continue;

                /* Even if the configuration matches, it may be configured with another [NextHop] section
                 * that has an explicit ID. If so, the assigned nexthop is not the one we are looking for. */
                if (set_contains(link->manager->nexthop_ids, UINT32_TO_PTR(nexthop->id)))
                        continue;

                if (ret)
                        *ret = nexthop;
                return 0;
        }

        return -ENOENT;
}

int nexthop_get_request_by_id(Manager *manager, uint32_t id, Request **ret) {
        Request *req;

        assert(manager);

        if (id == 0)
                return -EINVAL;

        req = ordered_set_get(
                        manager->request_queue,
                        &(Request) {
                                .type = REQUEST_TYPE_NEXTHOP,
                                .userdata = (void*) &(const NextHop) { .id = id },
                                .hash_func = (hash_func_t) nexthop_hash_func,
                                .compare_func = (compare_func_t) nexthop_compare_func,
                        });
        if (!req)
                return -ENOENT;

        if (ret)
                *ret = req;
        return 0;
}

static int nexthop_get_request(Link *link, const NextHop *in, Request **ret) {
        Request *req;
        int ifindex;

        assert(link);
        assert(link->manager);
        assert(in);

        if (in->id > 0)
                return nexthop_get_request_by_id(link->manager, in->id, ret);

        /* If ManageForeignNextHops=no, nexthop with id == 0 should be already filtered by
         * nexthop_section_verify(). */
        assert(link->manager->manage_foreign_nexthops);

        ifindex = nexthop_bound_to_link(in) ? link->ifindex : 0;

        ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                if (req->type != REQUEST_TYPE_NEXTHOP)
                        continue;

                NextHop *nexthop = ASSERT_PTR(req->userdata);
                if (nexthop->ifindex != ifindex)
                        continue;
                if (nexthop_compare_full(nexthop, in) != 0)
                        continue;

                /* Even if the configuration matches, it may be requested by another [NextHop] section
                 * that has an explicit ID. If so, the request is not the one we are looking for. */
                if (set_contains(link->manager->nexthop_ids, UINT32_TO_PTR(nexthop->id)))
                        continue;

                if (ret)
                        *ret = req;
                return 0;
        }

        return -ENOENT;
}

static int nexthop_add_new(Manager *manager, uint32_t id, NextHop **ret) {
        _cleanup_(nexthop_unrefp) NextHop *nexthop = NULL;
        int r;

        assert(manager);
        assert(id > 0);

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop->id = id;

        r = hashmap_ensure_put(&manager->nexthops_by_id, &nexthop_hash_ops, UINT32_TO_PTR(nexthop->id), nexthop);
        if (r < 0)
                return r;
        assert(r > 0);

        nexthop->manager = manager;

        if (ret)
                *ret = nexthop;

        TAKE_PTR(nexthop);
        return 0;
}

static int nexthop_acquire_id(Manager *manager, NextHop *nexthop) {
        assert(manager);
        assert(nexthop);

        if (nexthop->id > 0)
                return 0;

        /* If ManageForeignNextHops=no, nexthop with id == 0 should be already filtered by
         * nexthop_section_verify(). */
        assert(manager->manage_foreign_nexthops);

        /* Find the lowest unused ID. */

        for (uint32_t id = 1; id < UINT32_MAX; id++) {
                if (nexthop_get_by_id(manager, id, NULL) >= 0)
                        continue;
                if (nexthop_get_request_by_id(manager, id, NULL) >= 0)
                        continue;
                if (set_contains(manager->nexthop_ids, UINT32_TO_PTR(id)))
                        continue;

                nexthop->id = id;
                return 0;
        }

        return -EBUSY;
}

void log_nexthop_debug(const NextHop *nexthop, const char *str, Manager *manager) {
        _cleanup_free_ char *state = NULL, *group = NULL, *flags = NULL;
        struct nexthop_grp *nhg;
        Link *link = NULL;

        assert(nexthop);
        assert(str);
        assert(manager);

        if (!DEBUG_LOGGING)
                return;

        (void) link_get_by_index(manager, nexthop->ifindex, &link);
        (void) network_config_state_to_string_alloc(nexthop->state, &state);
        (void) route_flags_to_string_alloc(nexthop->flags, &flags);

        HASHMAP_FOREACH(nhg, nexthop->group)
                (void) strextendf_with_separator(&group, ",", "%"PRIu32":%"PRIu32, nhg->id, nhg->weight+1u);

        log_link_debug(link, "%s %s nexthop (%s): id: %"PRIu32", gw: %s, blackhole: %s, group: %s, flags: %s",
                       str, strna(network_config_source_to_string(nexthop->source)), strna(state),
                       nexthop->id,
                       IN_ADDR_TO_STRING(nexthop->family, &nexthop->gw.address),
                       yes_no(nexthop->blackhole), strna(group), strna(flags));
}

static void nexthop_forget_dependents(NextHop *nexthop, Manager *manager) {
        assert(nexthop);
        assert(manager);

        /* If a nexthop is removed, the kernel silently removes routes that depend on the removed nexthop.
         * Let's forget them. */

        for (;;) {
                _cleanup_(route_unrefp) Route *route = set_steal_first(nexthop->routes);
                if (!route)
                        break;

                Request *req;
                if (route_get_request(manager, route, &req) >= 0)
                        route_enter_removed(req->userdata);

                route_enter_removed(route);
                log_route_debug(route, "Forgetting silently removed", manager);
                route_detach(route);
        }

        nexthop->routes = set_free(nexthop->routes);
}

static void nexthop_forget(Manager *manager, NextHop *nexthop, const char *msg) {
        assert(manager);
        assert(nexthop);
        assert(msg);

        Request *req;
        if (nexthop_get_request_by_id(manager, nexthop->id, &req) >= 0)
                nexthop_enter_removed(req->userdata);

        if (!nexthop->manager && nexthop_get_by_id(manager, nexthop->id, &nexthop) < 0)
                return;

        nexthop_enter_removed(nexthop);
        log_nexthop_debug(nexthop, msg, manager);
        nexthop_forget_dependents(nexthop, nexthop->manager);
        nexthop_detach(nexthop);
}

static int nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, RemoveRequest *rreq) {
        int r;

        assert(m);
        assert(rreq);

        Manager *manager = ASSERT_PTR(rreq->manager);
        NextHop *nexthop = ASSERT_PTR(rreq->userdata);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_message_full_errno(m,
                                       (r == -ENOENT || !nexthop->manager) ? LOG_DEBUG : LOG_WARNING,
                                       r, "Could not drop nexthop, ignoring");

                /* If the nexthop cannot be removed, then assume the nexthop is already removed. */
                nexthop_forget(manager, nexthop, "Forgetting");
        }

        return 1;
}

int nexthop_remove(NextHop *nexthop, Manager *manager) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        Link *link = NULL;
        int r;

        assert(nexthop);
        assert(nexthop->id > 0);
        assert(manager);

        /* If the nexthop is remembered, then use the remembered object. */
        (void) nexthop_get_by_id(manager, PTR_TO_UINT32(nexthop->id), &nexthop);

        /* link may be NULL. */
        (void) link_get_by_index(manager, nexthop->ifindex, &link);

        log_nexthop_debug(nexthop, "Removing", manager);

        r = sd_rtnl_message_new_nexthop(manager->rtnl, &m, RTM_DELNEXTHOP, AF_UNSPEC, RTPROT_UNSPEC);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELNEXTHOP message: %m");

        r = sd_netlink_message_append_u32(m, NHA_ID, nexthop->id);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NHA_ID attribute: %m");

        r = manager_remove_request_add(manager, nexthop, nexthop, manager->rtnl, m, nexthop_remove_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not queue rtnetlink message: %m");

        nexthop_enter_removing(nexthop);
        return 0;
}

int nexthop_remove_and_cancel(NextHop *nexthop, Manager *manager) {
        _cleanup_(request_unrefp) Request *req = NULL;
        bool waiting = false;

        assert(nexthop);
        assert(nexthop->id > 0);
        assert(manager);

        /* If the nexthop is remembered by the manager, then use the remembered object. */
        (void) nexthop_get_by_id(manager, nexthop->id, &nexthop);

        /* Cancel the request for the nexthop. If the request is already called but we have not received the
         * notification about the request, then explicitly remove the nexthop. */
        if (nexthop_get_request_by_id(manager, nexthop->id, &req) >= 0) {
                request_ref(req); /* avoid the request freed by request_detach() */
                waiting = req->waiting_reply;
                request_detach(req);
                nexthop_cancel_requesting(nexthop);
        }

        /* If we know that the nexthop will come or already exists, remove it. */
        if (waiting || (nexthop->manager && nexthop_exists(nexthop)))
                return nexthop_remove(nexthop, manager);

        return 0;
}

static int nexthop_configure(NextHop *nexthop, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nexthop);
        assert(nexthop->id > 0);
        assert(IN_SET(nexthop->family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_nexthop_debug(nexthop, "Configuring", link->manager);

        r = sd_rtnl_message_new_nexthop(link->manager->rtnl, &m, RTM_NEWNEXTHOP, nexthop->family, nexthop->protocol);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NHA_ID, nexthop->id);
        if (r < 0)
                return r;

        if (!hashmap_isempty(nexthop->group)) {
                _cleanup_free_ struct nexthop_grp *group = NULL;
                struct nexthop_grp *p, *nhg;

                group = new(struct nexthop_grp, hashmap_size(nexthop->group));
                if (!group)
                        return log_oom();

                p = group;
                HASHMAP_FOREACH(nhg, nexthop->group)
                        *p++ = *nhg;

                r = sd_netlink_message_append_data(m, NHA_GROUP, group, sizeof(struct nexthop_grp) * hashmap_size(nexthop->group));
                if (r < 0)
                        return r;

        } else if (nexthop->blackhole) {
                r = sd_netlink_message_append_flag(m, NHA_BLACKHOLE);
                if (r < 0)
                        return r;
        } else {
                assert(nexthop->ifindex == link->ifindex);

                r = sd_netlink_message_append_u32(m, NHA_OIF, nexthop->ifindex);
                if (r < 0)
                        return r;

                if (in_addr_is_set(nexthop->family, &nexthop->gw.address)) {
                        r = netlink_message_append_in_addr_union(m, NHA_GATEWAY, nexthop->family, &nexthop->gw.address);
                        if (r < 0)
                                return r;

                        r = sd_rtnl_message_nexthop_set_flags(m, nexthop->flags & RTNH_F_ONLINK);
                        if (r < 0)
                                return r;
                }
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

int nexthop_configure_handler_internal(sd_netlink_message *m, Link *link, const char *error_msg) {
        int r;

        assert(m);
        assert(link);
        assert(error_msg);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, error_msg);
                link_enter_failed(link);
                return 0;
        }

        return 1;
}

static int static_nexthop_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, NextHop *nexthop) {
        int r;

        assert(link);

        r = nexthop_configure_handler_internal(m, link, "Failed to set static nexthop");
        if (r <= 0)
                return r;

        if (link->static_nexthop_messages == 0) {
                log_link_debug(link, "Nexthops set");
                link->static_nexthops_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int nexthop_is_ready(Manager *manager, uint32_t id, NextHop **ret) {
        NextHop *nexthop;

        assert(manager);

        if (id == 0)
                return -EINVAL;

        if (nexthop_get_request_by_id(manager, id, NULL) >= 0)
                goto not_ready;

        if (nexthop_get_by_id(manager, id, &nexthop) < 0)
                goto not_ready;

        if (!nexthop_exists(nexthop))
                goto not_ready;

        if (ret)
                *ret = nexthop;

        return true;

not_ready:
        if (ret)
                *ret = NULL;

        return false;
}

static bool nexthop_is_ready_to_configure(Link *link, const NextHop *nexthop) {
        struct nexthop_grp *nhg;
        int r;

        assert(link);
        assert(nexthop);
        assert(nexthop->id > 0);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (nexthop_bound_to_link(nexthop)) {
                assert(nexthop->ifindex == link->ifindex);

                /* TODO: fdb nexthop does not require IFF_UP. The conditions below needs to be updated
                 * when fdb nexthop support is added. See rtm_to_nh_config() in net/ipv4/nexthop.c of
                 * kernel. */
                if (link->set_flags_messages > 0)
                        return false;
                if (!FLAGS_SET(link->flags, IFF_UP))
                        return false;
        }

        /* All group members must be configured first. */
        HASHMAP_FOREACH(nhg, nexthop->group) {
                r = nexthop_is_ready(link->manager, nhg->id, NULL);
                if (r <= 0)
                        return r;
        }

        return gateway_is_ready(link, FLAGS_SET(nexthop->flags, RTNH_F_ONLINK), nexthop->family, &nexthop->gw.address);
}

static int nexthop_process_request(Request *req, Link *link, NextHop *nexthop) {
        NextHop *existing;
        int r;

        assert(req);
        assert(link);
        assert(link->manager);
        assert(nexthop);

        if (!nexthop_is_ready_to_configure(link, nexthop))
                return 0;

        r = nexthop_configure(nexthop, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure nexthop");

        nexthop_enter_configuring(nexthop);
        if (nexthop_get_by_id(link->manager, nexthop->id, &existing) >= 0)
                nexthop_enter_configuring(existing);

        return 1;
}

int link_request_nexthop(
                Link *link,
                const NextHop *nexthop,
                unsigned *message_counter,
                nexthop_netlink_handler_t netlink_handler) {

        _cleanup_(nexthop_unrefp) NextHop *tmp = NULL;
        NextHop *existing = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(nexthop);
        assert(nexthop->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (nexthop_get_request(link, nexthop, NULL) >= 0)
                return 0; /* already requested, skipping. */

        r = nexthop_dup(nexthop, &tmp);
        if (r < 0)
                return r;

        if (nexthop_get(link, nexthop, &existing) < 0) {
                r = nexthop_acquire_id(link->manager, tmp);
                if (r < 0)
                        return r;
        } else {
                /* Copy ID */
                assert(tmp->id == 0 || tmp->id == existing->id);
                tmp->id = existing->id;

                /* Copy state for logging below. */
                tmp->state = existing->state;
        }

        if (nexthop_bound_to_link(tmp))
                tmp->ifindex = link->ifindex;

        log_nexthop_debug(tmp, "Requesting", link->manager);
        r = link_queue_request_safe(link, REQUEST_TYPE_NEXTHOP,
                                    tmp,
                                    nexthop_unref,
                                    nexthop_hash_func,
                                    nexthop_compare_func,
                                    nexthop_process_request,
                                    message_counter,
                                    netlink_handler,
                                    NULL);
        if (r <= 0)
                return r;

        nexthop_enter_requesting(tmp);
        if (existing)
                nexthop_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

int link_request_static_nexthops(Link *link, bool only_ipv4) {
        NextHop *nh;
        int r;

        assert(link);
        assert(link->network);

        link->static_nexthops_configured = false;

        ORDERED_HASHMAP_FOREACH(nh, link->network->nexthops_by_section) {
                if (only_ipv4 && nh->family != AF_INET)
                        continue;

                r = link_request_nexthop(link, nh, &link->static_nexthop_messages, static_nexthop_handler);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request nexthop: %m");
        }

        if (link->static_nexthop_messages == 0) {
                link->static_nexthops_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Requesting nexthops");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static bool nexthop_can_update(const NextHop *assigned_nexthop, const NextHop *requested_nexthop) {
        assert(assigned_nexthop);
        assert(assigned_nexthop->manager);
        assert(requested_nexthop);
        assert(requested_nexthop->network);

        /* A group nexthop cannot be replaced with a non-group nexthop, and vice versa.
         * See replace_nexthop_grp() and replace_nexthop_single() in net/ipv4/nexthop.c of the kernel. */
        if (hashmap_isempty(assigned_nexthop->group) != hashmap_isempty(requested_nexthop->group))
                return false;

        /* There are several more conditions if we can replace a group nexthop, e.g. hash threshold and
         * resilience. But, currently we do not support to modify that. Let's add checks for them in the
         * future when we support to configure them. */

        /* When a nexthop is replaced with a blackhole nexthop, and a group nexthop has multiple nexthops
         * including this nexthop, then the kernel refuses to replace the existing nexthop.
         * So, here, for simplicity, let's unconditionally refuse to replace a non-blackhole nexthop with
         * a blackhole nexthop. See replace_nexthop() in net/ipv4/nexthop.c of the kernel. */
        if (!assigned_nexthop->blackhole && requested_nexthop->blackhole)
                return false;

        return true;
}

int link_drop_nexthops(Link *link, bool only_static) {
        NextHop *nexthop;
        Link *other;
        int r = 0;

        assert(link);
        assert(link->manager);

        /* First, mark all nexthops. */
        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                /* Ignore nexthops not assigned yet or already removed. */
                if (!nexthop_exists(nexthop))
                        continue;

                if (nexthop->source == NETWORK_CONFIG_SOURCE_FOREIGN) {
                        if (only_static)
                                continue;

                        /* Do not mark foreign nexthop when KeepConfiguration= is enabled. */
                        if (link->network &&
                            FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                                continue;

                } else if (nexthop->source != NETWORK_CONFIG_SOURCE_STATIC)
                        continue; /* Ignore dynamically configurad nexthops. */

                /* Ignore nexthops bound to other links. */
                if (nexthop->ifindex > 0 && nexthop->ifindex != link->ifindex)
                        continue;

                nexthop_mark(nexthop);
        }

        /* Then, unmark all nexthops requested by active links. */
        HASHMAP_FOREACH(other, link->manager->links_by_index) {
                if (only_static && other == link)
                        continue;

                if (!IN_SET(other->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                ORDERED_HASHMAP_FOREACH(nexthop, other->network->nexthops_by_section) {
                        NextHop *existing;

                        if (nexthop_get(other, nexthop, &existing) < 0)
                                continue;

                        if (!nexthop_can_update(existing, nexthop))
                                continue;

                        /* Found matching static configuration. Keep the existing nexthop. */
                        nexthop_unmark(existing);
                }
        }

        /* Finally, remove all marked nexthops. */
        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id) {
                if (!nexthop_is_marked(nexthop))
                        continue;

                RET_GATHER(r, nexthop_remove(nexthop, link->manager));
        }

        return r;
}

void link_forget_nexthops(Link *link) {
        assert(link);
        assert(link->manager);
        assert(link->ifindex > 0);
        assert(!FLAGS_SET(link->flags, IFF_UP));

        /* See comments in link_forget_routes(). */

        /* Remove all IPv4 nexthops. */
        NextHop *nexthop;
        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id) {
                if (nexthop->ifindex != link->ifindex)
                        continue;
                if (nexthop->family != AF_INET)
                        continue;

                nexthop_forget(link->manager, nexthop, "Forgetting silently removed");
        }

        /* Remove all group nexthops their all members are removed in the above. */
        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id) {
                if (hashmap_isempty(nexthop->group))
                        continue;

                /* Update group members. */
                struct nexthop_grp *nhg;
                HASHMAP_FOREACH(nhg, nexthop->group) {
                        if (nexthop_get_by_id(nexthop->manager, nhg->id, NULL) >= 0)
                                continue;

                        assert_se(hashmap_remove(nexthop->group, UINT32_TO_PTR(nhg->id)) == nhg);
                        free(nhg);
                }

                if (!hashmap_isempty(nexthop->group))
                        continue; /* At least one group member still exists. */

                nexthop_forget(link->manager, nexthop, "Forgetting silently removed");
        }
}

static int nexthop_update_group(NextHop *nexthop, sd_netlink_message *message) {
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        _cleanup_free_ struct nexthop_grp *group = NULL;
        size_t size = 0, n_group;
        int r;

        assert(nexthop);
        assert(message);

        r = sd_netlink_message_read_data(message, NHA_GROUP, &size, (void**) &group);
        if (r < 0 && r != -ENODATA)
                return log_debug_errno(r, "rtnl: could not get NHA_GROUP attribute, ignoring: %m");

        nexthop_detach_from_group_members(nexthop);

        if (size % sizeof(struct nexthop_grp) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "rtnl: received nexthop message with invalid nexthop group size, ignoring.");

        if ((uintptr_t) group % alignof(struct nexthop_grp) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "rtnl: received nexthop message with invalid alignment, ignoring.");

        n_group = size / sizeof(struct nexthop_grp);
        for (size_t i = 0; i < n_group; i++) {
                _cleanup_free_ struct nexthop_grp *nhg = NULL;

                if (group[i].id == 0) {
                        log_debug("rtnl: received nexthop message with invalid ID in group, ignoring.");
                        continue;
                }

                if (group[i].weight > 254) {
                        log_debug("rtnl: received nexthop message with invalid weight in group, ignoring.");
                        continue;
                }

                nhg = newdup(struct nexthop_grp, group + i, 1);
                if (!nhg)
                        return log_oom();

                r = hashmap_ensure_put(&h, &trivial_hash_ops_value_free, UINT32_TO_PTR(nhg->id), nhg);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_debug_errno(r, "Failed to store nexthop group, ignoring: %m");
                        continue;
                }
                if (r > 0)
                        TAKE_PTR(nhg);
        }

        hashmap_free_and_replace(nexthop->group, h);
        nexthop_attach_to_group_members(nexthop);
        return 0;
}

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive rule message, ignoring");

                return 0;
        }

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEXTHOP, RTM_DELNEXTHOP)) {
                log_warning("rtnl: received unexpected message type %u when processing nexthop, ignoring.", type);
                return 0;
        }

        uint32_t id;
        r = sd_netlink_message_read_u32(message, NHA_ID, &id);
        if (r == -ENODATA) {
                log_warning_errno(r, "rtnl: received nexthop message without NHA_ID attribute, ignoring: %m");
                return 0;
        } else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get NHA_ID attribute, ignoring: %m");
                return 0;
        } else if (id == 0) {
                log_warning("rtnl: received nexthop message with invalid nexthop ID, ignoring: %m");
                return 0;
        }

        NextHop *nexthop = NULL;
        (void) nexthop_get_by_id(m, id, &nexthop);

        if (type == RTM_DELNEXTHOP) {
                if (nexthop)
                        nexthop_forget(m, nexthop, "Forgetting removed");
                else
                        log_nexthop_debug(&(const NextHop) { .id = id }, "Kernel removed unknown", m);

                return 0;
        }

        Request *req = NULL;
        (void) nexthop_get_request_by_id(m, id, &req);

        /* If we did not know the nexthop, then save it. */
        bool is_new = false;
        if (!nexthop) {
                if (!req && !m->manage_foreign_nexthops) {
                        log_nexthop_debug(&(const NextHop) { .id = id }, "Ignoring received", m);
                        return 0;
                }

                r = nexthop_add_new(m, id, &nexthop);
                if (r < 0) {
                        log_warning_errno(r, "Failed to add received nexthop, ignoring: %m");
                        return 0;
                }

                is_new = true;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        if (req && req->waiting_reply) {
                NextHop *n = ASSERT_PTR(req->userdata);

                nexthop->source = n->source;
                nexthop->provider = n->provider;
        }

        r = sd_rtnl_message_get_family(message, &nexthop->family);
        if (r < 0)
                log_debug_errno(r, "rtnl: could not get nexthop family, ignoring: %m");

        r = sd_rtnl_message_nexthop_get_protocol(message, &nexthop->protocol);
        if (r < 0)
                log_debug_errno(r, "rtnl: could not get nexthop protocol, ignoring: %m");

        r = sd_rtnl_message_nexthop_get_flags(message, &nexthop->flags);
        if (r < 0)
                log_debug_errno(r, "rtnl: could not get nexthop flags, ignoring: %m");

        (void) nexthop_update_group(nexthop, message);

        if (nexthop->family != AF_UNSPEC) {
                r = netlink_message_read_in_addr_union(message, NHA_GATEWAY, nexthop->family, &nexthop->gw.address);
                if (r == -ENODATA)
                        nexthop->gw.address = IN_ADDR_NULL;
                else if (r < 0)
                        log_debug_errno(r, "rtnl: could not get NHA_GATEWAY attribute, ignoring: %m");
        }

        r = sd_netlink_message_has_flag(message, NHA_BLACKHOLE);
        if (r < 0)
                log_debug_errno(r, "rtnl: could not get NHA_BLACKHOLE attribute, ignoring: %m");
        else
                nexthop->blackhole = r;

        uint32_t ifindex;
        r = sd_netlink_message_read_u32(message, NHA_OIF, &ifindex);
        if (r == -ENODATA)
                nexthop->ifindex = 0;
        else if (r < 0)
                log_debug_errno(r, "rtnl: could not get NHA_OIF attribute, ignoring: %m");
        else if (ifindex > INT32_MAX)
                log_debug_errno(r, "rtnl: received invalid NHA_OIF attribute, ignoring: %m");
        else
                nexthop->ifindex = (int) ifindex;

        /* The linux kernel does not set NHA_OID attribute when NHA_BLACKHOLE or NHA_GROUP is set.
         * But let's check that for safety. */
        if (!nexthop_bound_to_link(nexthop) && nexthop->ifindex != 0) {
                log_debug("rtnl: received blackhole or group nexthop with NHA_OIF attribute, ignoring the attribute.");
                nexthop->ifindex = 0;
        }

        nexthop_enter_configured(nexthop);
        if (req)
                nexthop_enter_configured(req->userdata);

        log_nexthop_debug(nexthop, is_new ? "Remembering" : "Received remembered", m);
        return 1;
}

#define log_nexthop_section(nexthop, fmt, ...)                          \
        ({                                                              \
                const NextHop *_nexthop = (nexthop);                    \
                log_section_warning_errno(                              \
                                _nexthop ? _nexthop->section : NULL,    \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [NextHop] section.",     \
                                ##__VA_ARGS__);                         \
        })

static int nexthop_section_verify(NextHop *nh) {
        if (section_is_invalid(nh->section))
                return -EINVAL;

        if (!nh->network->manager->manage_foreign_nexthops && nh->id == 0)
                return log_nexthop_section(nh, "Nexthop without specifying Id= is not supported if ManageForeignNextHops=no is set in networkd.conf.");

        if (nh->family == AF_UNSPEC)
                nh->family = nh->gw.family;
        else if (nh->gw.family != AF_UNSPEC && nh->gw.family != nh->family)
                return log_nexthop_section(nh, "Family= and Gateway= settings for nexthop contradict each other.");

        assert(nh->gw.family == nh->family || nh->gw.family == AF_UNSPEC);

        if (!hashmap_isempty(nh->group)) {
                if (in_addr_is_set(nh->family, &nh->gw.address))
                        return log_nexthop_section(nh, "Nexthop group cannot have gateway address.");

                if (nh->family != AF_UNSPEC)
                        return log_nexthop_section(nh, "Nexthop group cannot have Family= setting.");

                if (nh->blackhole)
                        return log_nexthop_section(nh, "Nexthop group cannot be a blackhole.");

                if (nh->onlink > 0)
                        return log_nexthop_section(nh, "Nexthop group cannot have on-link flag.");

        } else if (nh->family == AF_UNSPEC)
                /* When neither Family=, Gateway=, nor Group= is specified, assume IPv4. */
                nh->family = AF_INET;

        if (nh->blackhole) {
                if (in_addr_is_set(nh->family, &nh->gw.address))
                        return log_nexthop_section(nh, "Blackhole nexthop cannot have gateway address.");

                if (nh->onlink > 0)
                        return log_nexthop_section(nh, "Blackhole nexthop cannot have on-link flag.");
        }

        if (nh->onlink < 0 && in_addr_is_set(nh->family, &nh->gw.address) &&
            ordered_hashmap_isempty(nh->network->addresses_by_section)) {
                /* If no address is configured, in most cases the gateway cannot be reachable.
                 * TODO: we may need to improve the condition above. */
                log_section_warning(nh->section, "Nexthop with Gateway= specified, but no static address configured. Enabling OnLink= option.");
                nh->onlink = true;
        }

        if (nh->onlink >= 0)
                SET_FLAG(nh->flags, RTNH_F_ONLINK, nh->onlink);

        return 0;
}

int network_drop_invalid_nexthops(Network *network) {
        _cleanup_hashmap_free_ Hashmap *nexthops = NULL;
        NextHop *nh;
        int r;

        assert(network);

        ORDERED_HASHMAP_FOREACH(nh, network->nexthops_by_section) {
                if (nexthop_section_verify(nh) < 0) {
                        nexthop_detach(nh);
                        continue;
                }

                if (nh->id == 0)
                        continue;

                /* Always use the setting specified later. So, remove the previously assigned setting. */
                NextHop *dup = hashmap_remove(nexthops, UINT32_TO_PTR(nh->id));
                if (dup) {
                        log_warning("%s: Duplicated nexthop settings for ID %"PRIu32" is specified at line %u and %u, "
                                    "dropping the nexthop setting specified at line %u.",
                                    dup->section->filename,
                                    nh->id, nh->section->line,
                                    dup->section->line, dup->section->line);
                        /* nexthop_detach() will drop the nexthop from nexthops_by_section. */
                        nexthop_detach(dup);
                }

                r = hashmap_ensure_put(&nexthops, NULL, UINT32_TO_PTR(nh->id), nh);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

        return 0;
}

int manager_build_nexthop_ids(Manager *manager) {
        Network *network;
        int r;

        assert(manager);

        if (!manager->manage_foreign_nexthops)
                return 0;

        manager->nexthop_ids = set_free(manager->nexthop_ids);

        ORDERED_HASHMAP_FOREACH(network, manager->networks) {
                NextHop *nh;

                ORDERED_HASHMAP_FOREACH(nh, network->nexthops_by_section) {
                        if (nh->id == 0)
                                continue;

                        r = set_ensure_put(&manager->nexthop_ids, NULL, UINT32_TO_PTR(nh->id));
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int config_parse_nexthop_family(
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

        int *family = ASSERT_PTR(data);

        if (isempty(rvalue))
                *family = AF_UNSPEC;
        else if (streq(rvalue, "ipv4"))
                *family = AF_INET;
        else if (streq(rvalue, "ipv6"))
                *family = AF_INET6;
        else
                return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);

        return 1;
}

static int config_parse_nexthop_group(
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

        Hashmap **group = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *group = hashmap_free(*group);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ struct nexthop_grp *nhg = NULL;
                _cleanup_free_ char *word = NULL;
                uint32_t w;
                char *sep;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        return 1;

                nhg = new0(struct nexthop_grp, 1);
                if (!nhg)
                        return log_oom();

                sep = strchr(word, ':');
                if (sep) {
                        *sep++ = '\0';
                        r = safe_atou32(sep, &w);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse weight for nexthop group, ignoring assignment: %s:%s",
                                           word, sep);
                                continue;
                        }
                        if (w == 0 || w > 256) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "Invalid weight for nexthop group, ignoring assignment: %s:%s",
                                           word, sep);
                                continue;
                        }
                        /* See comments in config_parse_multipath_route(). */
                        nhg->weight = w - 1;
                }

                r = safe_atou32(word, &nhg->id);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse nexthop ID in %s=, ignoring assignment: %s%s%s",
                                   lvalue, word, sep ? ":" : "", strempty(sep));
                        continue;
                }
                if (nhg->id == 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Nexthop ID in %s= must be positive, ignoring assignment: %s%s%s",
                                   lvalue, word, sep ? ":" : "", strempty(sep));
                        continue;
                }

                r = hashmap_ensure_put(group, &trivial_hash_ops_value_free, UINT32_TO_PTR(nhg->id), nhg);
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EEXIST) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Nexthop ID %"PRIu32" is specified multiple times in %s=, ignoring assignment: %s%s%s",
                                   nhg->id, lvalue, word, sep ? ":" : "", strempty(sep));
                        continue;
                }
                assert(r > 0);
                TAKE_PTR(nhg);
        }
}

int config_parse_nexthop_section(
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

        static const ConfigSectionParser table[_NEXTHOP_CONF_PARSER_MAX] = {
                [NEXTHOP_ID]        = { .parser = config_parse_uint32,         .ltype = 0, .offset = offsetof(NextHop, id),        },
                [NEXTHOP_GATEWAY]   = { .parser = config_parse_in_addr_data,   .ltype = 0, .offset = offsetof(NextHop, gw),        },
                [NEXTHOP_FAMILY]    = { .parser = config_parse_nexthop_family, .ltype = 0, .offset = offsetof(NextHop, family),    },
                [NEXTHOP_ONLINK]    = { .parser = config_parse_tristate,       .ltype = 0, .offset = offsetof(NextHop, onlink),    },
                [NEXTHOP_BLACKHOLE] = { .parser = config_parse_bool,           .ltype = 0, .offset = offsetof(NextHop, blackhole), },
                [NEXTHOP_GROUP]     = { .parser = config_parse_nexthop_group,  .ltype = 0, .offset = offsetof(NextHop, group),     },
        };

        _cleanup_(nexthop_unref_or_set_invalidp) NextHop *nexthop = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = nexthop_new_static(network, filename, section_line, &nexthop);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, nexthop);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(nexthop);
        return 0;
}

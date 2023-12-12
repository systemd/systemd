/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc.
 */

#include <net/if.h>
#include <linux/nexthop.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"

NextHop *nexthop_free(NextHop *nexthop) {
        if (!nexthop)
                return NULL;

        if (nexthop->network) {
                assert(nexthop->section);
                hashmap_remove(nexthop->network->nexthops_by_section, nexthop->section);
        }

        config_section_free(nexthop->section);

        if (nexthop->link) {
                set_remove(nexthop->link->nexthops, nexthop);

                if (nexthop->link->manager && nexthop->id > 0)
                        hashmap_remove(nexthop->link->manager->nexthops_by_id, UINT32_TO_PTR(nexthop->id));
        }

        if (nexthop->manager) {
                set_remove(nexthop->manager->nexthops, nexthop);

                if (nexthop->id > 0)
                        hashmap_remove(nexthop->manager->nexthops_by_id, UINT32_TO_PTR(nexthop->id));
        }

        hashmap_free_free(nexthop->group);

        return mfree(nexthop);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(NextHop, nexthop_free);

static int nexthop_new(NextHop **ret) {
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;

        nexthop = new(NextHop, 1);
        if (!nexthop)
                return -ENOMEM;

        *nexthop = (NextHop) {
                .family = AF_UNSPEC,
                .onlink = -1,
        };

        *ret = TAKE_PTR(nexthop);

        return 0;
}

static int nexthop_new_static(Network *network, const char *filename, unsigned section_line, NextHop **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        nexthop = hashmap_get(network->nexthops_by_section, n);
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

        r = hashmap_ensure_put(&network->nexthops_by_section, &config_section_hash_ops, nexthop->section, nexthop);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nexthop);
        return 0;
}

static void nexthop_hash_func(const NextHop *nexthop, struct siphash *state) {
        assert(nexthop);

        siphash24_compress(&nexthop->protocol, sizeof(nexthop->protocol), state);
        siphash24_compress(&nexthop->id, sizeof(nexthop->id), state);
        siphash24_compress(&nexthop->blackhole, sizeof(nexthop->blackhole), state);
        siphash24_compress(&nexthop->family, sizeof(nexthop->family), state);

        switch (nexthop->family) {
        case AF_INET:
        case AF_INET6:
                siphash24_compress(&nexthop->gw, FAMILY_ADDRESS_SIZE(nexthop->family), state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int nexthop_compare_func(const NextHop *a, const NextHop *b) {
        int r;

        r = CMP(a->protocol, b->protocol);
        if (r != 0)
                return r;

        r = CMP(a->id, b->id);
        if (r != 0)
                return r;

        r = CMP(a->blackhole, b->blackhole);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        if (IN_SET(a->family, AF_INET, AF_INET6))
                return memcmp(&a->gw, &b->gw, FAMILY_ADDRESS_SIZE(a->family));

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                nexthop_hash_ops,
                NextHop,
                nexthop_hash_func,
                nexthop_compare_func,
                nexthop_free);

static bool nexthop_equal(const NextHop *a, const NextHop *b) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        return nexthop_compare_func(a, b) == 0;
}

static int nexthop_dup(const NextHop *src, NextHop **ret) {
        _cleanup_(nexthop_freep) NextHop *dest = NULL;
        struct nexthop_grp *nhg;
        int r;

        assert(src);
        assert(ret);

        dest = newdup(NextHop, src, 1);
        if (!dest)
                return -ENOMEM;

        /* unset all pointers */
        dest->manager = NULL;
        dest->link = NULL;
        dest->network = NULL;
        dest->section = NULL;
        dest->group = NULL;

        HASHMAP_FOREACH(nhg, src->group) {
                _cleanup_free_ struct nexthop_grp *g = NULL;

                g = newdup(struct nexthop_grp, nhg, 1);
                if (!g)
                        return -ENOMEM;

                r = hashmap_ensure_put(&dest->group, NULL, UINT32_TO_PTR(g->id), g);
                if (r < 0)
                        return r;
                if (r > 0)
                        TAKE_PTR(g);
        }

        *ret = TAKE_PTR(dest);
        return 0;
}

int manager_get_nexthop_by_id(Manager *manager, uint32_t id, NextHop **ret) {
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

static bool nexthop_owned_by_link(const NextHop *nexthop) {
        return !nexthop->blackhole && hashmap_isempty(nexthop->group);
}

static int nexthop_get(Manager *manager, Link *link, NextHop *in, NextHop **ret) {
        NextHop *nexthop;
        Set *nexthops;

        assert(in);

        if (nexthop_owned_by_link(in)) {
                if (!link)
                        return -ENOENT;

                nexthops = link->nexthops;
        } else {
                if (!manager)
                        return -ENOENT;

                nexthops = manager->nexthops;
        }

        nexthop = set_get(nexthops, in);
        if (nexthop) {
                if (ret)
                        *ret = nexthop;
                return 0;
        }

        if (in->id > 0)
                return -ENOENT;

        /* Also find nexthop configured without ID. */
        SET_FOREACH(nexthop, nexthops) {
                uint32_t id;
                bool found;

                id = nexthop->id;
                nexthop->id = 0;
                found = nexthop_equal(nexthop, in);
                nexthop->id = id;

                if (!found)
                        continue;

                if (ret)
                        *ret = nexthop;
                return 0;
        }

        return -ENOENT;
}

static int nexthop_add(Manager *manager, Link *link, NextHop *nexthop) {
        int r;

        assert(nexthop);
        assert(nexthop->id > 0);

        if (nexthop_owned_by_link(nexthop)) {
                assert(link);

                r = set_ensure_put(&link->nexthops, &nexthop_hash_ops, nexthop);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EEXIST;

                nexthop->link = link;

                manager = link->manager;
        } else {
                assert(manager);

                r = set_ensure_put(&manager->nexthops, &nexthop_hash_ops, nexthop);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EEXIST;

                nexthop->manager = manager;
        }

        return hashmap_ensure_put(&manager->nexthops_by_id, NULL, UINT32_TO_PTR(nexthop->id), nexthop);
}

static int nexthop_acquire_id(Manager *manager, NextHop *nexthop) {
        _cleanup_set_free_ Set *ids = NULL;
        Network *network;
        uint32_t id;
        int r;

        assert(manager);
        assert(nexthop);

        if (nexthop->id > 0)
                return 0;

        /* If ManageForeignNextHops=no, nexthop with id == 0 should be already filtered by
         * nexthop_section_verify(). */
        assert(manager->manage_foreign_nexthops);

        /* Find the lowest unused ID. */

        ORDERED_HASHMAP_FOREACH(network, manager->networks) {
                NextHop *tmp;

                HASHMAP_FOREACH(tmp, network->nexthops_by_section) {
                        if (tmp->id == 0)
                                continue;

                        r = set_ensure_put(&ids, NULL, UINT32_TO_PTR(tmp->id));
                        if (r < 0)
                                return r;
                }
        }

        for (id = 1; id < UINT32_MAX; id++) {
                if (manager_get_nexthop_by_id(manager, id, NULL) >= 0)
                        continue;
                if (set_contains(ids, UINT32_TO_PTR(id)))
                        continue;
                break;
        }

        nexthop->id = id;
        return 0;
}

static void log_nexthop_debug(const NextHop *nexthop, const char *str, const Link *link) {
        _cleanup_free_ char *state = NULL, *group = NULL, *flags = NULL;
        struct nexthop_grp *nhg;

        assert(nexthop);
        assert(str);

        /* link may be NULL. */

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(nexthop->state, &state);
        (void) route_flags_to_string_alloc(nexthop->flags, &flags);

        HASHMAP_FOREACH(nhg, nexthop->group)
                (void) strextendf_with_separator(&group, ",", "%"PRIu32":%"PRIu32, nhg->id, nhg->weight+1u);

        log_link_debug(link, "%s %s nexthop (%s): id: %"PRIu32", gw: %s, blackhole: %s, group: %s, flags: %s",
                       str, strna(network_config_source_to_string(nexthop->source)), strna(state),
                       nexthop->id,
                       IN_ADDR_TO_STRING(nexthop->family, &nexthop->gw),
                       yes_no(nexthop->blackhole), strna(group), strna(flags));
}

static int nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);

        /* link may be NULL. */

        if (link && IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_link_message_warning_errno(link, m, r, "Could not drop nexthop, ignoring");

        return 1;
}

static int nexthop_remove(NextHop *nexthop) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        Manager *manager;
        Link *link;
        int r;

        assert(nexthop);
        assert(nexthop->manager || (nexthop->link && nexthop->link->manager));

        /* link may be NULL. */
        link = nexthop->link;
        manager = nexthop->manager ?: nexthop->link->manager;

        if (nexthop->id == 0) {
                log_link_debug(link, "Cannot remove nexthop without valid ID, ignoring.");
                return 0;
        }

        log_nexthop_debug(nexthop, "Removing", link);

        r = sd_rtnl_message_new_nexthop(manager->rtnl, &m, RTM_DELNEXTHOP, AF_UNSPEC, RTPROT_UNSPEC);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELNEXTHOP message: %m");

        r = sd_netlink_message_append_u32(m, NHA_ID, nexthop->id);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NHA_ID attribute: %m");

        r = netlink_call_async(manager->rtnl, NULL, m, nexthop_remove_handler,
                               link ? link_netlink_destroy_callback : NULL, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link); /* link may be NULL, link_ref() is OK with that */

        nexthop_enter_removing(nexthop);
        return 0;
}

static int nexthop_configure(NextHop *nexthop, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nexthop);
        assert(IN_SET(nexthop->family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_nexthop_debug(nexthop, "Configuring", link);

        r = sd_rtnl_message_new_nexthop(link->manager->rtnl, &m, RTM_NEWNEXTHOP, nexthop->family, nexthop->protocol);
        if (r < 0)
                return r;

        if (nexthop->id > 0) {
                r = sd_netlink_message_append_u32(m, NHA_ID, nexthop->id);
                if (r < 0)
                        return r;
        }

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
                r = sd_netlink_message_append_u32(m, NHA_OIF, link->ifindex);
                if (r < 0)
                        return r;

                if (in_addr_is_set(nexthop->family, &nexthop->gw)) {
                        r = netlink_message_append_in_addr_union(m, NHA_GATEWAY, nexthop->family, &nexthop->gw);
                        if (r < 0)
                                return r;

                        r = sd_rtnl_message_nexthop_set_flags(m, nexthop->flags & RTNH_F_ONLINK);
                        if (r < 0)
                                return r;
                }
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int static_nexthop_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, NextHop *nexthop) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set nexthop");
                link_enter_failed(link);
                return 1;
        }

        if (link->static_nexthop_messages == 0) {
                log_link_debug(link, "Nexthops set");
                link->static_nexthops_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static bool nexthop_is_ready_to_configure(Link *link, const NextHop *nexthop) {
        struct nexthop_grp *nhg;

        assert(link);
        assert(nexthop);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (nexthop_owned_by_link(nexthop)) {
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
                NextHop *g;

                if (manager_get_nexthop_by_id(link->manager, nhg->id, &g) < 0)
                        return false;

                if (!nexthop_exists(g))
                        return false;
        }

        if (nexthop->id == 0) {
                Request *req;

                ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                        if (req->type != REQUEST_TYPE_NEXTHOP)
                                continue;
                        if (((NextHop*) req->userdata)->id != 0)
                                return false; /* first configure nexthop with id. */
                }
        }

        return gateway_is_ready(link, FLAGS_SET(nexthop->flags, RTNH_F_ONLINK), nexthop->family, &nexthop->gw);
}

static int nexthop_process_request(Request *req, Link *link, NextHop *nexthop) {
        int r;

        assert(req);
        assert(link);
        assert(nexthop);

        if (!nexthop_is_ready_to_configure(link, nexthop))
                return 0;

        r = nexthop_configure(nexthop, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure nexthop");

        nexthop_enter_configuring(nexthop);
        return 1;
}

static int link_request_nexthop(Link *link, NextHop *nexthop) {
        NextHop *existing;
        int r;

        assert(link);
        assert(nexthop);
        assert(nexthop->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (nexthop_get(link->manager, link, nexthop, &existing) < 0) {
                _cleanup_(nexthop_freep) NextHop *tmp = NULL;

                r = nexthop_dup(nexthop, &tmp);
                if (r < 0)
                        return r;

                r = nexthop_acquire_id(link->manager, tmp);
                if (r < 0)
                        return r;

                r = nexthop_add(link->manager, link, tmp);
                if (r < 0)
                        return r;

                existing = TAKE_PTR(tmp);
        } else
                existing->source = nexthop->source;

        log_nexthop_debug(existing, "Requesting", link);
        r = link_queue_request_safe(link, REQUEST_TYPE_NEXTHOP,
                                    existing, NULL,
                                    nexthop_hash_func,
                                    nexthop_compare_func,
                                    nexthop_process_request,
                                    &link->static_nexthop_messages,
                                    static_nexthop_handler,
                                    NULL);
        if (r <= 0)
                return r;

        nexthop_enter_requesting(existing);
        return 1;
}

int link_request_static_nexthops(Link *link, bool only_ipv4) {
        NextHop *nh;
        int r;

        assert(link);
        assert(link->network);

        link->static_nexthops_configured = false;

        HASHMAP_FOREACH(nh, link->network->nexthops_by_section) {
                if (only_ipv4 && nh->family != AF_INET)
                        continue;

                r = link_request_nexthop(link, nh);
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

static void manager_mark_nexthops(Manager *manager, bool foreign, const Link *except) {
        NextHop *nexthop;
        Link *link;

        assert(manager);

        /* First, mark all nexthops. */
        SET_FOREACH(nexthop, manager->nexthops) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                /* When 'foreign' is true, mark only foreign nexthops, and vice versa. */
                if (foreign != (nexthop->source == NETWORK_CONFIG_SOURCE_FOREIGN))
                        continue;

                /* Ignore nexthops not assigned yet or already removed. */
                if (!nexthop_exists(nexthop))
                        continue;

                nexthop_mark(nexthop);
        }

        /* Then, unmark all nexthops requested by active links. */
        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (link == except)
                        continue;

                if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                HASHMAP_FOREACH(nexthop, link->network->nexthops_by_section) {
                        NextHop *existing;

                        if (nexthop_get(manager, NULL, nexthop, &existing) >= 0)
                                nexthop_unmark(existing);
                }
        }
}

static int manager_drop_marked_nexthops(Manager *manager) {
        NextHop *nexthop;
        int r = 0;

        assert(manager);

        SET_FOREACH(nexthop, manager->nexthops) {
                if (!nexthop_is_marked(nexthop))
                        continue;

                RET_GATHER(r, nexthop_remove(nexthop));
        }

        return r;
}

int link_drop_foreign_nexthops(Link *link) {
        NextHop *nexthop;
        int r = 0;

        assert(link);
        assert(link->manager);
        assert(link->network);

        /* First, mark all nexthops. */
        SET_FOREACH(nexthop, link->nexthops) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                /* Do not remove nexthops we configured. */
                if (nexthop->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore nexthops not assigned yet or already removed. */
                if (!nexthop_exists(nexthop))
                        continue;

                nexthop_mark(nexthop);
        }

        /* Then, unmark all nexthops requested by active links. */
        HASHMAP_FOREACH(nexthop, link->network->nexthops_by_section) {
                NextHop *existing;

                if (nexthop_get(NULL, link, nexthop, &existing) >= 0)
                        nexthop_unmark(existing);
        }

        /* Finally, remove all marked rules. */
        SET_FOREACH(nexthop, link->nexthops) {
                if (!nexthop_is_marked(nexthop))
                        continue;

                RET_GATHER(r, nexthop_remove(nexthop));
        }

        manager_mark_nexthops(link->manager, /* foreign = */ true, NULL);

        return RET_GATHER(r, manager_drop_marked_nexthops(link->manager));
}

int link_drop_managed_nexthops(Link *link) {
        NextHop *nexthop;
        int r = 0;

        assert(link);
        assert(link->manager);

        SET_FOREACH(nexthop, link->nexthops) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                /* Do not touch addresses managed by kernel or other tools. */
                if (nexthop->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore nexthops not assigned yet or already removing. */
                if (!nexthop_exists(nexthop))
                        continue;

                RET_GATHER(r, nexthop_remove(nexthop));
        }

        manager_mark_nexthops(link->manager, /* foreign = */ false, link);

        return RET_GATHER(r, manager_drop_marked_nexthops(link->manager));
}

void link_foreignize_nexthops(Link *link) {
        NextHop *nexthop;

        assert(link);

        SET_FOREACH(nexthop, link->nexthops)
                nexthop->source = NETWORK_CONFIG_SOURCE_FOREIGN;

        manager_mark_nexthops(link->manager, /* foreign = */ false, link);

        SET_FOREACH(nexthop, link->manager->nexthops) {
                if (!nexthop_is_marked(nexthop))
                        continue;

                nexthop->source = NETWORK_CONFIG_SOURCE_FOREIGN;
        }
}

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(nexthop_freep) NextHop *tmp = NULL;
        _cleanup_free_ void *raw_group = NULL;
        NextHop *nexthop = NULL;
        size_t raw_group_size;
        uint32_t ifindex;
        uint16_t type;
        Link *link = NULL;
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

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEXTHOP, RTM_DELNEXTHOP)) {
                log_warning("rtnl: received unexpected message type %u when processing nexthop, ignoring.", type);
                return 0;
        }

        r = sd_netlink_message_read_u32(message, NHA_OIF, &ifindex);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get NHA_OIF attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                if (ifindex <= 0) {
                        log_warning("rtnl: received nexthop message with invalid ifindex %"PRIu32", ignoring.", ifindex);
                        return 0;
                }

                r = link_get_by_index(m, ifindex, &link);
                if (r < 0) {
                        if (!m->enumerating)
                                log_warning("rtnl: received nexthop message for link (%"PRIu32") we do not know about, ignoring", ifindex);
                        return 0;
                }
        }

        r = nexthop_new(&tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_get_family(message, &tmp->family);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get nexthop family, ignoring: %m");
                return 0;
        } else if (!IN_SET(tmp->family, AF_UNSPEC, AF_INET, AF_INET6)) {
                log_link_debug(link, "rtnl: received nexthop message with invalid family %d, ignoring.", tmp->family);
                return 0;
        }

        r = sd_rtnl_message_nexthop_get_protocol(message, &tmp->protocol);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get nexthop protocol, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_nexthop_get_flags(message, &tmp->flags);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get nexthop flags, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_data(message, NHA_GROUP, &raw_group_size, &raw_group);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_GROUP attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                struct nexthop_grp *group = raw_group;
                size_t n_group;

                if (raw_group_size == 0 || raw_group_size % sizeof(struct nexthop_grp) != 0) {
                        log_link_warning(link, "rtnl: received nexthop message with invalid nexthop group size, ignoring.");
                        return 0;
                }

                assert((uintptr_t) group % alignof(struct nexthop_grp) == 0);

                n_group = raw_group_size / sizeof(struct nexthop_grp);
                for (size_t i = 0; i < n_group; i++) {
                        _cleanup_free_ struct nexthop_grp *nhg = NULL;

                        if (group[i].id == 0) {
                                log_link_warning(link, "rtnl: received nexthop message with invalid ID in group, ignoring.");
                                return 0;
                        }
                        if (group[i].weight > 254) {
                                log_link_warning(link, "rtnl: received nexthop message with invalid weight in group, ignoring.");
                                return 0;
                        }

                        nhg = newdup(struct nexthop_grp, group + i, 1);
                        if (!nhg)
                                return log_oom();

                        r = hashmap_ensure_put(&tmp->group, NULL, UINT32_TO_PTR(nhg->id), nhg);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to store nexthop group, ignoring: %m");
                                return 0;
                        }
                        if (r > 0)
                                TAKE_PTR(nhg);
                }
        }

        if (tmp->family != AF_UNSPEC) {
                r = netlink_message_read_in_addr_union(message, NHA_GATEWAY, tmp->family, &tmp->gw);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: could not get NHA_GATEWAY attribute, ignoring: %m");
                        return 0;
                }
        }

        r = sd_netlink_message_has_flag(message, NHA_BLACKHOLE);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_BLACKHOLE attribute, ignoring: %m");
                return 0;
        }
        tmp->blackhole = r;

        r = sd_netlink_message_read_u32(message, NHA_ID, &tmp->id);
        if (r == -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received nexthop message without NHA_ID attribute, ignoring: %m");
                return 0;
        } else if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_ID attribute, ignoring: %m");
                return 0;
        } else if (tmp->id == 0) {
                log_link_warning(link, "rtnl: received nexthop message with invalid nexthop ID, ignoring: %m");
                return 0;
        }

        /* All blackhole or group nexthops are managed by Manager. Note that the linux kernel does not
         * set NHA_OID attribute when NHA_BLACKHOLE or NHA_GROUP is set. Just for safety. */
        if (!nexthop_owned_by_link(tmp))
                link = NULL;

        (void) nexthop_get(m, link, tmp, &nexthop);

        switch (type) {
        case RTM_NEWNEXTHOP:
                if (nexthop) {
                        nexthop->flags = tmp->flags;
                        nexthop_enter_configured(nexthop);
                        log_nexthop_debug(tmp, "Received remembered", link);
                } else {
                        nexthop_enter_configured(tmp);
                        log_nexthop_debug(tmp, "Remembering", link);

                        r = nexthop_add(m, link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not remember foreign nexthop, ignoring: %m");
                                return 0;
                        }

                        TAKE_PTR(tmp);
                }

                break;
        case RTM_DELNEXTHOP:
                if (nexthop) {
                        nexthop_enter_removed(nexthop);
                        if (nexthop->state == 0) {
                                log_nexthop_debug(nexthop, "Forgetting", link);
                                nexthop_free(nexthop);
                        } else
                                log_nexthop_debug(nexthop, "Removed", link);
                } else
                        log_nexthop_debug(tmp, "Kernel removed unknown", link);
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int nexthop_section_verify(NextHop *nh) {
        if (section_is_invalid(nh->section))
                return -EINVAL;

        if (!nh->network->manager->manage_foreign_nexthops && nh->id == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [NextHop] section without specifying Id= is not supported "
                                         "if ManageForeignNextHops=no is set in networkd.conf. "
                                         "Ignoring [NextHop] section from line %u.",
                                         nh->section->filename, nh->section->line);

        if (!hashmap_isempty(nh->group)) {
                if (in_addr_is_set(nh->family, &nh->gw))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: nexthop group cannot have gateway address. "
                                                 "Ignoring [NextHop] section from line %u.",
                                                 nh->section->filename, nh->section->line);

                if (nh->family != AF_UNSPEC)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: nexthop group cannot have Family= setting. "
                                                 "Ignoring [NextHop] section from line %u.",
                                                 nh->section->filename, nh->section->line);

                if (nh->blackhole && in_addr_is_set(nh->family, &nh->gw))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: nexthop group cannot be a blackhole. "
                                                 "Ignoring [NextHop] section from line %u.",
                                                 nh->section->filename, nh->section->line);
        } else if (nh->family == AF_UNSPEC)
                /* When neither Family=, Gateway=, nor Group= is specified, assume IPv4. */
                nh->family = AF_INET;

        if (nh->blackhole && in_addr_is_set(nh->family, &nh->gw))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: blackhole nexthop cannot have gateway address. "
                                         "Ignoring [NextHop] section from line %u.",
                                         nh->section->filename, nh->section->line);

        if (nh->onlink < 0 && in_addr_is_set(nh->family, &nh->gw) &&
            ordered_hashmap_isempty(nh->network->addresses_by_section)) {
                /* If no address is configured, in most cases the gateway cannot be reachable.
                 * TODO: we may need to improve the condition above. */
                log_warning("%s: Gateway= without static address configured. "
                            "Enabling OnLink= option.",
                            nh->section->filename);
                nh->onlink = true;
        }

        if (nh->onlink >= 0)
                SET_FLAG(nh->flags, RTNH_F_ONLINK, nh->onlink);

        return 0;
}

void network_drop_invalid_nexthops(Network *network) {
        NextHop *nh;

        assert(network);

        HASHMAP_FOREACH(nh, network->nexthops_by_section)
                if (nexthop_section_verify(nh) < 0)
                        nexthop_free(nh);
}

int config_parse_nexthop_id(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        uint32_t id;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                n->id = 0;
                TAKE_PTR(n);
                return 0;
        }

        r = safe_atou32(rvalue, &id);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse nexthop id \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }
        if (id == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid nexthop id \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->id = id;
        TAKE_PTR(n);
        return 0;
}

int config_parse_nexthop_gateway(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                n->family = AF_UNSPEC;
                n->gw = IN_ADDR_NULL;

                TAKE_PTR(n);
                return 0;
        }

        r = in_addr_from_string_auto(rvalue, &n->family, &n->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_nexthop_family(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        AddressFamily a;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue) &&
            !in_addr_is_set(n->family, &n->gw)) {
                /* Accept an empty string only when Gateway= is null or not specified. */
                n->family = AF_UNSPEC;
                TAKE_PTR(n);
                return 0;
        }

        a = nexthop_address_family_from_string(rvalue);
        if (a < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        if (in_addr_is_set(n->family, &n->gw) &&
            ((a == ADDRESS_FAMILY_IPV4 && n->family == AF_INET6) ||
             (a == ADDRESS_FAMILY_IPV6 && n->family == AF_INET))) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified family '%s' conflicts with the family of the previously specified Gateway=, "
                           "ignoring assignment.", rvalue);
                return 0;
        }

        switch (a) {
        case ADDRESS_FAMILY_IPV4:
                n->family = AF_INET;
                break;
        case ADDRESS_FAMILY_IPV6:
                n->family = AF_INET6;
                break;
        default:
                assert_not_reached();
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_nexthop_onlink(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_tristate(rvalue, &n->onlink);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_nexthop_blackhole(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        n->blackhole = r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_nexthop_group(
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

        _cleanup_(nexthop_free_or_set_invalidp) NextHop *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                n->group = hashmap_free_free(n->group);
                TAKE_PTR(n);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ struct nexthop_grp *nhg = NULL;
                _cleanup_free_ char *word = NULL;
                uint32_t w;
                char *sep;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

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

                r = hashmap_ensure_put(&n->group, NULL, UINT32_TO_PTR(nhg->id), nhg);
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

        TAKE_PTR(n);
        return 0;
}

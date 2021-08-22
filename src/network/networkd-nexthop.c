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
#include "networkd-route.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"

NextHop *nexthop_free(NextHop *nexthop) {
        if (!nexthop)
                return NULL;

        if (nexthop->network) {
                assert(nexthop->section);
                hashmap_remove(nexthop->network->nexthops_by_section, nexthop->section);
        }

        network_config_section_free(nexthop->section);

        if (nexthop->link) {
                set_remove(nexthop->link->nexthops, nexthop);
                set_remove(nexthop->link->nexthops_foreign, nexthop);

                if (nexthop->link->manager && nexthop->id > 0)
                        hashmap_remove(nexthop->link->manager->nexthops_by_id, UINT32_TO_PTR(nexthop->id));
        }

        if (nexthop->manager) {
                set_remove(nexthop->manager->nexthops, nexthop);
                set_remove(nexthop->manager->nexthops_foreign, nexthop);

                if (nexthop->id > 0)
                        hashmap_remove(nexthop->manager->nexthops_by_id, UINT32_TO_PTR(nexthop->id));
        }

        hashmap_free_free(nexthop->group);

        return mfree(nexthop);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(NextHop, nexthop_free);

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
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
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

        r = hashmap_ensure_put(&network->nexthops_by_section, &network_config_hash_ops, nexthop->section, nexthop);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nexthop);
        return 0;
}

void nexthop_hash_func(const NextHop *nexthop, struct siphash *state) {
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

int nexthop_compare_func(const NextHop *a, const NextHop *b) {
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

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
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

static int nexthop_get(Manager *manager, Link *link, const NextHop *in, NextHop **ret) {
        NextHop *existing;

        assert(manager || link);
        assert(in);

        existing = set_get(link ? link->nexthops : manager->nexthops, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link ? link->nexthops_foreign : manager->nexthops_foreign, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static int nexthop_add_internal(Manager *manager, Link *link, Set **nexthops, const NextHop *in, NextHop **ret) {
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;
        int r;

        assert(manager || link);
        assert(nexthops);
        assert(in);

        r = nexthop_dup(in, &nexthop);
        if (r < 0)
                return r;

        r = set_ensure_put(nexthops, &nexthop_hash_ops, nexthop);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        nexthop->link = link;
        nexthop->manager = manager;

        if (ret)
                *ret = nexthop;

        TAKE_PTR(nexthop);
        return 0;
}

static int nexthop_add_foreign(Manager *manager, Link *link, const NextHop *in, NextHop **ret) {
        assert(manager || link);
        return nexthop_add_internal(manager, link, link ? &link->nexthops_foreign : &manager->nexthops_foreign, in, ret);
}

static bool nexthop_has_link(const NextHop *nexthop) {
        return !nexthop->blackhole && hashmap_isempty(nexthop->group);
}

static int nexthop_add(Link *link, const NextHop *in, NextHop **ret) {
        bool by_manager;
        NextHop *nexthop;
        int r;

        assert(link);
        assert(in);

        by_manager = !nexthop_has_link(in);

        if (by_manager)
                r = nexthop_get(link->manager, NULL, in, &nexthop);
        else
                r = nexthop_get(NULL, link, in, &nexthop);
        if (r == -ENOENT) {
                /* NextHop does not exist, create a new one */
                r = nexthop_add_internal(link->manager,
                                         by_manager ? NULL : link,
                                         by_manager ? &link->manager->nexthops : &link->nexthops,
                                         in, &nexthop);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign nexthop */
                r = set_ensure_put(by_manager ? &link->manager->nexthops : &link->nexthops,
                                   &nexthop_hash_ops, nexthop);
                if (r < 0)
                        return r;

                set_remove(by_manager ? link->manager->nexthops_foreign : link->nexthops_foreign, nexthop);
        } else if (r == 1) {
                /* NextHop exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = nexthop;
        return 0;
}

static int nexthop_update(Manager *manager, Link *link, NextHop *nexthop, const NextHop *in) {
        Set *nexthops;
        int r;

        /* link may be NULL. */

        assert(manager);
        assert(nexthop);
        assert(in);
        assert(in->id > 0);

        /* This updates nexthop ID if necessary, and register the nexthop to Manager. */

        if (nexthop->id > 0) {
                if (nexthop->id == in->id)
                        goto set_manager;
                return -EINVAL;
        }

        nexthops = link ? link->nexthops : manager->nexthops;

        nexthop = set_remove(nexthops, nexthop);
        if (!nexthop)
                return -ENOENT;

        nexthop->id = in->id;

        r = set_put(nexthops, nexthop);
        if (r <= 0) {
                int k;

                /* On failure, revert the change. */
                nexthop->id = 0;
                k = set_put(nexthops, nexthop);
                if (k <= 0) {
                        nexthop_free(nexthop);
                        return k < 0 ? k : -EEXIST;
                }

                return r < 0 ? r : -EEXIST;
        }

set_manager:
        return hashmap_ensure_put(&manager->nexthops_by_id, NULL, UINT32_TO_PTR(nexthop->id), nexthop);
}

static void log_nexthop_debug(const NextHop *nexthop, uint32_t id, const char *str, const Link *link) {
        _cleanup_free_ char *gw = NULL, *new_id = NULL, *group = NULL;
        struct nexthop_grp *nhg;

        assert(nexthop);
        assert(str);

        /* link may be NULL. */

        if (!DEBUG_LOGGING)
                return;

        if (nexthop->id != id)
                (void) asprintf(&new_id, "→%"PRIu32, id);

        (void) in_addr_to_string(nexthop->family, &nexthop->gw, &gw);

        HASHMAP_FOREACH(nhg, nexthop->group)
                (void) strextendf_with_separator(&group, ",", "%"PRIu32":%"PRIu32, nhg->id, nhg->weight+1);

        log_link_debug(link, "%s nexthop: id: %"PRIu32"%s, gw: %s, blackhole: %s, group: %s",
                       str, nexthop->id, strempty(new_id), strna(gw), yes_no(nexthop->blackhole), strna(group));
}

static int link_nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->nexthop_remove_messages > 0);

        link->nexthop_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_link_message_warning_errno(link, m, r, "Could not drop nexthop, ignoring");

        return 1;
}

static int manager_nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Manager *manager) {
        int r;

        assert(m);
        assert(manager);
        assert(manager->nexthop_remove_messages > 0);

        manager->nexthop_remove_messages--;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_message_warning_errno(m, r, "Could not drop nexthop, ignoring");

        return 1;
}

static int nexthop_remove(const NextHop *nexthop, Manager *manager, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(nexthop);
        assert(manager);

        /* link may be NULL. */

        if (nexthop->id == 0) {
                log_link_debug(link, "Cannot remove nexthop without valid ID, ignoring.");
                return 0;
        }

        log_nexthop_debug(nexthop, nexthop->id, "Removing", link);

        r = sd_rtnl_message_new_nexthop(manager->rtnl, &req, RTM_DELNEXTHOP, AF_UNSPEC, RTPROT_UNSPEC);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELNEXTHOP message: %m");

        r = sd_netlink_message_append_u32(req, NHA_ID, nexthop->id);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NHA_ID attribute: %m");

        if (link)
                r = netlink_call_async(manager->rtnl, NULL, req, link_nexthop_remove_handler,
                                       link_netlink_destroy_callback, link);
        else
                r = netlink_call_async(manager->rtnl, NULL, req, manager_nexthop_remove_handler,
                                       NULL, manager);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link); /* link may be NULL, link_ref() is OK with that */

        if (link)
                link->nexthop_remove_messages++;
        else
                manager->nexthop_remove_messages++;

        return 0;
}

static int nexthop_configure(
                const NextHop *nexthop,
                Link *link,
                link_netlink_message_handler_t callback,
                NextHop **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(nexthop->family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(callback);

        log_nexthop_debug(nexthop, nexthop->id, "Configuring", link);

        r = sd_rtnl_message_new_nexthop(link->manager->rtnl, &req,
                                        RTM_NEWNEXTHOP, nexthop->family,
                                        nexthop->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWNEXTHOP message: %m");

        if (nexthop->id > 0) {
                r = sd_netlink_message_append_u32(req, NHA_ID, nexthop->id);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NHA_ID attribute: %m");
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

                r = sd_netlink_message_append_data(req, NHA_GROUP, group, sizeof(struct nexthop_grp) * hashmap_size(nexthop->group));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NHA_GROUP attribute: %m");

        } else if (nexthop->blackhole) {
                r = sd_netlink_message_append_flag(req, NHA_BLACKHOLE);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NHA_BLACKHOLE attribute: %m");
        } else {
                r = sd_netlink_message_append_u32(req, NHA_OIF, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NHA_OIF attribute: %m");

                if (in_addr_is_set(nexthop->family, &nexthop->gw)) {
                        r = netlink_message_append_in_addr_union(req, NHA_GATEWAY, nexthop->family, &nexthop->gw);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append NHA_GATEWAY attribute: %m");

                        if (nexthop->onlink > 0) {
                                r = sd_rtnl_message_nexthop_set_flags(req, RTNH_F_ONLINK);
                                if (r < 0)
                                        return log_link_error_errno(link, r, "Failed to set RTNH_F_ONLINK flag: %m");
                        }
                }
        }

        r = nexthop_add(link, nexthop, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add nexthop: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return r;
}

static int static_nexthop_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->static_nexthop_messages > 0);

        link->static_nexthop_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

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

static int link_request_nexthop(
                Link *link,
                NextHop *nexthop,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        assert(link);
        assert(nexthop);

        log_nexthop_debug(nexthop, nexthop->id, "Requesting", link);
        return link_queue_request(link, REQUEST_TYPE_NEXTHOP, nexthop, consume_object,
                                  message_counter, netlink_handler, ret);
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

                r = link_request_nexthop(link, nh, false, &link->static_nexthop_messages,
                                         static_nexthop_handler, NULL);
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

static bool link_has_nexthop(const Link *link, const NextHop *nexthop) {
        NextHop *net_nexthop;

        assert(link);
        assert(nexthop);

        if (!link->network)
                return false;

        HASHMAP_FOREACH(net_nexthop, link->network->nexthops_by_section)
                if (nexthop_equal(net_nexthop, nexthop))
                        return true;

        return false;
}

static bool links_have_nexthop(const Manager *manager, const NextHop *nexthop, const Link *except) {
        Link *link;

        assert(manager);

        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (link == except)
                        continue;

                if (link_has_nexthop(link, nexthop))
                        return true;
        }

        return false;
}

static int manager_drop_nexthops_internal(Manager *manager, bool foreign, const Link *except) {
        NextHop *nexthop;
        Set *nexthops;
        int k, r = 0;

        assert(manager);

        nexthops = foreign ? manager->nexthops_foreign : manager->nexthops;
        SET_FOREACH(nexthop, nexthops) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                /* The nexthop will be configured later, or already configured by a link. */
                if (links_have_nexthop(manager, nexthop, except))
                        continue;

                /* The existing links do not have the nexthop. Let's drop this now. It may be
                 * re-configured later. */
                k = nexthop_remove(nexthop, manager, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int manager_drop_foreign_nexthops(Manager *manager) {
        return manager_drop_nexthops_internal(manager, true, NULL);
}

static int manager_drop_nexthops(Manager *manager, const Link *except) {
        return manager_drop_nexthops_internal(manager, false, except);
}

int link_drop_foreign_nexthops(Link *link) {
        NextHop *nexthop;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        SET_FOREACH(nexthop, link->nexthops_foreign) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                if (link_has_nexthop(link, nexthop))
                        k = nexthop_add(link, nexthop, NULL);
                else
                        k = nexthop_remove(nexthop, link->manager, link);
                if (k < 0 && r >= 0)
                        r = k;
        }

        k = manager_drop_foreign_nexthops(link->manager);
        if (k < 0 && r >= 0)
                r = k;

        return r;
}

int link_drop_nexthops(Link *link) {
        NextHop *nexthop;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        SET_FOREACH(nexthop, link->nexthops) {
                /* do not touch nexthop created by the kernel */
                if (nexthop->protocol == RTPROT_KERNEL)
                        continue;

                k = nexthop_remove(nexthop, link->manager, link);
                if (k < 0 && r >= 0)
                        r = k;
        }

        k = manager_drop_nexthops(link->manager, link);
        if (k < 0 && r >= 0)
                r = k;

        return r;
}

static bool nexthop_is_ready_to_configure(Link *link, const NextHop *nexthop) {
        struct nexthop_grp *nhg;

        assert(link);
        assert(nexthop);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (!nexthop_has_link(nexthop)) {
                if (link->manager->nexthop_remove_messages > 0)
                        return false;
        } else {
                Link *l;

                /* TODO: fdb nexthop does not require IFF_UP. The conditions below needs to be updated
                 * when fdb nexthop support is added. See rtm_to_nh_config() in net/ipv4/nexthop.c of
                 * kernel. */
                if (link->set_flags_messages > 0)
                        return false;
                if (!FLAGS_SET(link->flags, IFF_UP))
                        return false;

                HASHMAP_FOREACH(l, link->manager->links_by_index) {
                        if (l->address_remove_messages > 0)
                                return false;
                        if (l->nexthop_remove_messages > 0)
                                return false;
                        if (l->route_remove_messages > 0)
                                return false;
                }
        }

        /* All group members must be configured first. */
        HASHMAP_FOREACH(nhg, nexthop->group)
                if (manager_get_nexthop_by_id(link->manager, nhg->id, NULL) < 0)
                        return false;

        if (nexthop->id == 0) {
                Request *req;

                ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                        if (req->type != REQUEST_TYPE_NEXTHOP)
                                continue;
                        if (req->nexthop->id != 0)
                                return false; /* first configure nexthop with id. */
                }
        }

        return gateway_is_ready(link, nexthop->onlink, nexthop->family, &nexthop->gw);
}

int request_process_nexthop(Request *req) {
        NextHop *ret;
        int r;

        assert(req);
        assert(req->link);
        assert(req->nexthop);
        assert(req->type == REQUEST_TYPE_NEXTHOP);

        if (!nexthop_is_ready_to_configure(req->link, req->nexthop))
                return 0;

        r = nexthop_configure(req->nexthop, req->link, req->netlink_handler, &ret);
        if (r < 0)
                return r;

        /* To prevent a double decrement on failure in after_configure(). */
        req->message_counter = NULL;

        if (req->after_configure) {
                r = req->after_configure(req, ret);
                if (r < 0)
                        return r;
        }

        return 1;
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
                if (r < 0 || !link) {
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

                assert((uintptr_t) group % __alignof__(struct nexthop_grp) == 0);

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
        if (!nexthop_has_link(tmp))
                link = NULL;

        r = nexthop_get(m, link, tmp, &nexthop);
        if (r < 0) {
                uint32_t id;

                /* The nexthop may be created without setting NHA_ID. */

                id = tmp->id;
                tmp->id = 0;

                (void) nexthop_get(m, link, tmp, &nexthop);

                tmp->id = id;
        }

        switch (type) {
        case RTM_NEWNEXTHOP:
                if (nexthop)
                        log_nexthop_debug(nexthop, tmp->id, "Received remembered", link);
                else {
                        log_nexthop_debug(tmp, tmp->id, "Remembering foreign", link);
                        r = nexthop_add_foreign(m, link, tmp, &nexthop);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not remember foreign nexthop, ignoring: %m");
                                return 0;
                        }
                }

                r = nexthop_update(m, link, nexthop, tmp);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Could not update nexthop, ignoring: %m");
                        return 0;
                }
                break;
        case RTM_DELNEXTHOP:
                log_nexthop_debug(tmp, tmp->id, nexthop ? "Forgetting" : "Kernel removed unknown", link);
                nexthop_free(nexthop);
                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static int nexthop_section_verify(NextHop *nh) {
        if (section_is_invalid(nh->section))
                return -EINVAL;

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

        switch(a) {
        case ADDRESS_FAMILY_IPV4:
                n->family = AF_INET;
                break;
        case ADDRESS_FAMILY_IPV6:
                n->family = AF_INET6;
                break;
        default:
                assert_not_reached("Invalid family.");
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

        if (isempty(rvalue)) {
                n->onlink = -1;
                TAKE_PTR(n);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        n->onlink = r;

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

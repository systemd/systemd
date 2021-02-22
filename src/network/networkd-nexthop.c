/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc.
 */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
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

static void nexthop_copy(NextHop *dest, const NextHop *src) {
        assert(dest);
        assert(src);

        /* This only copies entries used in the above hash and compare functions. */

        dest->protocol = src->protocol;
        dest->id = src->id;
        dest->blackhole = src->blackhole;
        dest->family = src->family;
        dest->gw = src->gw;
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

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop_copy(nexthop, in);

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

static int nexthop_add(Link *link, const NextHop *in, NextHop **ret) {
        bool is_new = false;
        NextHop *nexthop;
        int r;

        assert(link);
        assert(in);

        if (in->blackhole)
                r = nexthop_get(link->manager, NULL, in, &nexthop);
        else
                r = nexthop_get(NULL, link, in, &nexthop);
        if (r == -ENOENT) {
                /* NextHop does not exist, create a new one */
                r = nexthop_add_internal(link->manager,
                                         in->blackhole ? NULL : link,
                                         in->blackhole ? &link->manager->nexthops : &link->nexthops,
                                         in, &nexthop);
                if (r < 0)
                        return r;
                is_new = true;
        } else if (r == 0) {
                /* Take over a foreign nexthop */
                r = set_ensure_put(in->blackhole ? &link->manager->nexthops : &link->nexthops,
                                   &nexthop_hash_ops, nexthop);
                if (r < 0)
                        return r;

                set_remove(in->blackhole ? link->manager->nexthops_foreign : link->nexthops_foreign, nexthop);
        } else if (r == 1) {
                /* NextHop exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = nexthop;
        return is_new;
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
        assert(nexthop);
        assert(str);

        /* link may be NULL. */

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *gw = NULL;

                (void) in_addr_to_string(nexthop->family, &nexthop->gw, &gw);

                if (nexthop->id == id)
                        log_link_debug(link, "%s nexthop: id: %"PRIu32", gw: %s, blackhole: %s",
                                       str, nexthop->id, strna(gw), yes_no(nexthop->blackhole));
                else
                        log_link_debug(link, "%s nexthop: id: %"PRIu32"→%"PRIu32", gw: %s, blackhole: %s",
                                       str, nexthop->id, id, strna(gw), yes_no(nexthop->blackhole));
        }
}

static int nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);

        /* Note that link may be NULL. */
        if (link && IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ENOENT)
                log_link_message_warning_errno(link, m, r, "Could not drop nexthop, ignoring");

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

        r = netlink_call_async(manager->rtnl, NULL, req, nexthop_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link); /* link may be NULL, link_ref() is OK with that */

        return 0;
}

static int nexthop_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->nexthop_messages > 0);

        link->nexthop_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set nexthop");
                link_enter_failed(link);
                return 1;
        }

        if (link->nexthop_messages == 0) {
                log_link_debug(link, "Nexthops set");
                link->static_nexthops_configured = true;
                /* Now all nexthops are configured. Let's configure remaining routes. */
                r = link_set_routes_with_gateway(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int nexthop_configure(const NextHop *nexthop, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(nexthop->family, AF_INET, AF_INET6));

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

        if (nexthop->blackhole) {
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

        r = netlink_call_async(link->manager->rtnl, NULL, req, nexthop_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        r = nexthop_add(link, nexthop, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add nexthop: %m");

        return r;
}

int link_set_nexthops(Link *link) {
        enum {
                PHASE_ID,         /* First phase: Nexthops with ID */
                PHASE_WITHOUT_ID, /* Second phase: Nexthops without ID */
                _PHASE_MAX,
        } phase;
        NextHop *nh;
        int r;

        assert(link);
        assert(link->network);

        if (link->nexthop_messages != 0) {
                log_link_debug(link, "Nexthops are configuring.");
                return 0;
        }

        link->static_nexthops_configured = false;

        for (phase = PHASE_ID; phase < _PHASE_MAX; phase++)
                HASHMAP_FOREACH(nh, link->network->nexthops_by_section) {
                        if ((nh->id > 0) != (phase == PHASE_ID))
                                continue;

                        r = nexthop_configure(nh, link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not set nexthop: %m");

                        link->nexthop_messages++;
                }

        if (link->nexthop_messages == 0) {
                link->static_nexthops_configured = true;
                /* Finally, configure routes with gateways. */
                return link_set_routes_with_gateway(link);
        }

        log_link_debug(link, "Setting nexthops");
        link_set_state(link, LINK_STATE_CONFIGURING);

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

        HASHMAP_FOREACH(link, manager->links) {
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

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(nexthop_freep) NextHop *tmp = NULL;
        NextHop *nexthop = NULL;
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

                r = link_get(m, ifindex, &link);
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
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6))
                return log_link_debug(link, "rtnl: received nexthop message with invalid family %d, ignoring.", tmp->family);

        r = sd_rtnl_message_nexthop_get_protocol(message, &tmp->protocol);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: could not get nexthop protocol, ignoring: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, NHA_GATEWAY, tmp->family, &tmp->gw);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_GATEWAY attribute, ignoring: %m");
                return 0;
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

        /* All blackhole nexthops are managed by Manager. Note that the linux kernel does not set
         * NHA_OID attribute when NHA_BLACKHOLE is set. Just for safety. */
        if (tmp->blackhole)
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

        if (nh->family == AF_UNSPEC)
                /* When no Gateway= is specified, assume IPv4. */
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

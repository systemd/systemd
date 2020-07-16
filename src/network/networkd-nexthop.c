/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc.
 */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-nexthop.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "util.h"

int nexthop_new(NextHop **ret) {
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;

        nexthop = new(NextHop, 1);
        if (!nexthop)
                return -ENOMEM;

        *nexthop = (NextHop) {
                .family = AF_UNSPEC,
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
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                nexthop = hashmap_get(network->nexthops_by_section, n);
                if (nexthop) {
                        *ret = TAKE_PTR(nexthop);

                        return 0;
                }
        }

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop->protocol = RTPROT_STATIC;
        nexthop->network = network;
        LIST_PREPEND(nexthops, network->static_nexthops, nexthop);
        network->n_static_nexthops++;

        if (filename) {
                nexthop->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->nexthops_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->nexthops_by_section, nexthop->section, nexthop);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(nexthop);

        return 0;
}

void nexthop_free(NextHop *nexthop) {
        if (!nexthop)
                return;

        if (nexthop->network) {
                LIST_REMOVE(nexthops, nexthop->network->static_nexthops, nexthop);

                assert(nexthop->network->n_static_nexthops > 0);
                nexthop->network->n_static_nexthops--;

                if (nexthop->section)
                        hashmap_remove(nexthop->network->nexthops_by_section, nexthop->section);
        }

        network_config_section_free(nexthop->section);

        if (nexthop->link) {
                set_remove(nexthop->link->nexthops, nexthop);
                set_remove(nexthop->link->nexthops_foreign, nexthop);
        }

        free(nexthop);
}

static void nexthop_hash_func(const NextHop *nexthop, struct siphash *state) {
        assert(nexthop);

        siphash24_compress(&nexthop->id, sizeof(nexthop->id), state);
        siphash24_compress(&nexthop->oif, sizeof(nexthop->oif), state);
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

        r = CMP(a->id, b->id);
        if (r != 0)
                return r;

        r = CMP(a->oif, b->oif);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        switch (a->family) {
        case AF_INET:
        case AF_INET6:

                r = memcmp(&a->gw, &b->gw, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                return 0;
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                nexthop_hash_ops,
                NextHop,
                nexthop_hash_func,
                nexthop_compare_func,
                nexthop_free);

bool nexthop_equal(NextHop *r1, NextHop *r2) {
        if (r1 == r2)
                return true;

        if (!r1 || !r2)
                return false;

        return nexthop_compare_func(r1, r2) == 0;
}

int nexthop_get(Link *link, NextHop *in, NextHop **ret) {
        NextHop *existing;

        assert(link);
        assert(in);

        existing = set_get(link->nexthops, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link->nexthops_foreign, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static int nexthop_add_internal(Link *link, Set **nexthops, NextHop *in, NextHop **ret) {
        _cleanup_(nexthop_freep) NextHop *nexthop = NULL;
        int r;

        assert(link);
        assert(nexthops);
        assert(in);

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop->id = in->id;
        nexthop->oif = in->oif;
        nexthop->family = in->family;
        nexthop->gw = in->gw;

        r = set_ensure_put(nexthops, &nexthop_hash_ops, nexthop);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        nexthop->link = link;

        if (ret)
                *ret = nexthop;

        nexthop = NULL;

        return 0;
}

int nexthop_add_foreign(Link *link, NextHop *in, NextHop **ret) {
        return nexthop_add_internal(link, &link->nexthops_foreign, in, ret);
}

int nexthop_add(Link *link, NextHop *in, NextHop **ret) {
        NextHop *nexthop;
        int r;

        r = nexthop_get(link, in, &nexthop);
        if (r == -ENOENT) {
                /* NextHop does not exist, create a new one */
                r = nexthop_add_internal(link, &link->nexthops, in, &nexthop);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign nexthop */
                r = set_ensure_put(&link->nexthops, &nexthop_hash_ops, nexthop);
                if (r < 0)
                        return r;

                set_remove(link->nexthops_foreign, nexthop);
        } else if (r == 1) {
                /* NextHop exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = nexthop;

        return 0;
}

static int nexthop_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_message_warning_errno(link, m, r, "Could not drop nexthop, ignoring");

        return 1;
}

int nexthop_remove(NextHop *nexthop, Link *link,
                   link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(nexthop->family, AF_INET, AF_INET6));

        r = sd_rtnl_message_new_nexthop(link->manager->rtnl, &req,
                                      RTM_DELNEXTHOP, nexthop->family,
                                      nexthop->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELNEXTHOP message: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *gw = NULL;

                if (!in_addr_is_null(nexthop->family, &nexthop->gw))
                        (void) in_addr_to_string(nexthop->family, &nexthop->gw, &gw);

                log_link_debug(link, "Removing nexthop: gw: %s", strna(gw));
        }

        if (in_addr_is_null(nexthop->family, &nexthop->gw) == 0) {
                r = netlink_message_append_in_addr_union(req, RTA_GATEWAY, nexthop->family, &nexthop->gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_GATEWAY attribute: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: nexthop_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int nexthop_configure(
                NextHop *nexthop,
                Link *link,
                link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(nexthop->family, AF_INET, AF_INET6));
        assert(callback);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *gw = NULL;

                if (!in_addr_is_null(nexthop->family, &nexthop->gw))
                        (void) in_addr_to_string(nexthop->family, &nexthop->gw, &gw);

                log_link_debug(link, "Configuring nexthop: gw: %s", strna(gw));
        }

        r = sd_rtnl_message_new_nexthop(link->manager->rtnl, &req,
                                        RTM_NEWNEXTHOP, nexthop->family,
                                        nexthop->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWNEXTHOP message: %m");

        r = sd_netlink_message_append_u32(req, NHA_ID, nexthop->id);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NHA_ID attribute: %m");

        r = sd_netlink_message_append_u32(req, NHA_OIF, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NHA_OIF attribute: %m");

        if (in_addr_is_null(nexthop->family, &nexthop->gw) == 0) {
                r = netlink_message_append_in_addr_union(req, NHA_GATEWAY, nexthop->family, &nexthop->gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NHA_GATEWAY attribute: %m");

                r = sd_rtnl_message_nexthop_set_family(req, nexthop->family);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set nexthop family: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        r = nexthop_add(link, nexthop, &nexthop);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add nexthop: %m");

        return 1;
}

int nexthop_section_verify(NextHop *nh) {
        if (section_is_invalid(nh->section))
                return -EINVAL;

        if (in_addr_is_null(nh->family, &nh->gw) < 0)
                return -EINVAL;

        return 0;
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
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = nexthop_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = safe_atou32(rvalue, &n->id);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse nexthop id \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

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

        r = in_addr_from_string_auto(rvalue, &n->family, &n->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

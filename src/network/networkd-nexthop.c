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

        r = hashmap_ensure_allocated(&network->nexthops_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(network->nexthops_by_section, nexthop->section, nexthop);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nexthop);
        return 0;
}

static void nexthop_hash_func(const NextHop *nexthop, struct siphash *state) {
        assert(nexthop);

        siphash24_compress(&nexthop->id, sizeof(nexthop->id), state);
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

static int nexthop_get(Link *link, NextHop *in, NextHop **ret) {
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

static int nexthop_add_foreign(Link *link, NextHop *in, NextHop **ret) {
        return nexthop_add_internal(link, &link->nexthops_foreign, in, ret);
}

static int nexthop_add(Link *link, NextHop *in, NextHop **ret) {
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
                log_link_debug(link, "Nexthop set");
                link->static_nexthops_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int nexthop_configure(NextHop *nexthop, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(nexthop->family, AF_INET, AF_INET6));

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

        r = netlink_call_async(link->manager->rtnl, NULL, req, nexthop_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        r = nexthop_add(link, nexthop, &nexthop);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add nexthop: %m");

        return 1;
}

int link_set_nexthop(Link *link) {
        NextHop *nh;
        int r;

        assert(link);
        assert(link->network);

        link->static_nexthops_configured = false;

        HASHMAP_FOREACH(nh, link->network->nexthops_by_section) {
                r = nexthop_configure(nh, link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set nexthop: %m");

                link->nexthop_messages++;
        }

        if (link->nexthop_messages == 0) {
                link->static_nexthops_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting nexthop");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 1;
}

int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(nexthop_freep) NextHop *tmp = NULL;
        _cleanup_free_ char *gateway = NULL;
        NextHop *nexthop = NULL;
        uint32_t ifindex;
        uint16_t type;
        Link *link;
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
        if (r == -ENODATA) {
                log_warning_errno(r, "rtnl: received nexthop message without NHA_OIF attribute, ignoring: %m");
                return 0;
        } else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get NHA_OIF attribute, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received nexthop message with invalid ifindex %"PRIu32", ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                if (!m->enumerating)
                        log_warning("rtnl: received nexthop message for link (%"PRIu32") we do not know about, ignoring", ifindex);
                return 0;
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

        r = netlink_message_read_in_addr_union(message, NHA_GATEWAY, tmp->family, &tmp->gw);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_GATEWAY attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, NHA_ID, &tmp->id);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: could not get NHA_ID attribute, ignoring: %m");
                return 0;
        }

        (void) nexthop_get(link, tmp, &nexthop);

        if (DEBUG_LOGGING)
                (void) in_addr_to_string(tmp->family, &tmp->gw, &gateway);

        switch (type) {
        case RTM_NEWNEXTHOP:
                if (nexthop)
                        log_link_debug(link, "Received remembered nexthop: %s, id: %d", strna(gateway), tmp->id);
                else {
                        log_link_debug(link, "Remembering foreign nexthop: %s, id: %d", strna(gateway), tmp->id);
                        r = nexthop_add_foreign(link, tmp, &nexthop);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not remember foreign nexthop, ignoring: %m");
                                return 0;
                        }
                }
                break;
        case RTM_DELNEXTHOP:
                if (nexthop) {
                        log_link_debug(link, "Forgetting nexthop: %s, id: %d", strna(gateway), tmp->id);
                        nexthop_free(nexthop);
                } else
                        log_link_debug(link, "Kernel removed a nexthop we don't remember: %s, id: %d, ignoring.",
                                       strna(gateway), tmp->id);
                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static int nexthop_section_verify(NextHop *nh) {
        if (section_is_invalid(nh->section))
                return -EINVAL;

        if (in_addr_is_null(nh->family, &nh->gw) < 0)
                return -EINVAL;

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

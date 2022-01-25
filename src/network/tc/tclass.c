/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tc-util.h"
#include "tclass.h"

const TClassVTable * const tclass_vtable[_TCLASS_KIND_MAX] = {
        [TCLASS_KIND_DRR] = &drr_tclass_vtable,
        [TCLASS_KIND_HTB] = &htb_tclass_vtable,
        [TCLASS_KIND_QFQ] = &qfq_tclass_vtable,
};

static int tclass_new(TClassKind kind, TClass **ret) {
        _cleanup_(tclass_freep) TClass *tclass = NULL;
        int r;

        if (kind == _TCLASS_KIND_INVALID) {
                tclass = new(TClass, 1);
                if (!tclass)
                        return -ENOMEM;

                *tclass = (TClass) {
                        .meta.kind = TC_KIND_TCLASS,
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                assert(kind >= 0 && kind < _TCLASS_KIND_MAX);
                tclass = malloc0(tclass_vtable[kind]->object_size);
                if (!tclass)
                        return -ENOMEM;

                tclass->meta.kind = TC_KIND_TCLASS;
                tclass->parent = TC_H_ROOT;
                tclass->kind = kind;

                if (TCLASS_VTABLE(tclass)->init) {
                        r = TCLASS_VTABLE(tclass)->init(tclass);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(tclass);

        return 0;
}

int tclass_new_static(TClassKind kind, Network *network, const char *filename, unsigned section_line, TClass **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(tclass_freep) TClass *tclass = NULL;
        TrafficControl *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = ordered_hashmap_get(network->tc_by_section, n);
        if (existing) {
                TClass *t;

                if (existing->kind != TC_KIND_TCLASS)
                        return -EINVAL;

                t = TC_TO_TCLASS(existing);

                if (t->kind != kind)
                        return -EINVAL;

                *ret = t;
                return 0;
        }

        r = tclass_new(kind, &tclass);
        if (r < 0)
                return r;

        tclass->network = network;
        tclass->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->tc_by_section, &config_section_hash_ops, tclass->section, tclass);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(tclass);
        return 0;
}

TClass* tclass_free(TClass *tclass) {
        if (!tclass)
                return NULL;

        if (tclass->network && tclass->section)
                ordered_hashmap_remove(tclass->network->tc_by_section, tclass->section);

        config_section_free(tclass->section);

        if (tclass->link)
                set_remove(tclass->link->traffic_control, TC(tclass));

        free(tclass->tca_kind);
        return mfree(tclass);
}

static const char *tclass_get_tca_kind(const TClass *tclass) {
        assert(tclass);

        return (TCLASS_VTABLE(tclass) && TCLASS_VTABLE(tclass)->tca_kind) ?
                TCLASS_VTABLE(tclass)->tca_kind : tclass->tca_kind;
}

void tclass_hash_func(const TClass *tclass, struct siphash *state) {
        assert(tclass);
        assert(state);

        siphash24_compress(&tclass->classid, sizeof(tclass->classid), state);
        siphash24_compress(&tclass->parent, sizeof(tclass->parent), state);
        siphash24_compress_string(tclass_get_tca_kind(tclass), state);
}

int tclass_compare_func(const TClass *a, const TClass *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->classid, b->classid);
        if (r != 0)
                return r;

        r = CMP(a->parent, b->parent);
        if (r != 0)
                return r;

        return strcmp_ptr(tclass_get_tca_kind(a), tclass_get_tca_kind(b));
}

static int tclass_get(Link *link, const TClass *in, TClass **ret) {
        TrafficControl *existing;
        int r;

        assert(link);
        assert(in);

        r = traffic_control_get(link, TC(in), &existing);
        if (r < 0)
                return r;

        if (ret)
                *ret = TC_TO_TCLASS(existing);
        return 0;
}

static int tclass_add(Link *link, TClass *tclass) {
        int r;

        assert(link);
        assert(tclass);

        r = traffic_control_add(link, TC(tclass));
        if (r < 0)
                return r;

        tclass->link = link;
        return 0;
}

static void log_tclass_debug(TClass *tclass, Link *link, const char *str) {
        _cleanup_free_ char *state = NULL;

        assert(tclass);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(tclass->state, &state);

        log_link_debug(link, "%s %s TClass (%s): classid=%"PRIx32":%"PRIx32", parent=%"PRIx32":%"PRIx32", kind=%s",
                       str, strna(network_config_source_to_string(tclass->source)), strna(state),
                       TC_H_MAJ(tclass->classid) >> 16, TC_H_MIN(tclass->classid),
                       TC_H_MAJ(tclass->parent) >> 16, TC_H_MIN(tclass->parent),
                       strna(tclass_get_tca_kind(tclass)));
}

static int tclass_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->tc_messages > 0);
        link->tc_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set TClass");
                link_enter_failed(link);
                return 1;
        }

        if (link->tc_messages == 0) {
                log_link_debug(link, "Traffic control configured");
                link->tc_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int tclass_configure(Link *link, TClass *tclass) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &req, RTM_NEWTCLASS,
                                                link->ifindex, tclass->classid, tclass->parent);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not create RTM_NEWTCLASS message: %m");

        r = sd_netlink_message_append_string(req, TCA_KIND, TCLASS_VTABLE(tclass)->tca_kind);
        if (r < 0)
                return r;

        if (TCLASS_VTABLE(tclass)->fill_message) {
                r = TCLASS_VTABLE(tclass)->fill_message(link, tclass, req);
                if (r < 0)
                        return r;
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, tclass_handler, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send netlink message: %m");

        link_ref(link);
        link->tc_messages++;

        return 0;
}

int manager_rtnl_process_tclass(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(tclass_freep) TClass *tmp = NULL;
        TClass *tclass = NULL;
        Link *link;
        uint16_t type;
        int ifindex, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive TClass message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWTCLASS, RTM_DELTCLASS)) {
                log_warning("rtnl: received unexpected message type %u when processing TClass, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received TClass message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        if (link_get_by_index(m, ifindex, &link) < 0) {
                if (!m->enumerating)
                        log_warning("rtnl: received TClass for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = tclass_new(_TCLASS_KIND_INVALID, &tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_traffic_control_get_handle(message, &tmp->classid);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without handle, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_parent(message, &tmp->parent);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without parent, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, TCA_KIND, &tmp->tca_kind);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without kind, ignoring: %m");
                return 0;
        }

        (void) tclass_get(link, tmp, &tclass);

        switch (type) {
        case RTM_NEWTCLASS:
                if (tclass) {
                        tclass_enter_configured(tclass);
                        log_tclass_debug(tclass, link, "Received remembered");
                } else {
                        tclass_enter_configured(tmp);
                        log_tclass_debug(tmp, link, "Received new");

                        r = tclass_add(link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember TClass, ignoring: %m");
                                return 0;
                        }

                        tclass = TAKE_PTR(tmp);
                }

                break;

        case RTM_DELTCLASS:
                if (tclass) {
                        tclass_enter_removed(tclass);
                        if (tclass->state == 0) {
                                log_tclass_debug(tclass, link, "Forgetting");
                                tclass_free(tclass);
                        } else
                                log_tclass_debug(tclass, link, "Removed");
                } else
                        log_tclass_debug(tmp, link, "Kernel removed unknown");

                break;

        default:
                assert_not_reached();
        }

        return 1;
}

int tclass_section_verify(TClass *tclass) {
        int r;

        assert(tclass);

        if (section_is_invalid(tclass->section))
                return -EINVAL;

        if (TCLASS_VTABLE(tclass)->verify) {
                r = TCLASS_VTABLE(tclass)->verify(tclass);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_tclass_parent(
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tclass_new_static(ltype, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "root"))
                tclass->parent = TC_H_ROOT;
        else {
                r = parse_handle(rvalue, &tclass->parent);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse 'Parent=', ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
        }

        TAKE_PTR(tclass);

        return 0;
}

int config_parse_tclass_classid(
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tclass_new_static(ltype, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tclass->classid = TC_H_UNSPEC;
                TAKE_PTR(tclass);
                return 0;
        }

        r = parse_handle(rvalue, &tclass->classid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'ClassId=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        TAKE_PTR(tclass);

        return 0;
}

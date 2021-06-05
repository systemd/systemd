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

        tclass = malloc0(tclass_vtable[kind]->object_size);
        if (!tclass)
                return -ENOMEM;

        tclass->meta.kind = TC_KIND_TCLASS,
        tclass->parent = TC_H_ROOT;
        tclass->kind = kind;

        if (TCLASS_VTABLE(tclass)->init) {
                r = TCLASS_VTABLE(tclass)->init(tclass);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(tclass);

        return 0;
}

int tclass_new_static(TClassKind kind, Network *network, const char *filename, unsigned section_line, TClass **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(tclass_freep) TClass *tclass = NULL;
        TrafficControl *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
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

        r = ordered_hashmap_ensure_put(&network->tc_by_section, &network_config_hash_ops, tclass->section, tclass);
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

        network_config_section_free(tclass->section);

        return mfree(tclass);
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

        r = sd_rtnl_message_new_tclass(link->manager->rtnl, &req, RTM_NEWTCLASS, AF_UNSPEC, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWTCLASS message: %m");

        r = sd_rtnl_message_set_tclass_parent(req, tclass->parent);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create tcm_parent message: %m");

        if (tclass->classid != TC_H_UNSPEC) {
                r = sd_rtnl_message_set_tclass_handle(req, tclass->classid);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set tcm_handle message: %m");
        }

        r = sd_netlink_message_append_string(req, TCA_KIND, TCLASS_VTABLE(tclass)->tca_kind);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_KIND attribute: %m");

        if (TCLASS_VTABLE(tclass)->fill_message) {
                r = TCLASS_VTABLE(tclass)->fill_message(link, tclass, req);
                if (r < 0)
                        return r;
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, tclass_handler, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->tc_messages++;

        return 0;
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

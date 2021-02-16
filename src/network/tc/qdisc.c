/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tc-util.h"

const QDiscVTable * const qdisc_vtable[_QDISC_KIND_MAX] = {
        [QDISC_KIND_BFIFO] = &bfifo_vtable,
        [QDISC_KIND_CAKE] = &cake_vtable,
        [QDISC_KIND_CODEL] = &codel_vtable,
        [QDISC_KIND_DRR] = &drr_vtable,
        [QDISC_KIND_ETS] = &ets_vtable,
        [QDISC_KIND_FQ] = &fq_vtable,
        [QDISC_KIND_FQ_CODEL] = &fq_codel_vtable,
        [QDISC_KIND_FQ_PIE] = &fq_pie_vtable,
        [QDISC_KIND_GRED] = &gred_vtable,
        [QDISC_KIND_HHF] = &hhf_vtable,
        [QDISC_KIND_HTB] = &htb_vtable,
        [QDISC_KIND_NETEM] = &netem_vtable,
        [QDISC_KIND_PIE] = &pie_vtable,
        [QDISC_KIND_QFQ] = &qfq_vtable,
        [QDISC_KIND_PFIFO] = &pfifo_vtable,
        [QDISC_KIND_PFIFO_FAST] = &pfifo_fast_vtable,
        [QDISC_KIND_PFIFO_HEAD_DROP] = &pfifo_head_drop_vtable,
        [QDISC_KIND_SFB] = &sfb_vtable,
        [QDISC_KIND_SFQ] = &sfq_vtable,
        [QDISC_KIND_TBF] = &tbf_vtable,
        [QDISC_KIND_TEQL] = &teql_vtable,
};

static int qdisc_new(QDiscKind kind, QDisc **ret) {
        _cleanup_(qdisc_freep) QDisc *qdisc = NULL;
        int r;

        if (kind == _QDISC_KIND_INVALID) {
                qdisc = new(QDisc, 1);
                if (!qdisc)
                        return -ENOMEM;

                *qdisc = (QDisc) {
                        .meta.kind = TC_KIND_QDISC,
                        .family = AF_UNSPEC,
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                qdisc = malloc0(qdisc_vtable[kind]->object_size);
                if (!qdisc)
                        return -ENOMEM;

                qdisc->meta.kind = TC_KIND_QDISC,
                qdisc->family = AF_UNSPEC;
                qdisc->parent = TC_H_ROOT;
                qdisc->kind = kind;

                if (QDISC_VTABLE(qdisc)->init) {
                        r = QDISC_VTABLE(qdisc)->init(qdisc);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(qdisc);

        return 0;
}

int qdisc_new_static(QDiscKind kind, Network *network, const char *filename, unsigned section_line, QDisc **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(qdisc_freep) QDisc *qdisc = NULL;
        TrafficControl *existing;
        QDisc *q = NULL;
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
                if (existing->kind != TC_KIND_QDISC)
                        return -EINVAL;

                q = TC_TO_QDISC(existing);

                if (q->kind != _QDISC_KIND_INVALID &&
                    kind != _QDISC_KIND_INVALID &&
                    q->kind != kind)
                        return -EINVAL;

                if (q->kind == kind || kind == _QDISC_KIND_INVALID) {
                        *ret = q;
                        return 0;
                }
        }

        r = qdisc_new(kind, &qdisc);
        if (r < 0)
                return r;

        if (q) {
                qdisc->family = q->family;
                qdisc->handle = q->handle;
                qdisc->parent = q->parent;
                qdisc->tca_kind = TAKE_PTR(q->tca_kind);

                qdisc_free(q);
        }

        qdisc->network = network;
        qdisc->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->tc_by_section, &network_config_hash_ops, qdisc->section, TC(qdisc));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(qdisc);
        return 0;
}

QDisc* qdisc_free(QDisc *qdisc) {
        if (!qdisc)
                return NULL;

        if (qdisc->network && qdisc->section)
                ordered_hashmap_remove(qdisc->network->tc_by_section, qdisc->section);

        network_config_section_free(qdisc->section);

        free(qdisc->tca_kind);
        return mfree(qdisc);
}

static int qdisc_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->tc_messages > 0);
        link->tc_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set QDisc");
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

int qdisc_configure(Link *link, QDisc *qdisc) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        r = sd_rtnl_message_new_qdisc(link->manager->rtnl, &req, RTM_NEWQDISC, qdisc->family, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWQDISC message: %m");

        r = sd_rtnl_message_set_qdisc_parent(req, qdisc->parent);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create tcm_parent message: %m");

        if (qdisc->handle != TC_H_UNSPEC) {
                r = sd_rtnl_message_set_qdisc_handle(req, qdisc->handle);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set tcm_handle message: %m");
        }

        if (QDISC_VTABLE(qdisc)) {
                if (QDISC_VTABLE(qdisc)->fill_tca_kind) {
                        r = QDISC_VTABLE(qdisc)->fill_tca_kind(link, qdisc, req);
                        if (r < 0)
                                return r;
                } else {
                        r = sd_netlink_message_append_string(req, TCA_KIND, QDISC_VTABLE(qdisc)->tca_kind);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append TCA_KIND attribute: %m");
                }

                if (QDISC_VTABLE(qdisc)->fill_message) {
                        r = QDISC_VTABLE(qdisc)->fill_message(link, qdisc, req);
                        if (r < 0)
                                return r;
                }
        } else {
                r = sd_netlink_message_append_string(req, TCA_KIND, qdisc->tca_kind);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_KIND attribute: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, qdisc_handler, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->tc_messages++;

        return 0;
}

int qdisc_section_verify(QDisc *qdisc, bool *has_root, bool *has_clsact) {
        int r;

        assert(qdisc);
        assert(has_root);
        assert(has_clsact);

        if (section_is_invalid(qdisc->section))
                return -EINVAL;

        if (QDISC_VTABLE(qdisc) && QDISC_VTABLE(qdisc)->verify) {
                r = QDISC_VTABLE(qdisc)->verify(qdisc);
                if (r < 0)
                        return r;
        }

        if (qdisc->parent == TC_H_ROOT) {
                if (*has_root)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: More than one root qdisc section is defined. "
                                                 "Ignoring the qdisc section from line %u.",
                                                 qdisc->section->filename, qdisc->section->line);
                *has_root = true;
        } else if (qdisc->parent == TC_H_CLSACT) { /* TC_H_CLSACT == TC_H_INGRESS */
                if (*has_clsact)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: More than one clsact or ingress qdisc section is defined. "
                                                 "Ignoring the qdisc section from line %u.",
                                                 qdisc->section->filename, qdisc->section->line);
                *has_clsact = true;
        }

        return 0;
}

int config_parse_qdisc_parent(
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

        _cleanup_(qdisc_free_or_set_invalidp) QDisc *qdisc = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(ltype, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "root")) {
                qdisc->parent = TC_H_ROOT;
                if (qdisc->handle == 0)
                        qdisc->handle = TC_H_UNSPEC;
        } else if (streq(rvalue, "clsact")) {
                qdisc->parent = TC_H_CLSACT;
                qdisc->handle = TC_H_MAKE(TC_H_CLSACT, 0);
        } else if (streq(rvalue, "ingress")) {
                qdisc->parent = TC_H_INGRESS;
                qdisc->handle = TC_H_MAKE(TC_H_INGRESS, 0);
        } else {
                r = parse_handle(rvalue, &qdisc->parent);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse 'Parent=', ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
        }

        if (STR_IN_SET(rvalue, "clsact", "ingress")) {
                r = free_and_strdup(&qdisc->tca_kind, rvalue);
                if (r < 0)
                        return log_oom();
        } else
                qdisc->tca_kind = mfree(qdisc->tca_kind);

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_qdisc_handle(
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

        _cleanup_(qdisc_free_or_set_invalidp) QDisc *qdisc = NULL;
        Network *network = data;
        uint16_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(ltype, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                qdisc->handle = TC_H_UNSPEC;
                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou16_full(rvalue, 16, &n);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'Handle=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        qdisc->handle = (uint32_t) n << 16;
        TAKE_PTR(qdisc);

        return 0;
}

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
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                assert(kind >= 0 && kind < _QDISC_KIND_MAX);
                qdisc = malloc0(qdisc_vtable[kind]->object_size);
                if (!qdisc)
                        return -ENOMEM;

                qdisc->meta.kind = TC_KIND_QDISC,
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
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(qdisc_freep) QDisc *qdisc = NULL;
        TrafficControl *existing;
        QDisc *q = NULL;
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
                qdisc->handle = q->handle;
                qdisc->parent = q->parent;
                qdisc->tca_kind = TAKE_PTR(q->tca_kind);

                qdisc_free(q);
        }

        qdisc->network = network;
        qdisc->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->tc_by_section, &config_section_hash_ops, qdisc->section, TC(qdisc));
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

        config_section_free(qdisc->section);

        if (qdisc->link)
                set_remove(qdisc->link->traffic_control, TC(qdisc));

        free(qdisc->tca_kind);
        return mfree(qdisc);
}

static const char *qdisc_get_tca_kind(const QDisc *qdisc) {
        assert(qdisc);

        return (QDISC_VTABLE(qdisc) && QDISC_VTABLE(qdisc)->tca_kind) ?
                QDISC_VTABLE(qdisc)->tca_kind : qdisc->tca_kind;
}

void qdisc_hash_func(const QDisc *qdisc, struct siphash *state) {
        assert(qdisc);
        assert(state);

        siphash24_compress(&qdisc->handle, sizeof(qdisc->handle), state);
        siphash24_compress(&qdisc->parent, sizeof(qdisc->parent), state);
        siphash24_compress_string(qdisc_get_tca_kind(qdisc), state);
}

int qdisc_compare_func(const QDisc *a, const QDisc *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->handle, b->handle);
        if (r != 0)
                return r;

        r = CMP(a->parent, b->parent);
        if (r != 0)
                return r;

        return strcmp_ptr(qdisc_get_tca_kind(a), qdisc_get_tca_kind(b));
}

static int qdisc_get(Link *link, const QDisc *in, QDisc **ret) {
        TrafficControl *existing;
        int r;

        assert(link);
        assert(in);

        r = traffic_control_get(link, TC(in), &existing);
        if (r < 0)
                return r;

        if (ret)
                *ret = TC_TO_QDISC(existing);
        return 0;
}

static int qdisc_add(Link *link, QDisc *qdisc) {
        int r;

        assert(link);
        assert(qdisc);

        r = traffic_control_add(link, TC(qdisc));
        if (r < 0)
                return r;

        qdisc->link = link;
        return 0;
}

static void log_qdisc_debug(QDisc *qdisc, Link *link, const char *str) {
        _cleanup_free_ char *state = NULL;

        assert(qdisc);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(qdisc->state, &state);

        log_link_debug(link, "%s %s QDisc (%s): handle=%"PRIx32":%"PRIx32", parent=%"PRIx32":%"PRIx32", kind=%s",
                       str, strna(network_config_source_to_string(qdisc->source)), strna(state),
                       TC_H_MAJ(qdisc->handle) >> 16, TC_H_MIN(qdisc->handle),
                       TC_H_MAJ(qdisc->parent) >> 16, TC_H_MIN(qdisc->parent),
                       strna(qdisc_get_tca_kind(qdisc)));
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

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &req, RTM_NEWQDISC,
                                                link->ifindex, qdisc->handle, qdisc->parent);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not create RTM_NEWQDISC message: %m");

        r = sd_netlink_message_append_string(req, TCA_KIND, qdisc_get_tca_kind(qdisc));
        if (r < 0)
                return r;

        if (QDISC_VTABLE(qdisc) && QDISC_VTABLE(qdisc)->fill_message) {
                r = QDISC_VTABLE(qdisc)->fill_message(link, qdisc, req);
                if (r < 0)
                        return r;
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, qdisc_handler, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send netlink message: %m");

        link_ref(link);
        link->tc_messages++;

        return 0;
}

int manager_rtnl_process_qdisc(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(qdisc_freep) QDisc *tmp = NULL;
        QDisc *qdisc = NULL;
        Link *link;
        uint16_t type;
        int ifindex, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive QDisc message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWQDISC, RTM_DELQDISC)) {
                log_warning("rtnl: received unexpected message type %u when processing QDisc, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received QDisc message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        if (link_get_by_index(m, ifindex, &link) < 0) {
                if (!m->enumerating)
                        log_warning("rtnl: received QDisc for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = qdisc_new(_QDISC_KIND_INVALID, &tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_traffic_control_get_handle(message, &tmp->handle);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received QDisc message without handle, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_parent(message, &tmp->parent);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received QDisc message without parent, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, TCA_KIND, &tmp->tca_kind);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received QDisc message without kind, ignoring: %m");
                return 0;
        }

        (void) qdisc_get(link, tmp, &qdisc);

        switch (type) {
        case RTM_NEWQDISC:
                if (qdisc) {
                        qdisc_enter_configured(qdisc);
                        log_qdisc_debug(qdisc, link, "Received remembered");
                } else {
                        qdisc_enter_configured(tmp);
                        log_qdisc_debug(tmp, link, "Received new");

                        r = qdisc_add(link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember QDisc, ignoring: %m");
                                return 0;
                        }

                        qdisc = TAKE_PTR(tmp);
                }

                break;

        case RTM_DELQDISC:
                if (qdisc) {
                        qdisc_enter_removed(qdisc);
                        if (qdisc->state == 0) {
                                log_qdisc_debug(qdisc, link, "Forgetting");
                                qdisc_free(qdisc);
                        } else
                                log_qdisc_debug(qdisc, link, "Removed");
                } else
                        log_qdisc_debug(tmp, link, "Kernel removed unknown");

                break;

        default:
                assert_not_reached();
        }

        return 1;
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

        if (streq(rvalue, "root"))
                qdisc->parent = TC_H_ROOT;
        else if (streq(rvalue, "clsact")) {
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

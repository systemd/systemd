/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "parse-util.h"
#include "qdisc.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tc-util.h"

const QDiscVTable * const qdisc_vtable[_QDISC_KIND_MAX] = {
        [QDISC_KIND_BFIFO]           = &bfifo_vtable,
        [QDISC_KIND_CAKE]            = &cake_vtable,
        [QDISC_KIND_CODEL]           = &codel_vtable,
        [QDISC_KIND_DRR]             = &drr_vtable,
        [QDISC_KIND_ETS]             = &ets_vtable,
        [QDISC_KIND_FQ]              = &fq_vtable,
        [QDISC_KIND_FQ_CODEL]        = &fq_codel_vtable,
        [QDISC_KIND_FQ_PIE]          = &fq_pie_vtable,
        [QDISC_KIND_GRED]            = &gred_vtable,
        [QDISC_KIND_HHF]             = &hhf_vtable,
        [QDISC_KIND_HTB]             = &htb_vtable,
        [QDISC_KIND_NETEM]           = &netem_vtable,
        [QDISC_KIND_PIE]             = &pie_vtable,
        [QDISC_KIND_QFQ]             = &qfq_vtable,
        [QDISC_KIND_PFIFO]           = &pfifo_vtable,
        [QDISC_KIND_PFIFO_FAST]      = &pfifo_fast_vtable,
        [QDISC_KIND_PFIFO_HEAD_DROP] = &pfifo_head_drop_vtable,
        [QDISC_KIND_SFB]             = &sfb_vtable,
        [QDISC_KIND_SFQ]             = &sfq_vtable,
        [QDISC_KIND_TBF]             = &tbf_vtable,
        [QDISC_KIND_TEQL]            = &teql_vtable,
};

static int qdisc_new(QDiscKind kind, QDisc **ret) {
        _cleanup_(qdisc_freep) QDisc *qdisc = NULL;
        int r;

        if (kind == _QDISC_KIND_INVALID) {
                qdisc = new(QDisc, 1);
                if (!qdisc)
                        return -ENOMEM;

                *qdisc = (QDisc) {
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                assert(kind >= 0 && kind < _QDISC_KIND_MAX);
                qdisc = malloc0(qdisc_vtable[kind]->object_size);
                if (!qdisc)
                        return -ENOMEM;

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
        QDisc *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = hashmap_get(network->qdiscs_by_section, n);
        if (existing) {
                if (existing->kind != _QDISC_KIND_INVALID &&
                    kind != _QDISC_KIND_INVALID &&
                    existing->kind != kind)
                        return -EINVAL;

                if (existing->kind == kind || kind == _QDISC_KIND_INVALID) {
                        *ret = existing;
                        return 0;
                }
        }

        r = qdisc_new(kind, &qdisc);
        if (r < 0)
                return r;

        if (existing) {
                qdisc->handle = existing->handle;
                qdisc->parent = existing->parent;
                qdisc->tca_kind = TAKE_PTR(existing->tca_kind);

                qdisc_free(existing);
        }

        qdisc->network = network;
        qdisc->section = TAKE_PTR(n);
        qdisc->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = hashmap_ensure_put(&network->qdiscs_by_section, &config_section_hash_ops, qdisc->section, qdisc);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(qdisc);
        return 0;
}

QDisc* qdisc_free(QDisc *qdisc) {
        if (!qdisc)
                return NULL;

        if (qdisc->network && qdisc->section)
                hashmap_remove(qdisc->network->qdiscs_by_section, qdisc->section);

        config_section_free(qdisc->section);

        if (qdisc->link)
                set_remove(qdisc->link->qdiscs, qdisc);

        free(qdisc->tca_kind);
        return mfree(qdisc);
}

static const char *qdisc_get_tca_kind(const QDisc *qdisc) {
        assert(qdisc);

        return (QDISC_VTABLE(qdisc) && QDISC_VTABLE(qdisc)->tca_kind) ?
                QDISC_VTABLE(qdisc)->tca_kind : qdisc->tca_kind;
}

static void qdisc_hash_func(const QDisc *qdisc, struct siphash *state) {
        assert(qdisc);
        assert(state);

        siphash24_compress_typesafe(qdisc->handle, state);
        siphash24_compress_typesafe(qdisc->parent, state);
        siphash24_compress_string(qdisc_get_tca_kind(qdisc), state);
}

static int qdisc_compare_func(const QDisc *a, const QDisc *b) {
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

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        qdisc_hash_ops,
        QDisc,
        qdisc_hash_func,
        qdisc_compare_func,
        qdisc_free);

static int qdisc_get(Link *link, const QDisc *in, QDisc **ret) {
        QDisc *existing;

        assert(link);
        assert(in);

        existing = set_get(link->qdiscs, in);
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

static int qdisc_add(Link *link, QDisc *qdisc) {
        int r;

        assert(link);
        assert(qdisc);

        r = set_ensure_put(&link->qdiscs, &qdisc_hash_ops, qdisc);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        qdisc->link = link;
        return 0;
}

static int qdisc_dup(const QDisc *src, QDisc **ret) {
        _cleanup_(qdisc_freep) QDisc *dst = NULL;

        assert(src);
        assert(ret);

        if (QDISC_VTABLE(src))
                dst = memdup(src, QDISC_VTABLE(src)->object_size);
        else
                dst = newdup(QDisc, src, 1);
        if (!dst)
                return -ENOMEM;

        /* clear all pointers */
        dst->network = NULL;
        dst->section = NULL;
        dst->link = NULL;
        dst->tca_kind = NULL;

        if (src->tca_kind) {
                dst->tca_kind = strdup(src->tca_kind);
                if (!dst->tca_kind)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(dst);
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

int link_find_qdisc(Link *link, uint32_t handle, const char *kind, QDisc **ret) {
        QDisc *qdisc;

        assert(link);

        SET_FOREACH(qdisc, link->qdiscs) {
                if (qdisc->handle != handle)
                        continue;

                if (!qdisc_exists(qdisc))
                        continue;

                if (kind && !streq_ptr(kind, qdisc_get_tca_kind(qdisc)))
                        continue;

                if (ret)
                        *ret = qdisc;
                return 0;
        }

        return -ENOENT;
}

QDisc* qdisc_drop(QDisc *qdisc) {
        TClass *tclass;
        Link *link;

        assert(qdisc);

        link = ASSERT_PTR(qdisc->link);

        /* also drop all child classes assigned to the qdisc. */
        SET_FOREACH(tclass, link->tclasses) {
                if (TC_H_MAJ(tclass->classid) != qdisc->handle)
                        continue;

                tclass_drop(tclass);
        }

        qdisc_enter_removed(qdisc);

        if (qdisc->state == 0) {
                log_qdisc_debug(qdisc, link, "Forgetting");
                qdisc = qdisc_free(qdisc);
        } else
                log_qdisc_debug(qdisc, link, "Removed");

        return qdisc;
}

static int qdisc_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, QDisc *qdisc) {
        int r;

        assert(m);
        assert(link);

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

static int qdisc_configure(QDisc *qdisc, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(qdisc);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_qdisc_debug(qdisc, link, "Configuring");

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &m, RTM_NEWQDISC,
                                                link->ifindex, qdisc->handle, qdisc->parent);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, TCA_KIND, qdisc_get_tca_kind(qdisc));
        if (r < 0)
                return r;

        if (QDISC_VTABLE(qdisc) && QDISC_VTABLE(qdisc)->fill_message) {
                r = QDISC_VTABLE(qdisc)->fill_message(link, qdisc, m);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool qdisc_is_ready_to_configure(QDisc *qdisc, Link *link) {
        assert(qdisc);
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        /* TC_H_CLSACT == TC_H_INGRESS */
        if (!IN_SET(qdisc->parent, TC_H_ROOT, TC_H_CLSACT)) {
                if (TC_H_MIN(qdisc->parent) == 0) {
                        if (link_find_qdisc(link, qdisc->parent, NULL, NULL) < 0)
                                return false;
                } else {
                        if (link_find_tclass(link, qdisc->parent, NULL) < 0)
                                return false;
                }
        }

        if (QDISC_VTABLE(qdisc) &&
            QDISC_VTABLE(qdisc)->is_ready &&
            QDISC_VTABLE(qdisc)->is_ready(qdisc, link) <= 0)
                return false;

        return true;
}

static int qdisc_process_request(Request *req, Link *link, QDisc *qdisc) {
        int r;

        assert(req);
        assert(link);
        assert(qdisc);

        if (!qdisc_is_ready_to_configure(qdisc, link))
                return 0;

        r = qdisc_configure(qdisc, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure QDisc: %m");

        qdisc_enter_configuring(qdisc);
        return 1;
}

int link_request_qdisc(Link *link, QDisc *qdisc) {
        QDisc *existing;
        int r;

        assert(link);
        assert(qdisc);

        if (qdisc_get(link, qdisc, &existing) < 0) {
                _cleanup_(qdisc_freep) QDisc *tmp = NULL;

                r = qdisc_dup(qdisc, &tmp);
                if (r < 0)
                        return log_oom();

                r = qdisc_add(link, tmp);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to store QDisc: %m");

                existing = TAKE_PTR(tmp);
        } else
                existing->source = qdisc->source;

        log_qdisc_debug(existing, link, "Requesting");
        r = link_queue_request_safe(link, REQUEST_TYPE_TC_QDISC,
                                    existing, NULL,
                                    qdisc_hash_func,
                                    qdisc_compare_func,
                                    qdisc_process_request,
                                    &link->tc_messages,
                                    qdisc_handler,
                                    NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request QDisc: %m");
        if (r == 0)
                return 0;

        qdisc_enter_requesting(existing);
        return 1;
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

                if (!m->enumerating) {
                        /* Some kind of QDisc (e.g. tbf) also create an implicit class under the qdisc, but
                         * the kernel may not notify about the class. Hence, we need to enumerate classes. */
                        r = link_enumerate_tclass(link, qdisc->handle);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to enumerate TClass, ignoring: %m");
                }

                break;

        case RTM_DELQDISC:
                if (qdisc)
                        qdisc_drop(qdisc);
                else
                        log_qdisc_debug(tmp, link, "Kernel removed unknown");

                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int qdisc_section_verify(QDisc *qdisc, bool *has_root, bool *has_clsact) {
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

void network_drop_invalid_qdisc(Network *network) {
        bool has_root = false, has_clsact = false;
        QDisc *qdisc;

        assert(network);

        HASHMAP_FOREACH(qdisc, network->qdiscs_by_section)
                if (qdisc_section_verify(qdisc, &has_root, &has_clsact) < 0)
                        qdisc_free(qdisc);
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
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
        Network *network = ASSERT_PTR(data);
        uint16_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

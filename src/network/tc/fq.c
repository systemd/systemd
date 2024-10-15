/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "fq.h"
#include "logarithm.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

static int fair_queueing_init(QDisc *qdisc) {
        FairQueueing *fq;

        assert(qdisc);

        fq = FQ(qdisc);

        fq->pacing = -1;
        fq->ce_threshold_usec = USEC_INFINITY;

        return 0;
}

static int fair_queueing_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        FairQueueing *fq;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(fq = FQ(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "fq");
        if (r < 0)
                return r;

        if (fq->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_PLIMIT, fq->packet_limit);
                if (r < 0)
                        return r;
        }

        if (fq->flow_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_FLOW_PLIMIT, fq->flow_limit);
                if (r < 0)
                        return r;
        }

        if (fq->quantum > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_QUANTUM, fq->quantum);
                if (r < 0)
                        return r;
        }

        if (fq->initial_quantum > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_INITIAL_QUANTUM, fq->initial_quantum);
                if (r < 0)
                        return r;
        }

        if (fq->pacing >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_RATE_ENABLE, fq->pacing);
                if (r < 0)
                        return r;
        }

        if (fq->max_rate > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_FLOW_MAX_RATE, fq->max_rate);
                if (r < 0)
                        return r;
        }

        if (fq->buckets > 0) {
                uint32_t l;

                l = log2u(fq->buckets);
                r = sd_netlink_message_append_u32(req, TCA_FQ_BUCKETS_LOG, l);
                if (r < 0)
                        return r;
        }

        if (fq->orphan_mask > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_ORPHAN_MASK, fq->orphan_mask);
                if (r < 0)
                        return r;
        }

        if (fq->ce_threshold_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CE_THRESHOLD, fq->ce_threshold_usec);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_fair_queueing_u32(
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

        _cleanup_(qdisc_unref_or_set_invalidp) QDisc *qdisc = NULL;
        FairQueueing *fq;
        Network *network = ASSERT_PTR(data);
        uint32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fq = FQ(qdisc);

        if (streq(lvalue, "PacketLimit"))
                p = &fq->packet_limit;
        else if (streq(lvalue, "FlowLimit"))
                p = &fq->flow_limit;
        else if (streq(lvalue, "Buckets"))
                p = &fq->buckets;
        else if (streq(lvalue, "OrphanMask"))
                p = &fq->orphan_mask;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;

        return 0;
}

int config_parse_fair_queueing_size(
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

        _cleanup_(qdisc_unref_or_set_invalidp) QDisc *qdisc = NULL;
        FairQueueing *fq;
        Network *network = ASSERT_PTR(data);
        uint64_t sz;
        uint32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fq = FQ(qdisc);

        if (STR_IN_SET(lvalue, "QuantumBytes", "Quantum"))
                p = &fq->quantum;
        else if (STR_IN_SET(lvalue, "InitialQuantumBytes", "InitialQuantum"))
                p = &fq->initial_quantum;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1024, &sz);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (sz > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *p = sz;
        qdisc = NULL;

        return 0;
}

int config_parse_fair_queueing_bool(
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

        _cleanup_(qdisc_unref_or_set_invalidp) QDisc *qdisc = NULL;
        FairQueueing *fq;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fq = FQ(qdisc);

        r = parse_tristate(rvalue, &fq->pacing);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        fq->pacing = r;
        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fair_queueing_usec(
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

        _cleanup_(qdisc_unref_or_set_invalidp) QDisc *qdisc = NULL;
        FairQueueing *fq;
        Network *network = ASSERT_PTR(data);
        usec_t sec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fq = FQ(qdisc);

        if (isempty(rvalue)) {
                fq->ce_threshold_usec = USEC_INFINITY;

                qdisc = NULL;
                return 0;
        }

        r = parse_sec(rvalue, &sec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (sec > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        fq->ce_threshold_usec = sec;
        qdisc = NULL;

        return 0;
}

int config_parse_fair_queueing_max_rate(
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

        _cleanup_(qdisc_unref_or_set_invalidp) QDisc *qdisc = NULL;
        FairQueueing *fq;
        Network *network = ASSERT_PTR(data);
        uint64_t sz;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fq = FQ(qdisc);

        if (isempty(rvalue)) {
                fq->max_rate = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1000, &sz);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (sz / 8 > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        fq->max_rate = sz / 8;
        qdisc = NULL;

        return 0;
}

const QDiscVTable fq_vtable = {
        .init = fair_queueing_init,
        .object_size = sizeof(FairQueueing),
        .tca_kind = "fq",
        .fill_message = fair_queueing_fill_message,
};

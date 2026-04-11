/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "extract-word.h"
#include "fq.h"
#include "log.h"
#include "logarithm.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static int fair_queueing_init(QDisc *qdisc) {
        FairQueueing *fq;

        assert(qdisc);

        fq = FQ(qdisc);

        fq->pacing = -1;
        fq->ce_threshold_usec = USEC_INFINITY;
        fq->timer_slack_usec = USEC_INFINITY;
        fq->horizon_usec = USEC_INFINITY;
        fq->offload_horizon_usec = USEC_INFINITY;
        fq->horizon_drop = -1;

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

        if (fq->low_rate_threshold > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_LOW_RATE_THRESHOLD, fq->low_rate_threshold);
                if (r < 0)
                        return r;
        }

        if (fq->timer_slack_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_TIMER_SLACK, fq->timer_slack_usec * NSEC_PER_USEC);
                if (r < 0)
                        return r;
        }

        if (fq->horizon_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_HORIZON, fq->horizon_usec);
                if (r < 0)
                        return r;
        }

        if (fq->horizon_drop >= 0) {
                r = sd_netlink_message_append_u8(req, TCA_FQ_HORIZON_DROP, fq->horizon_drop);
                if (r < 0)
                        return r;
        }

        if (fq->offload_horizon_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_OFFLOAD_HORIZON, fq->offload_horizon_usec);
                if (r < 0)
                        return r;
        }

        if (fq->n_priomap > 0) {
                struct tc_prio_qopt prio = {
                        .bands = FQ_BANDS,
                };

                memcpy(prio.priomap, fq->priomap, sizeof(fq->priomap));

                r = sd_netlink_message_append_data(req, TCA_FQ_PRIOMAP, &prio, sizeof(prio));
                if (r < 0)
                        return r;
        }

        if (fq->n_weights >= FQ_BANDS) {
                r = sd_netlink_message_append_data(req, TCA_FQ_WEIGHTS, fq->weights, sizeof(fq->weights));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_fq_u32(
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

int config_parse_fq_size(
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

int config_parse_fq_bool(
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
        int *p, r;

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

        if (streq(lvalue, "Pacing"))
                p = &fq->pacing;
        else if (streq(lvalue, "HorizonDrop"))
                p = &fq->horizon_drop;
        else
                assert_not_reached();

        r = parse_tristate(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fq_sec(
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
        usec_t sec, *p;
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

        if (streq(lvalue, "CEThresholdSec"))
                p = &fq->ce_threshold_usec;
        else if (streq(lvalue, "TimerSlackSec"))
                p = &fq->timer_slack_usec;
        else if (streq(lvalue, "HorizonSec"))
                p = &fq->horizon_usec;
        else if (streq(lvalue, "OffloadHorizonSec"))
                p = &fq->offload_horizon_usec;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = USEC_INFINITY;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_sec(rvalue, &sec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        /* TimerSlackSec is sent to the kernel in nanoseconds (usec * NSEC_PER_USEC),
         * so it has a tighter upper bound to avoid u32 overflow. */
        if (p == &fq->timer_slack_usec ? sec > UINT32_MAX / NSEC_PER_USEC : sec > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *p = sec;
        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fq_max_rate(
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

int config_parse_fq_rate(
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

        if (streq(lvalue, "LowRateThreshold"))
                p = &fq->low_rate_threshold;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                TAKE_PTR(qdisc);
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

        *p = sz / 8;
        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fq_priomap(
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

        if (isempty(rvalue)) {
                memzero(fq->priomap, sizeof(fq->priomap));
                fq->n_priomap = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        fq->n_priomap = 0;

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint8_t v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        break;
                }
                if (r == 0)
                        break;

                r = safe_atou8(word, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        return 0;
                }
                if (v >= FQ_BANDS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid '%s=' value (must be < %d), ignoring assignment: %s",
                                   lvalue, FQ_BANDS, word);
                        return 0;
                }
                if (fq->n_priomap > TC_PRIO_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many values in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }

                fq->priomap[fq->n_priomap++] = v;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fq_weights(
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

        if (isempty(rvalue)) {
                memzero(fq->weights, sizeof(fq->weights));
                fq->n_weights = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        fq->n_weights = 0;

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                int v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        break;
                }
                if (r == 0)
                        break;

                r = safe_atoi(word, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (v < FQ_MIN_WEIGHT) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid '%s=' value (must be >= %d), ignoring assignment: %s",
                                   lvalue, FQ_MIN_WEIGHT, word);
                        continue;
                }
                if (fq->n_weights >= FQ_BANDS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many values in '%s=' (maximum %d), ignoring assignment: %s",
                                   lvalue, FQ_BANDS, word);
                        continue;
                }

                fq->weights[fq->n_weights++] = v;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable fq_vtable = {
        .init = fair_queueing_init,
        .object_size = sizeof(FairQueueing),
        .tca_kind = "fq",
        .fill_message = fair_queueing_fill_message,
};

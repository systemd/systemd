/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "strv.h"

static int fair_queueing_controlled_delay_init(QDisc *qdisc) {
        FairQueueingControlledDelay *fqcd;

        assert(qdisc);

        fqcd = FQ_CODEL(qdisc);

        fqcd->memory_limit = UINT32_MAX;
        fqcd->ce_threshold_usec = USEC_INFINITY;
        fqcd->ecn = -1;

        return 0;
}

static int fair_queueing_controlled_delay_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        FairQueueingControlledDelay *fqcd;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(fqcd = FQ_CODEL(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "fq_codel");
        if (r < 0)
                return r;

        if (fqcd->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_LIMIT, fqcd->packet_limit);
                if (r < 0)
                        return r;
        }

        if (fqcd->flows > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_FLOWS, fqcd->flows);
                if (r < 0)
                        return r;
        }

        if (fqcd->quantum > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_QUANTUM, fqcd->quantum);
                if (r < 0)
                        return r;
        }

        if (fqcd->interval_usec > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_INTERVAL, fqcd->interval_usec);
                if (r < 0)
                        return r;
        }

        if (fqcd->target_usec > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_TARGET, fqcd->target_usec);
                if (r < 0)
                        return r;
        }

        if (fqcd->ecn >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_ECN, fqcd->ecn);
                if (r < 0)
                        return r;
        }

        if (fqcd->ce_threshold_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_CE_THRESHOLD, fqcd->ce_threshold_usec);
                if (r < 0)
                        return r;
        }

        if (fqcd->memory_limit != UINT32_MAX) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_MEMORY_LIMIT, fqcd->memory_limit);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_fair_queueing_controlled_delay_u32(
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
        FairQueueingControlledDelay *fqcd;
        Network *network = ASSERT_PTR(data);
        uint32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fqcd = FQ_CODEL(qdisc);

        if (streq(lvalue, "PacketLimit"))
                p = &fqcd->packet_limit;
        else if (streq(lvalue, "Flows"))
                p = &fqcd->flows;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fair_queueing_controlled_delay_usec(
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
        FairQueueingControlledDelay *fqcd;
        Network *network = ASSERT_PTR(data);
        usec_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fqcd = FQ_CODEL(qdisc);

        if (streq(lvalue, "TargetSec"))
                p = &fqcd->target_usec;
        else if (streq(lvalue, "IntervalSec"))
                p = &fqcd->interval_usec;
        else if (streq(lvalue, "CEThresholdSec"))
                p = &fqcd->ce_threshold_usec;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                if (streq(lvalue, "CEThresholdSec"))
                        *p = USEC_INFINITY;
                else
                        *p = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_sec(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fair_queueing_controlled_delay_bool(
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
        FairQueueingControlledDelay *fqcd;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fqcd = FQ_CODEL(qdisc);

        r = parse_tristate(rvalue, &fqcd->ecn);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_fair_queueing_controlled_delay_size(
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
        FairQueueingControlledDelay *fqcd;
        Network *network = ASSERT_PTR(data);
        uint64_t sz;
        uint32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        fqcd = FQ_CODEL(qdisc);

        if (STR_IN_SET(lvalue, "MemoryLimitBytes", "MemoryLimit"))
                p = &fqcd->memory_limit;
        else if (STR_IN_SET(lvalue, "QuantumBytes", "Quantum"))
                p = &fqcd->quantum;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                if (STR_IN_SET(lvalue, "MemoryLimitBytes", "MemoryLimit"))
                        *p = UINT32_MAX;
                else
                        *p = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_size(rvalue, 1024, &sz);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (sz >= UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *p = sz;
        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable fq_codel_vtable = {
        .object_size = sizeof(FairQueueingControlledDelay),
        .tca_kind = "fq_codel",
        .init = fair_queueing_controlled_delay_init,
        .fill_message = fair_queueing_controlled_delay_fill_message,
};

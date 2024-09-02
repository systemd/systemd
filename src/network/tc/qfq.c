/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "parse-util.h"
#include "qdisc.h"
#include "qfq.h"
#include "string-util.h"

#define QFQ_MAX_WEIGHT       (1 << 10)
#define QFQ_MIN_MAX_PACKET   512
#define QFQ_MAX_MAX_PACKET   (1 << 16)

const QDiscVTable qfq_vtable = {
        .object_size = sizeof(QuickFairQueueing),
        .tca_kind = "qfq",
};

static int quick_fair_queueing_class_fill_message(Link *link, TClass *tclass, sd_netlink_message *req) {
        QuickFairQueueingClass *qfq;
        int r;

        assert(link);
        assert(tclass);
        assert(req);

        assert_se(qfq = TCLASS_TO_QFQ(tclass));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "qfq");
        if (r < 0)
                return r;

        if (qfq->weight > 0) {
                r = sd_netlink_message_append_u32(req, TCA_QFQ_WEIGHT, qfq->weight);
                if (r < 0)
                        return r;
        }

        if (qfq->max_packet > 0) {
                r = sd_netlink_message_append_u32(req, TCA_QFQ_LMAX, qfq->max_packet);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_quick_fair_queueing_weight(
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

        _cleanup_(tclass_unref_or_set_invalidp) TClass *tclass = NULL;
        QuickFairQueueingClass *qfq;
        Network *network = ASSERT_PTR(data);
        uint32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_QFQ, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        qfq = TCLASS_TO_QFQ(tclass);

        if (isempty(rvalue)) {
                qfq->weight = 0;
                TAKE_PTR(tclass);
                return 0;
        }

        r = safe_atou32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (v == 0 || v > QFQ_MAX_WEIGHT) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qfq->weight = v;
        TAKE_PTR(tclass);

        return 0;
}

int config_parse_quick_fair_queueing_max_packet(
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

        _cleanup_(tclass_unref_or_set_invalidp) TClass *tclass = NULL;
        QuickFairQueueingClass *qfq;
        Network *network = ASSERT_PTR(data);
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_QFQ, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        qfq = TCLASS_TO_QFQ(tclass);

        if (isempty(rvalue)) {
                qfq->max_packet = 0;
                TAKE_PTR(tclass);
                return 0;
        }

        r = parse_size(rvalue, 1024, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (v < QFQ_MIN_MAX_PACKET || v > QFQ_MAX_MAX_PACKET) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qfq->max_packet = (uint32_t) v;
        TAKE_PTR(tclass);

        return 0;
}

const TClassVTable qfq_tclass_vtable = {
        .object_size = sizeof(QuickFairQueueingClass),
        .tca_kind = "qfq",
        .fill_message = quick_fair_queueing_class_fill_message,
};

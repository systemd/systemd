/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"

static int controlled_delay_init(QDisc *qdisc) {
        ControlledDelay *cd;

        assert(qdisc);

        cd = CODEL(qdisc);

        cd->ce_threshold_usec = USEC_INFINITY;
        cd->ecn = -1;

        return 0;
}

static int controlled_delay_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        ControlledDelay *cd;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(cd = CODEL(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "codel");
        if (r < 0)
                return r;

        if (cd->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_LIMIT, cd->packet_limit);
                if (r < 0)
                        return r;
        }

        if (cd->interval_usec > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_INTERVAL, cd->interval_usec);
                if (r < 0)
                        return r;
        }

        if (cd->target_usec > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_TARGET, cd->target_usec);
                if (r < 0)
                        return r;
        }

        if (cd->ecn >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_ECN, cd->ecn);
                if (r < 0)
                        return r;
        }

        if (cd->ce_threshold_usec != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_CE_THRESHOLD, cd->ce_threshold_usec);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_controlled_delay_u32(
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
        ControlledDelay *cd;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cd = CODEL(qdisc);

        if (isempty(rvalue)) {
                cd->packet_limit = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &cd->packet_limit);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;

        return 0;
}

int config_parse_controlled_delay_usec(
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
        ControlledDelay *cd;
        Network *network = ASSERT_PTR(data);
        usec_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cd = CODEL(qdisc);

        if (streq(lvalue, "TargetSec"))
                p = &cd->target_usec;
        else if (streq(lvalue, "IntervalSec"))
                p = &cd->interval_usec;
        else if (streq(lvalue, "CEThresholdSec"))
                p = &cd->ce_threshold_usec;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                if (streq(lvalue, "CEThresholdSec"))
                        *p = USEC_INFINITY;
                else
                        *p = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_sec(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;

        return 0;
}

int config_parse_controlled_delay_bool(
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
        ControlledDelay *cd;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cd = CODEL(qdisc);

        r = parse_tristate(rvalue, &cd->ecn);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable codel_vtable = {
        .object_size = sizeof(ControlledDelay),
        .tca_kind = "codel",
        .init = controlled_delay_init,
        .fill_message = controlled_delay_fill_message,
};

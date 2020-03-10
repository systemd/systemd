/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "drr.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-util.h"

static int drr_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        DeficitRoundRobinScheduler *drr;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        drr = DRR(qdisc);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "drr");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if (drr->quantum > 0) {
                r = sd_netlink_message_append_u32(req, TCA_DRR_QUANTUM, drr->quantum);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_DRR_QUANTUM, attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_drr_size(
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
        DeficitRoundRobinScheduler *drr;
        Network *network = data;
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_DRR, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        drr = DRR(qdisc);

        if (isempty(rvalue)) {
                drr->quantum = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1000, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (u > UINT32_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        drr->quantum = (uint32_t) u;

        qdisc = NULL;
        return 0;
}

const QDiscVTable drr_vtable = {
        .object_size = sizeof(DeficitRoundRobinScheduler),
        .tca_kind = "drr",
        .fill_message = drr_fill_message,
};

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "drr.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-util.h"

const QDiscVTable drr_vtable = {
        .object_size = sizeof(DeficitRoundRobinScheduler),
        .tca_kind = "drr",
};

static int drr_class_fill_message(Link *link, TClass *tclass, sd_netlink_message *req) {
        DeficitRoundRobinSchedulerClass *drr;
        int r;

        assert(link);
        assert(tclass);
        assert(req);

        assert_se(drr = TCLASS_TO_DRR(tclass));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "drr");
        if (r < 0)
                return r;

        if (drr->quantum > 0) {
                r = sd_netlink_message_append_u32(req, TCA_DRR_QUANTUM, drr->quantum);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        DeficitRoundRobinSchedulerClass *drr;
        Network *network = ASSERT_PTR(data);
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_DRR, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        drr = TCLASS_TO_DRR(tclass);

        if (isempty(rvalue)) {
                drr->quantum = 0;

                TAKE_PTR(tclass);
                return 0;
        }

        r = parse_size(rvalue, 1024, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (u > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        drr->quantum = (uint32_t) u;

        TAKE_PTR(tclass);
        return 0;
}

const TClassVTable drr_tclass_vtable = {
        .object_size = sizeof(DeficitRoundRobinSchedulerClass),
        .tca_kind = "drr",
        .fill_message = drr_class_fill_message,
};

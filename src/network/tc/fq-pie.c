/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "fq-pie.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-util.h"

static int fq_pie_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        FlowQueuePIE *fq_pie;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(fq_pie = FQ_PIE(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "fq_pie");
        if (r < 0)
                return r;

        if (fq_pie->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_FQ_PIE_LIMIT, fq_pie->packet_limit);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_fq_pie_packet_limit(
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
        FlowQueuePIE *fq_pie;
        Network *network = ASSERT_PTR(data);
        uint32_t val;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_FQ_PIE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_WARNING, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        fq_pie = FQ_PIE(qdisc);

        if (isempty(rvalue)) {
                fq_pie->packet_limit = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &val);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (val == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        fq_pie->packet_limit = val;
        qdisc = NULL;

        return 0;
}

const QDiscVTable fq_pie_vtable = {
        .object_size = sizeof(FlowQueuePIE),
        .tca_kind = "fq_pie",
        .fill_message = fq_pie_fill_message,
};

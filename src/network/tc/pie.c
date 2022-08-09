/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "pie.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-util.h"

static int pie_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        ProportionalIntegralControllerEnhanced *pie;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(pie = PIE(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "pie");
        if (r < 0)
                return r;

        if (pie->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_PIE_LIMIT, pie->packet_limit);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_pie_packet_limit(
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
        ProportionalIntegralControllerEnhanced *pie;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_PIE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        pie = PIE(qdisc);

        if (isempty(rvalue)) {
                pie->packet_limit = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, &pie->packet_limit);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable pie_vtable = {
        .object_size = sizeof(ProportionalIntegralControllerEnhanced),
        .tca_kind = "pie",
        .fill_message = pie_fill_message,
};

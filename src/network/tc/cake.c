/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "cake.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"

static int cake_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        CommonApplicationsKeptEnhanced *c;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        c = CAKE(qdisc);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "cake");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if (c->bandwidth > 0) {
                r = sd_netlink_message_append_u64(req, TCA_CAKE_BASE_RATE64, c->bandwidth);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_CAKE_BASE_RATE64 attribute: %m");
        }

        r = sd_netlink_message_append_s32(req, TCA_CAKE_OVERHEAD, c->overhead);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_CAKE_OVERHEAD attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_cake_bandwidth(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = data;
        uint64_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->bandwidth = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_size(rvalue, 1000, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->bandwidth = k/8;
        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_cake_overhead(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = data;
        int32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->overhead = 0;
                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atoi32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (v < -64 || v > 256) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->overhead = v;
        TAKE_PTR(qdisc);
        return 0;
}

const QDiscVTable cake_vtable = {
        .object_size = sizeof(CommonApplicationsKeptEnhanced),
        .tca_kind = "cake",
        .fill_message = cake_fill_message,
};

/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"

static int controlled_delay_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        ControlledDelay *cd;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        cd = CODEL(qdisc);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "codel");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if (cd->packet_limit > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CODEL_LIMIT, cd->packet_limit);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_CODEL_LIMIT attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_tc_controlled_delay_u32(
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
        ControlledDelay *cd;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_CODEL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        cd = CODEL(qdisc);

        if (isempty(rvalue)) {
                cd->packet_limit = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &cd->packet_limit);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;

        return 0;
}

const QDiscVTable codel_vtable = {
        .object_size = sizeof(ControlledDelay),
        .tca_kind = "codel",
        .fill_message = controlled_delay_fill_message,
};

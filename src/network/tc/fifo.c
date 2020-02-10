/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>
#include <math.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netem.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "tc-util.h"
#include "util.h"

static int fifo_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        struct tc_fifo_qopt opt = {};
        FirstInFirstOut *fifo;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        fifo = FIFO(qdisc);

        if (fifo->limit > 0)
                opt.limit = fifo->limit;

        r = sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(struct tc_fifo_qopt));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_OPTIONS attribute: %m");

        return 0;
}

int config_parse_fifo_size(
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
        Network *network = data;
        FirstInFirstOut *fifo;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_FIFO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        fifo = FIFO(qdisc);

        if (isempty(rvalue)) {
                fifo->limit = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &fifo->limit);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;
        return 0;
}

const QDiscVTable fifo_vtable = {
        .object_size = sizeof(FirstInFirstOut),
        .tca_kind = "pfifo",
        .fill_message = fifo_fill_message,
};

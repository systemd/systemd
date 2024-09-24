/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "sfq.h"
#include "string-util.h"

static int stochastic_fairness_queueing_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        StochasticFairnessQueueing *sfq;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(sfq = SFQ(qdisc));

        const struct tc_sfq_qopt_v1 opt = {
                .v0.perturb_period = sfq->perturb_period / USEC_PER_SEC,
        };

        r = sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        return 0;
}

int config_parse_stochastic_fairness_queueing_perturb_period(
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
        StochasticFairnessQueueing *sfq;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_SFQ, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        sfq = SFQ(qdisc);

        if (isempty(rvalue)) {
                sfq->perturb_period = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_sec(rvalue, &sfq->perturb_period);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable sfq_vtable = {
        .object_size = sizeof(StochasticFairnessQueueing),
        .tca_kind = "sfq",
        .fill_message = stochastic_fairness_queueing_fill_message,
};

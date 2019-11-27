/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "sfq.h"
#include "string-util.h"

int stochastic_fairness_queueing_new(StochasticFairnessQueueing **ret) {
        StochasticFairnessQueueing *sfq = NULL;

        sfq = new0(StochasticFairnessQueueing, 1);
        if (!sfq)
                return -ENOMEM;

        *ret = TAKE_PTR(sfq);

        return 0;
}

int stochastic_fairness_queueing_fill_message(Link *link, const StochasticFairnessQueueing *sfq, sd_netlink_message *req) {
        struct tc_sfq_qopt_v1 opt = {};
        int r;

        assert(link);
        assert(sfq);
        assert(req);

        opt.v0.perturb_period = sfq->perturb_period / USEC_PER_SEC;

        r = sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(struct tc_sfq_qopt_v1));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_OPTIONS attribute: %m");

        return 0;
}

int config_parse_tc_stochastic_fairness_queueing_perturb_period(
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(network, filename, section_line, &qdisc);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                qdisc->sfq.perturb_period = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_sec(rvalue, &qdisc->sfq.perturb_period);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc->has_stochastic_fairness_queueing = true;
        qdisc = NULL;

        return 0;
}

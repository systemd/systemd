/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "sfb.h"
#include "string-util.h"

static int stochastic_fair_blue_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        StochasticFairBlue *sfb;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(sfb = SFB(qdisc));

        const struct tc_sfb_qopt opt = {
            .rehash_interval = 600*1000,
            .warmup_time = 60*1000,
            .penalty_rate = 10,
            .penalty_burst = 20,
            .increment = (SFB_MAX_PROB + 1000) / 2000,
            .decrement = (SFB_MAX_PROB + 10000) / 20000,
            .max = 25,
            .bin_size = 20,
            .limit = sfb->packet_limit,
        };

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "sfb");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_SFB_PARMS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_stochastic_fair_blue_u32(
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
        StochasticFairBlue *sfb;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_SFB, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        sfb = SFB(qdisc);

        if (isempty(rvalue)) {
                sfb->packet_limit = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, &sfb->packet_limit);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable sfb_vtable = {
        .object_size = sizeof(StochasticFairBlue),
        .tca_kind = "sfb",
        .fill_message = stochastic_fair_blue_fill_message,
};

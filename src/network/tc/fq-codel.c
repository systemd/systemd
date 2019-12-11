/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"

int fair_queuing_controlled_delay_new(FairQueuingControlledDelay **ret) {
        FairQueuingControlledDelay *fqcd = NULL;

        fqcd = new0(FairQueuingControlledDelay, 1);
        if (!fqcd)
                return -ENOMEM;

        *ret = TAKE_PTR(fqcd);

        return 0;
}

int fair_queuing_controlled_delay_fill_message(Link *link, const FairQueuingControlledDelay *fqcd, sd_netlink_message *req) {
        int r;

        assert(link);
        assert(fqcd);
        assert(req);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "fq_codel");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_append_u32(req, TCA_FQ_CODEL_LIMIT, fqcd->limit);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_FQ_CODEL_LIMIT attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_tc_fair_queuing_controlled_delay_limit(
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
                qdisc->fq_codel.limit = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &qdisc->fq_codel.limit);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc->has_fair_queuing_controlled_delay = true;
        qdisc = NULL;

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

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
#include "util.h"

int token_buffer_filter_new(TokenBufferFilter **ret) {
        TokenBufferFilter *ne = NULL;

        ne = new0(TokenBufferFilter, 1);
        if (!ne)
                return -ENOMEM;

        *ret = TAKE_PTR(ne);

        return 0;
}

int token_buffer_filter_fill_message(Link *link, const TokenBufferFilter *tbf, sd_netlink_message *req) {
        struct tc_tbf_qopt opt = {};
        int r;

        assert(link);
        assert(tbf);
        assert(req);

        opt.rate.rate = tbf->rate >= (1ULL << 32) ? ~0U : tbf->rate;
        opt.limit = tbf->rate * (double) tbf->latency / USEC_PER_SEC + tbf->burst;

        r = sd_netlink_message_open_array(req, TCA_OPTIONS);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_append_data(req, TCA_TBF_PARMS, &opt, sizeof(struct tc_tbf_qopt));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_TBF_PARMS attribute: %m");

        r = sd_netlink_message_append_data(req, TCA_TBF_BURST, &tbf->burst, sizeof(tbf->burst));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_TBF_BURST attribute: %m");

        if (tbf->rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_data(req, TCA_TBF_RATE64, &tbf->rate, sizeof(tbf->rate));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_TBF_RATE64 attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_tc_token_buffer_filter_size(
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
        uint64_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(network, filename, section_line, &qdisc);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                if (streq(lvalue, "TokenBufferFilterRate"))
                        qdisc->tbf.rate = 0;
                else if (streq(lvalue, "TokenBufferFilterBurst"))
                        qdisc->tbf.burst = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1000, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "TokenBufferFilterRate"))
                qdisc->tbf.rate = k / 8;
        else if (streq(lvalue, "TokenBufferFilterBurst"))
                qdisc->tbf.burst = k;

        qdisc->has_token_buffer_filter = true;
        qdisc = NULL;

        return 0;
}

int config_parse_tc_token_buffer_filter_latency(
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
        usec_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(network, filename, section_line, &qdisc);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                qdisc->tbf.latency = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_sec(rvalue, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc->tbf.latency = u;

        qdisc->has_token_buffer_filter = true;
        qdisc = NULL;

        return 0;
}

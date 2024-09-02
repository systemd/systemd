/* SPDX-License-Identifier: LGPL-2.1-or-later
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
#include "strv.h"
#include "tc-util.h"

static int token_bucket_filter_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        uint32_t rtab[256], ptab[256];
        TokenBucketFilter *tbf;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(tbf = TBF(qdisc));

        struct tc_tbf_qopt opt = {
                .rate.rate = tbf->rate >= (1ULL << 32) ? ~0U : tbf->rate,
                .peakrate.rate = tbf->peak_rate >= (1ULL << 32) ? ~0U : tbf->peak_rate,
                .rate.mpu = tbf->mpu,
        };

        if (tbf->limit > 0)
                opt.limit = tbf->limit;
        else {
                double lim, lim2;

                lim = tbf->rate * (double) tbf->latency / USEC_PER_SEC + tbf->burst;
                if (tbf->peak_rate > 0) {
                        lim2 = tbf->peak_rate * (double) tbf->latency / USEC_PER_SEC + tbf->mtu;
                        lim = MIN(lim, lim2);
                }
                opt.limit = lim;
        }

        r = tc_fill_ratespec_and_table(&opt.rate, rtab, tbf->mtu);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate ratespec: %m");

        r = tc_transmit_time(opt.rate.rate, tbf->burst, &opt.buffer);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate buffer size: %m");

        if (opt.peakrate.rate > 0) {
                opt.peakrate.mpu = tbf->mpu;

                r = tc_fill_ratespec_and_table(&opt.peakrate, ptab, tbf->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to calculate ratespec: %m");

                r = tc_transmit_time(opt.peakrate.rate, tbf->mtu, &opt.mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to calculate mtu size: %m");
        }

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "tbf");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_TBF_PARMS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_TBF_BURST, &tbf->burst, sizeof(tbf->burst));
        if (r < 0)
                return r;

        if (tbf->rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_u64(req, TCA_TBF_RATE64, tbf->rate);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_data(req, TCA_TBF_RTAB, rtab, sizeof(rtab));
        if (r < 0)
                return r;

        if (opt.peakrate.rate > 0) {
                if (tbf->peak_rate >= (1ULL << 32)) {
                        r = sd_netlink_message_append_u64(req, TCA_TBF_PRATE64, tbf->peak_rate);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_append_u32(req, TCA_TBF_PBURST, tbf->mtu);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_data(req, TCA_TBF_PTAB, ptab, sizeof(ptab));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_token_bucket_filter_size(
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
        Network *network = ASSERT_PTR(data);
        TokenBucketFilter *tbf;
        uint64_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TBF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        tbf = TBF(qdisc);

        if (isempty(rvalue)) {
                if (STR_IN_SET(lvalue, "BurstBytes", "Burst"))
                        tbf->burst = 0;
                else if (STR_IN_SET(lvalue, "LimitBytes", "LimitSize"))
                        tbf->limit = 0;
                else if (streq(lvalue, "MTUBytes"))
                        tbf->mtu = 0;
                else if (streq(lvalue, "MPUBytes"))
                        tbf->mpu = 0;
                else
                        assert_not_reached();

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_size(rvalue, 1024, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (STR_IN_SET(lvalue, "BurstBytes", "Burst"))
                tbf->burst = k;
        else if (STR_IN_SET(lvalue, "LimitBytes", "LimitSize"))
                tbf->limit = k;
        else if (streq(lvalue, "MPUBytes"))
                tbf->mpu = k;
        else if (streq(lvalue, "MTUBytes"))
                tbf->mtu = k;
        else
                assert_not_reached();

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_token_bucket_filter_rate(
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
        Network *network = ASSERT_PTR(data);
        TokenBucketFilter *tbf;
        uint64_t k, *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TBF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        tbf = TBF(qdisc);
        if (streq(lvalue, "Rate"))
                p = &tbf->rate;
        else if (streq(lvalue, "PeakRate"))
                p = &tbf->peak_rate;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

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

        *p = k / 8;

        qdisc = NULL;

        return 0;
}

int config_parse_token_bucket_filter_latency(
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
        Network *network = ASSERT_PTR(data);
        TokenBucketFilter *tbf;
        usec_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TBF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        tbf = TBF(qdisc);

        if (isempty(rvalue)) {
                tbf->latency = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_sec(rvalue, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        tbf->latency = u;

        qdisc = NULL;

        return 0;
}

static int token_bucket_filter_verify(QDisc *qdisc) {
        TokenBucketFilter *tbf = TBF(qdisc);

        if (tbf->limit > 0 && tbf->latency > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Specifying both LimitBytes= and LatencySec= is not allowed. "
                                         "Ignoring [TokenBucketFilter] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (tbf->limit == 0 && tbf->latency == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Either LimitBytes= or LatencySec= is required. "
                                         "Ignoring [TokenBucketFilter] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (tbf->rate == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Rate= is mandatory. "
                                         "Ignoring [TokenBucketFilter] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (tbf->burst == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: BurstBytes= is mandatory. "
                                         "Ignoring [TokenBucketFilter] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (tbf->peak_rate > 0 && tbf->mtu == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: MTUBytes= is mandatory when PeakRate= is specified. "
                                         "Ignoring [TokenBucketFilter] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        return 0;
}

const QDiscVTable tbf_vtable = {
        .object_size = sizeof(TokenBucketFilter),
        .tca_kind = "tbf",
        .fill_message = token_bucket_filter_fill_message,
        .verify = token_bucket_filter_verify
};

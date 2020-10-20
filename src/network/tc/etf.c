/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 Intel Corporation */

#include <linux/pkt_sched.h>
#include <math.h>
#include <time.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "etf.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "tc-util.h"
#include "util.h"
#include "macro.h"

static int earliest_txtime_first_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        struct tc_etf_qopt opt = {};
        EarliestTxTimeFirst *etf;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        etf = ETF(qdisc);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "etf");
        if (r < 0)
          return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if ( opt.clockid != CLOCKID_INVALID ) {

          opt.clockid = etf->clockid;
          opt.delta = etf->delta;
          opt.flags = 0;
          if (etf->deadline)
            opt.flags |= TC_ETF_DEADLINE_MODE_ON;
          if (etf->offload)
            opt.flags |= TC_ETF_OFFLOAD_ON;
          if (etf->skipsock)
            opt.flags |= TC_ETF_SKIP_SOCK_CHECK;

          r = sd_netlink_message_append_data(req, TCA_ETF_PARMS, &opt, sizeof(struct tc_etf_qopt));
          if (r < 0)
            return log_link_error_errno(link, r, "Could not append TCA_ETF_PARMS attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
          return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_tc_etf_clockid (
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
        EarliestTxTimeFirst *etf;
        int r;
        const struct static_clockid *c;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_ETF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        etf = ETF(qdisc);

        etf->clockid = CLOCKID_INVALID;

        if (isempty(rvalue)) {

                TAKE_PTR(qdisc);
                return 0;
        }

        /* Drop the CLOCK_ prefix if that is being used. */
        if (strcasestr(rvalue, "CLOCK_") != NULL)
            rvalue += sizeof("CLOCK_") - 1;

        for (c = clockids_sysv; c->name; c++) {
            if (strcasecmp(c->name, rvalue) == 0) {
                etf->clockid = c->clockid;

                TAKE_PTR(qdisc);

                return 0;
            }
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_tc_etf_delay_nsec (
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
        EarliestTxTimeFirst *etf;
        __s32 v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_ETF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        etf = ETF(qdisc);

        if (isempty(rvalue)) {
                etf->delta = 0;

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
        if (v > INT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        etf->delta = v;

        TAKE_PTR(qdisc);

        return 0;
}


int config_parse_tc_etf_bool (
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
        EarliestTxTimeFirst *etf;
        int r;
        bool k, *p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_ETF, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        etf = ETF(qdisc);

        if (streq(lvalue, "EarliestTxTimeFirstDeadline"))
                p = &etf->deadline;
        else if (streq(lvalue, "EarliestTxTimeFirstOffload"))
                p = &etf->offload;
        else if (streq(lvalue, "EarliestTxTimeFirstSkipsock"))
                p = &etf->skipsock;
        else
                assert_not_reached();

        if (isempty(rvalue)) {

                *p = -1;

                TAKE_PTR(qdisc);
                return 0;
        }

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        *p = k;
        TAKE_PTR(qdisc);

        return 0;
}

static int earliest_txtime_first_verify(QDisc *qdisc) {
        EarliestTxTimeFirst *etf = ETF(qdisc);

        assert(qdisc);

        etf = ETF(qdisc);

        if (etf->clockid == CLOCKID_INVALID)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Clockid= is mandatory. "
                                         "Ignoring [EarliestTxTimeFirst] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        return 0;
}

const QDiscVTable etf_vtable = {
        .object_size = sizeof(EarliestTxTimeFirst),
        .tca_kind = "etf",
        .fill_message = earliest_txtime_first_fill_message,
        .verify = earliest_txtime_first_verify
};

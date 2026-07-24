/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "cbs.h"
#include "conf-parser.h"
#include "log.h"
#include "networkd-link.h"
#include "parse-util.h"
#include "string-util.h"

static int credit_based_shaper_init(QDisc *qdisc) {
        CreditBasedShaper *cbs;

        assert(qdisc);

        cbs = CBS(qdisc);

        cbs->offload = -1;
        cbs->hicredit = INT32_MAX;
        cbs->locredit = INT32_MAX;

        return 0;
}

static int credit_based_shaper_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        CreditBasedShaper *cbs;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(cbs = CBS(qdisc));

        struct tc_cbs_qopt opt = {
                .idleslope = cbs->idleslope,
                .sendslope = cbs->sendslope,
        };

        if (cbs->hicredit != INT32_MAX)
                opt.hicredit = cbs->hicredit;

        if (cbs->locredit != INT32_MAX)
                opt.locredit = cbs->locredit;

        if (cbs->offload >= 0)
                opt.offload = cbs->offload;

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "cbs");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_CBS_PARMS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

static int credit_based_shaper_verify(QDisc *qdisc) {
        CreditBasedShaper *cbs = CBS(qdisc);

        if (cbs->idleslope == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: IdleSlope= is mandatory. "
                                         "Ignoring [CreditBasedShaper] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (cbs->sendslope == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: SendSlope= is mandatory. "
                                         "Ignoring [CreditBasedShaper] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        return 0;
}

int config_parse_cbs_slope(
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
        CreditBasedShaper *cbs;
        Network *network = ASSERT_PTR(data);
        int32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CBS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cbs = CBS(qdisc);

        if (streq(lvalue, "IdleSlope"))
                p = &cbs->idleslope;
        else if (streq(lvalue, "SendSlope"))
                p = &cbs->sendslope;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atoi32(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_cbs_s32(
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
        CreditBasedShaper *cbs;
        Network *network = ASSERT_PTR(data);
        int32_t *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CBS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cbs = CBS(qdisc);

        if (streq(lvalue, "HiCredit"))
                p = &cbs->hicredit;
        else if (streq(lvalue, "LoCredit"))
                p = &cbs->locredit;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = INT32_MAX;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atoi32(rvalue, p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_cbs_tristate(
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
        CreditBasedShaper *cbs;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CBS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        cbs = CBS(qdisc);

        r = parse_tristate(rvalue, &cbs->offload);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

const QDiscVTable cbs_vtable = {
        .init = credit_based_shaper_init,
        .object_size = sizeof(CreditBasedShaper),
        .tca_kind = "cbs",
        .fill_message = credit_based_shaper_fill_message,
        .verify = credit_based_shaper_verify,
};

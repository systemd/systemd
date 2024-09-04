/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netem.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "strv.h"
#include "tc-util.h"

static int network_emulator_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        NetworkEmulator *ne;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(ne = NETEM(qdisc));

        struct tc_netem_qopt opt = {
                .limit = ne->limit > 0 ? ne->limit : 1000,
                .loss = ne->loss,
                .duplicate = ne->duplicate,
        };

        if (ne->delay != USEC_INFINITY) {
                r = tc_time_to_tick(ne->delay, &opt.latency);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to calculate latency in TCA_OPTION: %m");
        }

        if (ne->jitter != USEC_INFINITY) {
                r = tc_time_to_tick(ne->jitter, &opt.jitter);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to calculate jitter in TCA_OPTION: %m");
        }

        r = sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        return 0;
}

int config_parse_network_emulator_delay(
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
        NetworkEmulator *ne;
        usec_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_NETEM, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ne = NETEM(qdisc);

        if (isempty(rvalue)) {
                if (STR_IN_SET(lvalue, "DelaySec", "NetworkEmulatorDelaySec"))
                        ne->delay = USEC_INFINITY;
                else if (STR_IN_SET(lvalue, "DelayJitterSec", "NetworkEmulatorDelayJitterSec"))
                        ne->jitter = USEC_INFINITY;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_sec(rvalue, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (STR_IN_SET(lvalue, "DelaySec", "NetworkEmulatorDelaySec"))
                ne->delay = u;
        else if (STR_IN_SET(lvalue, "DelayJitterSec", "NetworkEmulatorDelayJitterSec"))
                ne->jitter = u;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_network_emulator_rate(
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
        NetworkEmulator *ne;
        uint32_t rate;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_NETEM, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ne = NETEM(qdisc);

        if (isempty(rvalue)) {
                if (STR_IN_SET(lvalue, "LossRate", "NetworkEmulatorLossRate"))
                        ne->loss = 0;
                else if (STR_IN_SET(lvalue, "DuplicateRate", "NetworkEmulatorDuplicateRate"))
                        ne->duplicate = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_tc_percent(rvalue, &rate);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (STR_IN_SET(lvalue, "LossRate", "NetworkEmulatorLossRate"))
                ne->loss = rate;
        else if (STR_IN_SET(lvalue, "DuplicateRate", "NetworkEmulatorDuplicateRate"))
                ne->duplicate = rate;

        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_network_emulator_packet_limit(
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
        NetworkEmulator *ne;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_NETEM, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ne = NETEM(qdisc);

        if (isempty(rvalue)) {
                ne->limit = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou(rvalue, &ne->limit);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);
        return 0;
}

const QDiscVTable netem_vtable = {
        .object_size = sizeof(NetworkEmulator),
        .tca_kind = "netem",
        .fill_message = network_emulator_fill_message,
};

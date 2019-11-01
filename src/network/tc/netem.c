/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>
#include <math.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "netem.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "tc-util.h"
#include "util.h"

int network_emulator_new(NetworkEmulator **ret) {
        NetworkEmulator *ne = NULL;

        ne = new(NetworkEmulator, 1);
        if (!ne)
                return -ENOMEM;

        *ne = (NetworkEmulator) {
                .delay = USEC_INFINITY,
                .jitter = USEC_INFINITY,
        };

        *ret = TAKE_PTR(ne);

        return 0;
}

int network_emulator_fill_message(Link *link, QDiscs *qdisc, sd_netlink_message *req) {
        struct tc_netem_qopt opt = {
               .limit = 1000,
        };
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        if (qdisc->ne.limit > 0)
                opt.limit = qdisc->ne.limit;

        if (qdisc->ne.loss > 0)
                opt.loss = qdisc->ne.loss;

        if (qdisc->ne.duplicate > 0)
                opt.duplicate = qdisc->ne.duplicate;

        if (qdisc->ne.delay != USEC_INFINITY) {
                r = tc_time_to_tick(qdisc->ne.delay, &opt.latency);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to calculate latency in TCA_OPTION: %m");
        }

        if (qdisc->ne.jitter != USEC_INFINITY) {
                r = tc_time_to_tick(qdisc->ne.jitter, &opt.jitter);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to calculate jitter in TCA_OPTION: %m");
        }

        r = sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(struct tc_netem_qopt));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_OPTION attribute: %m");

        return 0;
}

int config_parse_tc_network_emulator_delay(
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

        _cleanup_(qdisc_free_or_set_invalidp) QDiscs *qdisc = NULL;
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
                if (streq(lvalue, "NetworkEmulatorDelaySec"))
                        qdisc->ne.delay = USEC_INFINITY;
                else if (streq(lvalue, "NetworkEmulatorDelayJitterSec"))
                        qdisc->ne.jitter = USEC_INFINITY;

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

        if (streq(lvalue, "NetworkEmulatorDelaySec"))
                qdisc->ne.delay = u;
        else if (streq(lvalue, "NetworkEmulatorDelayJitterSec"))
                qdisc->ne.jitter = u;

        qdisc->has_network_emulator = true;
        qdisc = NULL;

        return 0;
}

int config_parse_tc_network_emulator_rate(
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

        _cleanup_(qdisc_free_or_set_invalidp) QDiscs *qdisc = NULL;
        Network *network = data;
        uint32_t rate;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(network, filename, section_line, &qdisc);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                qdisc->ne.loss = 0;

                qdisc = NULL;
                return 0;
        }

        r = parse_tc_percent(rvalue, &rate);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "NetworkEmulatorLossRate"))
                qdisc->ne.loss = rate;
        else if (streq(lvalue, "NetworkEmulatorDuplicateRate"))
                qdisc->ne.duplicate = rate;

        qdisc = NULL;
        return 0;
}

int config_parse_tc_network_emulator_packet_limit(
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

        _cleanup_(qdisc_free_or_set_invalidp) QDiscs *qdisc = NULL;
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
                qdisc->ne.limit = 0;
                qdisc = NULL;

                return 0;
        }

        r = safe_atou(rvalue, &qdisc->ne.limit);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse 'NetworkEmulatorPacketLimit=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        qdisc = NULL;
        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "cake.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-table.h"
#include "string-util.h"

static int cake_init(QDisc *qdisc) {
        CommonApplicationsKeptEnhanced *c;

        assert(qdisc);

        c = CAKE(qdisc);

        c->autorate = -1;
        c->compensation_mode = _CAKE_COMPENSATION_MODE_INVALID;
        c->raw = -1;
        c->flow_isolation_mode = _CAKE_FLOW_ISOLATION_MODE_INVALID;
        c->nat = -1;
        c->preset = _CAKE_PRESET_INVALID;
        c->wash = -1;
        c->split_gso = -1;
        c->ack_filter = _CAKE_ACK_FILTER_INVALID;

        return 0;
}

static int cake_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        CommonApplicationsKeptEnhanced *c;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(c = CAKE(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "cake");
        if (r < 0)
                return r;

        if (c->bandwidth > 0) {
                r = sd_netlink_message_append_u64(req, TCA_CAKE_BASE_RATE64, c->bandwidth);
                if (r < 0)
                        return r;
        }

        if (c->autorate >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_AUTORATE, c->autorate);
                if (r < 0)
                        return r;
        }

        if (c->overhead_set) {
                r = sd_netlink_message_append_s32(req, TCA_CAKE_OVERHEAD, c->overhead);
                if (r < 0)
                        return r;
        }

        if (c->mpu > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_MPU, c->mpu);
                if (r < 0)
                        return r;
        }

        if (c->compensation_mode >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_ATM, c->compensation_mode);
                if (r < 0)
                        return r;
        }

        if (c->raw > 0) {
                /* TCA_CAKE_RAW attribute is mostly a flag, not boolean. */
                r = sd_netlink_message_append_u32(req, TCA_CAKE_RAW, 0);
                if (r < 0)
                        return r;
        }

        if (c->flow_isolation_mode >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_FLOW_MODE, c->flow_isolation_mode);
                if (r < 0)
                        return r;
        }

        if (c->nat >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_NAT, c->nat);
                if (r < 0)
                        return r;
        }

        if (c->preset >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_DIFFSERV_MODE, c->preset);
                if (r < 0)
                        return r;
        }

        if (c->fwmark > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_FWMARK, c->fwmark);
                if (r < 0)
                        return r;
        }

        if (c->wash >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_WASH, c->wash);
                if (r < 0)
                        return r;
        }

        if (c->split_gso >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_SPLIT_GSO, c->split_gso);
                if (r < 0)
                        return r;
        }

        if (c->rtt > 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_RTT, c->rtt);
                if (r < 0)
                        return r;
        }

        if (c->ack_filter >= 0) {
                r = sd_netlink_message_append_u32(req, TCA_CAKE_ACK_FILTER, c->ack_filter);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_cake_bandwidth(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        uint64_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->bandwidth = 0;

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

        c->bandwidth = k/8;
        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_cake_overhead(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        int32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->overhead_set = false;
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
        if (v < -64 || v > 256) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->overhead = v;
        c->overhead_set = true;
        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_cake_mpu(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        uint32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->mpu = 0;
                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (v <= 0 || v > 256) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->mpu = v;
        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_cake_tristate(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        int *dest, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (streq(lvalue, "AutoRateIngress"))
                dest = &c->autorate;
        else if (streq(lvalue, "UseRawPacketSize"))
                dest = &c->raw;
        else if (streq(lvalue, "NAT"))
                dest = &c->nat;
        else if (streq(lvalue, "Wash"))
                dest = &c->wash;
        else if (streq(lvalue, "SplitGSO"))
                dest = &c->split_gso;
        else
                assert_not_reached();

        r = parse_tristate(rvalue, dest);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);
        return 0;
}

static const char * const cake_compensation_mode_table[_CAKE_COMPENSATION_MODE_MAX] = {
        [CAKE_COMPENSATION_MODE_NONE] = "none",
        [CAKE_COMPENSATION_MODE_ATM]  = "atm",
        [CAKE_COMPENSATION_MODE_PTM]  = "ptm",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(cake_compensation_mode, CakeCompensationMode);

int config_parse_cake_compensation_mode(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        CakeCompensationMode mode;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->compensation_mode = _CAKE_COMPENSATION_MODE_INVALID;
                TAKE_PTR(qdisc);
                return 0;
        }

        mode = cake_compensation_mode_from_string(rvalue);
        if (mode < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, mode,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->compensation_mode = mode;
        TAKE_PTR(qdisc);
        return 0;
}

static const char * const cake_flow_isolation_mode_table[_CAKE_FLOW_ISOLATION_MODE_MAX] = {
        [CAKE_FLOW_ISOLATION_MODE_NONE]     = "none",
        [CAKE_FLOW_ISOLATION_MODE_SRC_IP]   = "src-host",
        [CAKE_FLOW_ISOLATION_MODE_DST_IP]   = "dst-host",
        [CAKE_FLOW_ISOLATION_MODE_HOSTS]    = "hosts",
        [CAKE_FLOW_ISOLATION_MODE_FLOWS]    = "flows",
        [CAKE_FLOW_ISOLATION_MODE_DUAL_SRC] = "dual-src-host",
        [CAKE_FLOW_ISOLATION_MODE_DUAL_DST] = "dual-dst-host",
        [CAKE_FLOW_ISOLATION_MODE_TRIPLE]   = "triple",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(cake_flow_isolation_mode, CakeFlowIsolationMode);

int config_parse_cake_flow_isolation_mode(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        CakeFlowIsolationMode mode;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->flow_isolation_mode = _CAKE_FLOW_ISOLATION_MODE_INVALID;
                TAKE_PTR(qdisc);
                return 0;
        }

        mode = cake_flow_isolation_mode_from_string(rvalue);
        if (mode < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, mode,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->flow_isolation_mode = mode;
        TAKE_PTR(qdisc);
        return 0;
}

static const char * const cake_priority_queueing_preset_table[_CAKE_PRESET_MAX] = {
        [CAKE_PRESET_DIFFSERV3]  = "diffserv3",
        [CAKE_PRESET_DIFFSERV4]  = "diffserv4",
        [CAKE_PRESET_DIFFSERV8]  = "diffserv8",
        [CAKE_PRESET_BESTEFFORT] = "besteffort",
        [CAKE_PRESET_PRECEDENCE] = "precedence",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(cake_priority_queueing_preset, CakePriorityQueueingPreset);

int config_parse_cake_priority_queueing_preset(
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
        CommonApplicationsKeptEnhanced *c;
        CakePriorityQueueingPreset preset;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->preset = _CAKE_PRESET_INVALID;
                TAKE_PTR(qdisc);
                return 0;
        }

        preset = cake_priority_queueing_preset_from_string(rvalue);
        if (preset < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, preset,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->preset = preset;
        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_cake_fwmark(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        uint32_t fwmark;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->fwmark = 0;
                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, &fwmark);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (fwmark <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->fwmark = fwmark;
        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_cake_rtt(
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
        CommonApplicationsKeptEnhanced *c;
        Network *network = ASSERT_PTR(data);
        usec_t t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->rtt = 0;
                TAKE_PTR(qdisc);
                return 0;
        }

        r = parse_sec(rvalue, &t);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (t <= 0 || t > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->rtt = t;
        TAKE_PTR(qdisc);
        return 0;
}

static const char * const cake_ack_filter_table[_CAKE_ACK_FILTER_MAX] = {
        [CAKE_ACK_FILTER_NO]         = "no",
        [CAKE_ACK_FILTER_YES]        = "yes",
        [CAKE_ACK_FILTER_AGGRESSIVE] = "aggressive",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(cake_ack_filter, CakeAckFilter, CAKE_ACK_FILTER_YES);

int config_parse_cake_ack_filter(
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
        CommonApplicationsKeptEnhanced *c;
        CakeAckFilter ack_filter;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_CAKE, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        c = CAKE(qdisc);

        if (isempty(rvalue)) {
                c->ack_filter = _CAKE_ACK_FILTER_INVALID;
                TAKE_PTR(qdisc);
                return 0;
        }

        ack_filter = cake_ack_filter_from_string(rvalue);
        if (ack_filter < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, ack_filter,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        c->ack_filter = ack_filter;
        TAKE_PTR(qdisc);
        return 0;
}

const QDiscVTable cake_vtable = {
        .object_size = sizeof(CommonApplicationsKeptEnhanced),
        .tca_kind = "cake",
        .init = cake_init,
        .fill_message = cake_fill_message,
};

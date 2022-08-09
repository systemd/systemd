/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/can/netlink.h>

#include "networkd-can.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-setlink.h"
#include "parse-util.h"
#include "string-util.h"

#define CAN_TERMINATION_DEFAULT_OHM_VALUE 120

int can_set_netlink_message(Link *link, sd_netlink_message *m) {
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        r = sd_netlink_message_set_flags(m, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, link->kind);
        if (r < 0)
                return r;

        if (link->network->can_bitrate > 0) {
                struct can_bittiming bt = {
                        .bitrate = link->network->can_bitrate,
                        .sample_point = link->network->can_sample_point,
                        .sjw = link->network->can_sync_jump_width,
                };

                log_link_debug(link, "Setting bitrate = %u bit/s", bt.bitrate);
                if (link->network->can_sample_point > 0)
                        log_link_debug(link, "Setting sample point = %u.%u%%", bt.sample_point / 10, bt.sample_point % 10);
                else
                        log_link_debug(link, "Using default sample point");

                r = sd_netlink_message_append_data(m, IFLA_CAN_BITTIMING, &bt, sizeof(bt));
                if (r < 0)
                        return r;
        } else if (link->network->can_time_quanta_ns > 0) {
                struct can_bittiming bt = {
                        .tq = link->network->can_time_quanta_ns,
                        .prop_seg = link->network->can_propagation_segment,
                        .phase_seg1 = link->network->can_phase_buffer_segment_1,
                        .phase_seg2 = link->network->can_phase_buffer_segment_2,
                        .sjw = link->network->can_sync_jump_width,
                };

                log_link_debug(link, "Setting time quanta = %"PRIu32" nsec", bt.tq);
                r = sd_netlink_message_append_data(m, IFLA_CAN_BITTIMING, &bt, sizeof(bt));
                if (r < 0)
                        return r;
        }

        if (link->network->can_data_bitrate > 0) {
                struct can_bittiming bt = {
                        .bitrate = link->network->can_data_bitrate,
                        .sample_point = link->network->can_data_sample_point,
                        .sjw = link->network->can_data_sync_jump_width,
                };

                log_link_debug(link, "Setting data bitrate = %u bit/s", bt.bitrate);
                if (link->network->can_data_sample_point > 0)
                        log_link_debug(link, "Setting data sample point = %u.%u%%", bt.sample_point / 10, bt.sample_point % 10);
                else
                        log_link_debug(link, "Using default data sample point");

                r = sd_netlink_message_append_data(m, IFLA_CAN_DATA_BITTIMING, &bt, sizeof(bt));
                if (r < 0)
                        return r;
        } else if (link->network->can_data_time_quanta_ns > 0) {
                struct can_bittiming bt = {
                        .tq = link->network->can_data_time_quanta_ns,
                        .prop_seg = link->network->can_data_propagation_segment,
                        .phase_seg1 = link->network->can_data_phase_buffer_segment_1,
                        .phase_seg2 = link->network->can_data_phase_buffer_segment_2,
                        .sjw = link->network->can_data_sync_jump_width,
                };

                log_link_debug(link, "Setting data time quanta = %"PRIu32" nsec", bt.tq);
                r = sd_netlink_message_append_data(m, IFLA_CAN_DATA_BITTIMING, &bt, sizeof(bt));
                if (r < 0)
                        return r;
        }

        if (link->network->can_restart_us > 0) {
                uint64_t restart_ms;

                if (link->network->can_restart_us == USEC_INFINITY)
                        restart_ms = 0;
                else
                        restart_ms = DIV_ROUND_UP(link->network->can_restart_us, USEC_PER_MSEC);

                log_link_debug(link, "Setting restart = %s", FORMAT_TIMESPAN(restart_ms * 1000, MSEC_PER_SEC));
                r = sd_netlink_message_append_u32(m, IFLA_CAN_RESTART_MS, restart_ms);
                if (r < 0)
                        return r;
        }

        if (link->network->can_control_mode_mask != 0) {
                struct can_ctrlmode cm = {
                        .mask = link->network->can_control_mode_mask,
                        .flags = link->network->can_control_mode_flags,
                };

                r = sd_netlink_message_append_data(m, IFLA_CAN_CTRLMODE, &cm, sizeof(cm));
                if (r < 0)
                        return r;
        }

        if (link->network->can_termination_set) {
                log_link_debug(link, "Setting can-termination to '%u'.", link->network->can_termination);

                r = sd_netlink_message_append_u16(m, IFLA_CAN_TERMINATION, link->network->can_termination);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_can_bitrate(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *br = ASSERT_PTR(data);
        uint64_t sz;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_size(rvalue, 1000, &sz);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse can bitrate '%s', ignoring: %m", rvalue);
                return 0;
        }

        /* Linux uses __u32 for bitrates, so the value should not exceed that. */
        if (sz <= 0 || sz > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Bit rate out of permitted range 1...4294967295");
                return 0;
        }

        *br = (uint32_t) sz;

        return 0;
}

int config_parse_can_time_quanta(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        nsec_t val, *tq = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_nsec(rvalue, &val);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse can time quanta '%s', ignoring: %m", rvalue);
                return 0;
        }

        /* Linux uses __u32 for bitrates, so the value should not exceed that. */
        if (val <= 0 || val > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Time quanta out of permitted range 1...4294967295");
                return 0;
        }

        *tq = val;
        return 0;
}

int config_parse_can_restart_usec(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        usec_t usec, *restart_usec = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse CAN restart sec '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (usec != USEC_INFINITY &&
            DIV_ROUND_UP(usec, USEC_PER_MSEC) > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "CAN RestartSec= must be in the range 0...%"PRIu32"ms, ignoring: %s", UINT32_MAX, rvalue);
                return 0;
        }

        *restart_usec = usec;
        return 0;
}

int config_parse_can_control_mode(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t mask = ltype;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(mask != 0);

        if (isempty(rvalue)) {
                network->can_control_mode_mask &= ~mask;
                network->can_control_mode_flags &= ~mask;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse CAN control mode '%s', ignoring: %s", lvalue, rvalue);
                return 0;
        }

        network->can_control_mode_mask |= mask;
        SET_FLAG(network->can_control_mode_flags, mask, r);
        return 0;
}

int config_parse_can_termination(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->can_termination_set = false;
                return 0;
        }

        /* Note that 0 termination ohm value means no termination resistor, and there is no conflict
         * between parse_boolean() and safe_atou16() when Termination=0. However, Termination=1 must be
         * treated as 1 ohm, instead of true (and then the default ohm value). So, we need to parse the
         * string with safe_atou16() at first. */

        r = safe_atou16(rvalue, &network->can_termination);
        if (r < 0) {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse CAN termination value, ignoring: %s", rvalue);
                        return 0;
                }

                network->can_termination = r ? CAN_TERMINATION_DEFAULT_OHM_VALUE : 0;
        }

        network->can_termination_set = true;
        return 0;
}

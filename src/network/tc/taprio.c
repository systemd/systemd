/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "extract-word.h"
#include "log.h"
#include "networkd-link.h"
#include "parse-util.h"
#include "string-util.h"
#include "taprio.h"

static int time_aware_priority_shaper_init(QDisc *qdisc) {
        TimeAwarePriorityShaper *taprio;

        assert(qdisc);

        taprio = TAPRIO(qdisc);

        taprio->clockid = CLOCK_TAI;

        return 0;
}

static int time_aware_priority_shaper_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        TimeAwarePriorityShaper *taprio;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(taprio = TAPRIO(qdisc));

        struct tc_mqprio_qopt opt = {
                .num_tc = taprio->num_tc,
        };

        memcpy(opt.prio_tc_map, taprio->map, sizeof(opt.prio_tc_map));
        memcpy(opt.count, taprio->count, sizeof(opt.count));
        memcpy(opt.offset, taprio->offset, sizeof(opt.offset));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "taprio");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_TAPRIO_ATTR_PRIOMAP, &opt, sizeof(opt));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_s32(req, TCA_TAPRIO_ATTR_SCHED_CLOCKID, taprio->clockid);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_BASE_TIME, taprio->base_time);
        if (r < 0)
                return r;

        if (taprio->cycle_time > 0) {
                r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME, taprio->cycle_time);
                if (r < 0)
                        return r;
        }

        if (taprio->cycle_time_extension > 0) {
                r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION, taprio->cycle_time_extension);
                if (r < 0)
                        return r;
        }

        if (taprio->flags > 0) {
                r = sd_netlink_message_append_u32(req, TCA_TAPRIO_ATTR_FLAGS, taprio->flags);
                if (r < 0)
                        return r;
        }

        /* Append schedule entries */
        if (taprio->n_entries > 0) {
                r = sd_netlink_message_open_container(req, TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST);
                if (r < 0)
                        return r;

                for (size_t i = 0; i < taprio->n_entries; i++) {
                        r = sd_netlink_message_open_container(req, TCA_TAPRIO_SCHED_ENTRY);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_append_u32(req, TCA_TAPRIO_SCHED_ENTRY_CMD, taprio->entries[i].command);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_append_u32(req, TCA_TAPRIO_SCHED_ENTRY_GATE_MASK, taprio->entries[i].gate_mask);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_append_u32(req, TCA_TAPRIO_SCHED_ENTRY_INTERVAL, taprio->entries[i].interval);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_close_container(req);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

static int time_aware_priority_shaper_verify(QDisc *qdisc) {
        TimeAwarePriorityShaper *taprio = TAPRIO(qdisc);

        if (taprio->num_tc == 0 || taprio->num_tc > TC_QOPT_MAX_QUEUE)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NumTrafficClasses= must be between 1 and %d. "
                                         "Ignoring [TimeAwarePriorityShaper] section from line %u.",
                                         qdisc->section->filename, TC_QOPT_MAX_QUEUE, qdisc->section->line);

        if (taprio->n_entries == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: At least one ScheduleEntry= is required. "
                                         "Ignoring [TimeAwarePriorityShaper] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        for (unsigned i = 0; i < ELEMENTSOF(taprio->map); i++)
                if (taprio->map[i] >= taprio->num_tc)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: TrafficClassMap= entry %u maps to TC %u "
                                                 "but only %u TCs configured. "
                                                 "Ignoring [TimeAwarePriorityShaper] section from line %u.",
                                                 qdisc->section->filename, i, taprio->map[i],
                                                 taprio->num_tc, qdisc->section->line);

        return 0;
}

int config_parse_taprio_u32(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        uint32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->num_tc = 0;

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

        taprio->num_tc = v;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_clockid(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->clockid = CLOCK_TAI;

                TAKE_PTR(qdisc);
                return 0;
        }

        if (streq(rvalue, "TAI"))
                taprio->clockid = CLOCK_TAI;
        else if (streq(rvalue, "REALTIME"))
                taprio->clockid = CLOCK_REALTIME;
        else if (streq(rvalue, "MONOTONIC"))
                taprio->clockid = CLOCK_MONOTONIC;
        else if (streq(rvalue, "BOOTTIME"))
                taprio->clockid = CLOCK_BOOTTIME;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_schedule_entry(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        TAPrioScheduleEntry *entries;
        _cleanup_free_ char *cmd_str = NULL, *gate_str = NULL, *interval_str = NULL;
        const char *p;
        uint32_t command, gate_mask, interval;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->entries = mfree(taprio->entries);
                taprio->n_entries = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        /* Parse format: "S <gate_mask_hex> <interval_ns>" */
        p = rvalue;

        r = extract_first_word(&p, &cmd_str, NULL, 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse command in '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (streq(cmd_str, "S"))
                command = TC_TAPRIO_CMD_SET_GATES;
        else if (streq(cmd_str, "H"))
                command = TC_TAPRIO_CMD_SET_AND_HOLD;
        else if (streq(cmd_str, "R"))
                command = TC_TAPRIO_CMD_SET_AND_RELEASE;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unknown schedule command '%s', ignoring assignment: %s",
                           cmd_str, rvalue);
                return 0;
        }

        r = extract_first_word(&p, &gate_str, NULL, 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse gate mask in '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        r = safe_atou32_full(gate_str, 16, &gate_mask);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse gate mask '%s', ignoring assignment: %s",
                           gate_str, rvalue);
                return 0;
        }

        r = extract_first_word(&p, &interval_str, NULL, 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse interval in '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        r = safe_atou32(interval_str, &interval);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse interval '%s', ignoring assignment: %s",
                           interval_str, rvalue);
                return 0;
        }

        entries = reallocarray(taprio->entries, taprio->n_entries + 1, sizeof(TAPrioScheduleEntry));
        if (!entries)
                return log_oom();

        entries[taprio->n_entries] = (TAPrioScheduleEntry) {
                .command = command,
                .gate_mask = gate_mask,
                .interval = interval,
        };

        taprio->entries = entries;
        taprio->n_entries++;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_traffic_class_map(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                zero(taprio->map);

                TAKE_PTR(qdisc);
                return 0;
        }

        zero(taprio->map);

        p = rvalue;
        for (unsigned i = 0; i < ELEMENTSOF(taprio->map); i++) {
                _cleanup_free_ char *word = NULL;
                uint8_t v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = safe_atou8(word, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse traffic class index '%s', ignoring assignment: %s",
                                   word, rvalue);
                        return 0;
                }

                taprio->map[i] = v;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_traffic_class_queues(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                zero(taprio->count);
                zero(taprio->offset);

                TAKE_PTR(qdisc);
                return 0;
        }

        zero(taprio->count);
        zero(taprio->offset);

        /* Parse "count@offset" entries, space-separated */
        p = rvalue;
        for (unsigned i = 0; i < TC_QOPT_MAX_QUEUE; i++) {
                _cleanup_free_ char *word = NULL;
                char *at;
                uint16_t cnt, off;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                at = strchr(word, '@');
                if (!at) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Expected 'count@offset' format, ignoring assignment: %s",
                                   word);
                        return 0;
                }

                /* Temporarily NUL-terminate to parse count portion */
                *at = '\0';
                r = safe_atou16(word, &cnt);
                *at = '@';
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse queue count in '%s', ignoring assignment: %s",
                                   word, rvalue);
                        return 0;
                }

                r = safe_atou16(at + 1, &off);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse queue offset '%s', ignoring assignment: %s",
                                   at + 1, rvalue);
                        return 0;
                }

                taprio->count[i] = cnt;
                taprio->offset[i] = off;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_base_time(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        int64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->base_time = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atoi64(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        taprio->base_time = v;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_cycle_time(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        int64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                if (streq(lvalue, "CycleTime"))
                        taprio->cycle_time = 0;
                else if (streq(lvalue, "CycleTimeExtension"))
                        taprio->cycle_time_extension = 0;
                else
                        assert_not_reached();

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atoi64(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (v < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "'%s=' must not be negative, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "CycleTime"))
                taprio->cycle_time = v;
        else if (streq(lvalue, "CycleTimeExtension"))
                taprio->cycle_time_extension = v;
        else
                assert_not_reached();

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_taprio_flags(
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
        TimeAwarePriorityShaper *taprio;
        Network *network = ASSERT_PTR(data);
        uint32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->flags = 0;

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

        taprio->flags = v;

        TAKE_PTR(qdisc);

        return 0;
}

static void time_aware_priority_shaper_done(QDisc *qdisc) {
        TimeAwarePriorityShaper *taprio;

        assert(qdisc);

        taprio = TAPRIO(qdisc);
        free(taprio->entries);
}

static int time_aware_priority_shaper_dup(const QDisc *src, QDisc *dst) {
        const TimeAwarePriorityShaper *s = (const TimeAwarePriorityShaper *) src;
        TimeAwarePriorityShaper *d = TAPRIO(dst);

        if (s->entries && s->n_entries > 0) {
                d->entries = newdup(TAPrioScheduleEntry, s->entries, s->n_entries);
                if (!d->entries)
                        return -ENOMEM;
        }

        return 0;
}

const QDiscVTable taprio_vtable = {
        .init = time_aware_priority_shaper_init,
        .done = time_aware_priority_shaper_done,
        .dup = time_aware_priority_shaper_dup,
        .object_size = sizeof(TimeAwarePriorityShaper),
        .tca_kind = "taprio",
        .fill_message = time_aware_priority_shaper_fill_message,
        .verify = time_aware_priority_shaper_verify,
};

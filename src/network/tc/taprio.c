/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 Intel Corporation */

#include <linux/pkt_sched.h>
#include <math.h>
#include <time.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "taprio.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "tc-util.h"
#include "util.h"
#include "memory-util.h"
#include "macro.h"

static int time_aware_prio_shaper_init(QDisc *qdisc) {
        TimeAwarePrioShaper *taprio;

        assert(qdisc);

        taprio = TAPRIO(qdisc);

        LIST_HEAD_INIT(taprio->sched_head);
        taprio->n_entry = 0;

        memzero(taprio->count, sizeof(uint16_t) * (TC_QOPT_MAX_QUEUE + 1));
        memzero(taprio->offset, sizeof(uint16_t) * (TC_QOPT_MAX_QUEUE + 1));
        taprio->n_queues = 0;

        memzero(taprio->prio, sizeof(uint8_t) * (MQ_PRIO_MAX + 1));
        taprio->n_prio = 0;

        taprio->clockid = CLOCKID_INVALID;
        taprio->cycle_time = 0;
        taprio->cycle_time_extension = 0;
        taprio->base_time = 0;
        taprio->txtime_delay = 0;
        taprio->flags = 0 ; /* sw fallback */

        return 0;
}


static int taprio_set_sched_entries(Link *link, sd_netlink_message *message, const sentry *entry, uint16_t index) {
        int r;

        assert(message);
        assert(entry);
        assert(index > 0);

        /* This returns 1 on success, 0 on recoverable error, and negative errno on failure. */
        r = sd_netlink_message_open_array(message, index);
        if (r < 0)
                return 0;

        r = sd_netlink_message_append_u32(message, TCA_TAPRIO_SCHED_ENTRY_INDEX, index);
        if (r < 0)
                goto cancel;

        r = sd_netlink_message_append_u8(message, TCA_TAPRIO_SCHED_ENTRY_INTERVAL, entry->interval);
        if (r < 0)
                goto cancel;

        r = sd_netlink_message_append_u32(message, TCA_TAPRIO_SCHED_ENTRY_GATE_MASK, entry->gatemask);
        if (r < 0)
                goto cancel;

        r = sd_netlink_message_append_u32(message, TCA_TAPRIO_SCHED_ENTRY_CMD, entry->cmd);
        if (r < 0)
                goto cancel;

        return 1;

cancel:
        r = sd_netlink_message_cancel_array(message);
        if (r < 0)
                log_link_error_errno(link, r, "Could not cancel sched entries  message attribute: %m");

        return 0;
}


static int time_aware_prio_shaper_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        struct tc_mqprio_qopt opt = {};
        TimeAwarePrioShaper *taprio;
        int r;
        uint16_t j = 0;
        _cleanup_free_ sentry *e = NULL;

        assert(link);
        assert(qdisc);
        assert(req);

        taprio = TAPRIO(qdisc);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "taprio");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if (taprio->tc_num > 0) {
            opt.num_tc = taprio->tc_num;

            if (taprio->n_prio > 0) {
                    for (unsigned i = 0; i < taprio->n_prio; i++) {
                        opt.prio_tc_map[i] = taprio->prio[i];
                    }
            }

            if (taprio->n_queues > 0) {
                    for (unsigned i = 0; i < taprio->n_queues; i++) {
                        opt.count[i] = taprio->count[i];
                        opt.offset[i] = taprio->offset[i];
                    }
            }

            r = sd_netlink_message_append_data(req, TCA_TAPRIO_ATTR_PRIOMAP, &opt, sizeof(struct tc_mqprio_qopt));
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_PRIOMAP attribute: %m");

        }

        if (taprio->flags >= 0) {
            r = sd_netlink_message_append_u32(req, TCA_TAPRIO_ATTR_FLAGS, taprio->flags);
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_FLAGS attribute: %m");
        }

        if (taprio->cycle_time_extension != CLOCKID_INVALID) {
            r = sd_netlink_message_append_u32(req, TCA_TAPRIO_ATTR_SCHED_CLOCKID, taprio->clockid);
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_SCHED_CLOCKID attribute: %m");
        }

        if (taprio->cycle_time > 0) {
            r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME, taprio->cycle_time);
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME attribute: %m");
        }

        if (taprio->cycle_time_extension > 0) {
                r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION, taprio->cycle_time_extension);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION attribute: %m");
        }

        if (taprio->base_time > 0) {
            r = sd_netlink_message_append_s64(req, TCA_TAPRIO_ATTR_SCHED_BASE_TIME, taprio->base_time);
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_SCHED_BASE_TIME attribute: %m");
        }

        if (taprio->txtime_delay > 0) {
                r = sd_netlink_message_append_s32(req, TCA_TAPRIO_ATTR_TXTIME_DELAY, taprio->txtime_delay);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_TAPRIO_ATTR_TXTIME_DELAY attribute: %m");
        }

        if (taprio->n_entry > 0) {

            r = sd_netlink_message_open_container(req, TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST);
            if (r < 0)
                return log_link_error_errno(link, r, "Could not open TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST container: %m");

            LIST_FOREACH(sched_entry, e, taprio->sched_head) {
                r = taprio_set_sched_entries(link, req, e, ++j);
                if (r < 0)
                    return r;
                if (r == 0)
                    break;
            }

            r = sd_netlink_message_close_container(req);
            if (r < 0)
                    return log_link_error_errno(link, r, "Could not close container TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_tc_taprio_clockid (
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
        TimeAwarePrioShaper *taprio;
        int r;
        const struct static_clockid *c;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        taprio->clockid = CLOCKID_INVALID;

        if (isempty(rvalue)) {

                TAKE_PTR(qdisc);
                return 0;
        }

        /* Drop the CLOCK_ prefix if that is being used. */
        if (strcasestr(rvalue, "CLOCK_") != NULL)
            rvalue += sizeof("CLOCK_") - 1;

        for (c = clockids_sysv; c->name; c++) {
            if (strcasecmp(c->name, rvalue) == 0) {
                taprio->clockid = c->clockid;

                TAKE_PTR(qdisc);

                return 0;
            }
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_tc_taprio_base_time (
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
        TimeAwarePrioShaper *taprio;
        int64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

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
                TAKE_PTR(qdisc);
                return 0;
        }
        if (v > INT64_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                TAKE_PTR(qdisc);
                return 0;
        }

        taprio->base_time = v;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_tc_taprio_cycle_time (
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
        TimeAwarePrioShaper *taprio;
        int64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

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
                TAKE_PTR(qdisc);
                return 0;
        }
        if (v > INT64_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                TAKE_PTR(qdisc);
                return 0;
        }

        /* This is the cycle_time_extension case, if the close_time
         * plus the amount that can be extended would fall after the
         * next schedule base_time, we can extend the current schedule
         * for that amount.
         *
         * FIXME: the IEEE 802.1Q-2018 Specification isn't clear about
         * how precisely the extension should be made. So after
         * conformance testing, this logic may change.
         */
        if (streq(lvalue, "Cycletime"))
            taprio->cycle_time = v;
        else if (streq(lvalue, "CycletimeExtension"))
            taprio->cycle_time_extension = v;
        else
            assert_not_reached();

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_tc_taprio_txtime_delay (
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
        TimeAwarePrioShaper *taprio;
        int32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
            taprio->txtime_delay = 0;
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

        taprio->txtime_delay = v;

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_tc_taprio_num_tc (
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
        TimeAwarePrioShaper *taprio;
        uint8_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
            taprio->tc_num = 0;
            TAKE_PTR(qdisc);
            return 0;
        }

        r = safe_atou8(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        /* Number of traffic classes to use. Up to 16 classes supported */
        if (v > 16) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        taprio->tc_num = v;

        TAKE_PTR(qdisc);

        return 0;
}

static struct sentry *create_entry(TimeAwarePrioShaper *taprio, uint32_t gatemask, uint32_t interval, uint8_t cmd)
{
    sentry *e;

    e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;

    e->taprio = taprio;
    e->gatemask = gatemask;
    e->interval = interval;
    e->cmd = cmd;

    LIST_INIT(sched_entry,e);

    return e;
}

static int str_to_entry_cmd(const char *str)
{
    if (strcmp(str, "S") == 0)
        return TC_TAPRIO_CMD_SET_GATES;
    if (strcmp(str, "H") == 0)
        return TC_TAPRIO_CMD_SET_AND_HOLD;
    if (strcmp(str, "R") == 0)
        return TC_TAPRIO_CMD_SET_AND_RELEASE;
    return -1;
}

int config_parse_tc_taprio_sched_entry(
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
        TimeAwarePrioShaper *taprio;
        Network *network = data;
        int r;
        uint32_t mask, interval;
        uint8_t cmd;
        _cleanup_free_ sentry *e = NULL;
        _cleanup_free_ char *s_cmd = NULL,
                *s_interval = NULL, *s_mask = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {

                TAKE_PTR(qdisc);
                return 0;
        }

        /*
        * sched-entry S 01 300000
        * sched-entry H 02 300000
        * sched-entry R 01 200000
        */
        r = extract_many_words(&lvalue, NULL, EXTRACT_UNQUOTE,
                               &s_cmd, &s_mask, &s_interval, NULL);
        if (r < 0) {
            log_syntax(unit, LOG_ERR, filename, line, r,
                    "Failed to parse '%s=', Syntax error.",
                    lvalue);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }
        if (r < 2) {
            log_syntax(unit, LOG_ERR, filename, line, r,
                    "Failed to parse '%s=', Missing gatemask or interval columns.",
                    lvalue);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }
        if (!isempty(lvalue)) {
            log_syntax(unit, LOG_ERR, filename, line, r,
                    "Failed to parse '%s=', Trailing garbage.",
                    lvalue);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }

        /* Verify command */
        if (strlen(s_cmd) != 1) {
            log_syntax(unit, LOG_ERR, filename, line, r,
                    "Failed to parse '%s=', Unknown cmd modifier '%s'",
                    lvalue,s_cmd);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }

        r = str_to_entry_cmd(s_cmd);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                            "Failed to parse '%s=', Unknown cmd modifier: %s",
                            lvalue, s_cmd);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }

        cmd = r;

        r = safe_atou32(s_mask, &mask);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                            "Failed to parse '%s=', ignoring assignment: %s",
                            lvalue, s_mask);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }

        r = safe_atou32(s_interval, &interval);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                            "Failed to parse '%s=', ignoring assignment: %s",
                            lvalue, s_interval);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }
        if (interval > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified '%s=' is too large, ignoring assignment: %s",
                           lvalue, s_interval);
            TAKE_PTR(qdisc);
            return -EINVAL;
        }

        e = create_entry(taprio, mask, interval, cmd);
        if (!e) {
            fprintf(stderr, "taprio: not enough memory for new schedule entry\n");
            TAKE_PTR(qdisc);
            return -1;
        }

        LIST_APPEND(sched_entry, taprio->sched_head, e);
        taprio->n_entry++;
        TAKE_PTR(qdisc);

        return 0;
}


int config_parse_tc_taprio_priomap(
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
        TimeAwarePrioShaper *taprio;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->n_prio = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint8_t v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        continue;
                }
                if (r == 0)
                        break;

                r = safe_atou8(word, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (taprio->n_prio > TC_PRIO_MAX) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Too many priomap in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }

                taprio->prio[taprio->n_prio++] = v;
        }

        TAKE_PTR(qdisc);

        return 0;
}


int config_parse_tc_taprio_queuemap(
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
        TimeAwarePrioShaper *taprio;
        Network *network = data;
        int r;
        char *tmp, *tok;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {

                TAKE_PTR(qdisc);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint16_t v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        continue;
                }
                if (r == 0)
                        break;

                tok = strtok(word, "@");
                r = safe_atou16(tok, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (taprio->n_queues > TC_QOPT_MAX_QUEUE) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Too many queuemap in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                taprio->count[taprio->n_queues] = v;

                tok = strtok(NULL, "@");
                r = safe_atou16(tok, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                taprio->offset[taprio->n_queues] = v;
                taprio->n_queues++;
        }

        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_tc_taprio_flags (
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
        TimeAwarePrioShaper *taprio;
        int r;
        int k, *p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TAPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        taprio = TAPRIO(qdisc);

        if (isempty(rvalue)) {
                taprio->flags = -1;

                TAKE_PTR(qdisc);
                return 0;
        }

        taprio->flags = 0 ; /* sw fallback */
        if (streq(rvalue, "assisted"))
                taprio->flags = TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        else if (streq(rvalue, "hwoffload"))
                taprio->flags = TCA_TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        else
                assert_not_reached();

        TAKE_PTR(qdisc);

        return 0;
}

static int time_aware_prio_shaper_verify(QDisc *qdisc) {
        TimeAwarePrioShaper *taprio = TAPRIO(qdisc);

        assert(qdisc);

        taprio = TAPRIO(qdisc);

        if (taprio->tc_num > 0 && taprio->tc_num < 16)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: tc_num= is invalid "
                                         "Ignoring [TimeAwarePrioShaperTcNum] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        for (unsigned i = 0; i < taprio->n_prio; i++)
                if (taprio->prio[i] >= TC_QOPT_MAX_QUEUE)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: PriorityMap= element is out of bands. "
                                                 "Ignoring [TimeAwarePrioShaper] section from line %u.",
                                                 qdisc->section->filename, qdisc->section->line);

        if (taprio->flags == TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST && taprio->clockid != CLOCK_TAI )
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Clockid=CLOCK_TAI is mandatory with txassisted mode"
                                         "Ignoring [TimeAwarePrioShaperTxTimeMode] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        return 0;
}

const QDiscVTable taprio_vtable = {
        .object_size = sizeof(TimeAwarePrioShaper),
        .tca_kind = "taprio",
        .fill_message = time_aware_prio_shaper_fill_message,
        .init = time_aware_prio_shaper_init,
        .verify = time_aware_prio_shaper_verify
};

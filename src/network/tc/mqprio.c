/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "extract-word.h"
#include "log.h"
#include "mqprio.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"

static int mqprio_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        MultiQueuePriorityQDisc *mqprio;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(mqprio = MQPRIO(qdisc));

        struct tc_mqprio_qopt opt = {
                .num_tc = mqprio->num_tc,
                .hw = mqprio->hw,
        };

        memcpy(opt.prio_tc_map, mqprio->priority_map, sizeof(opt.prio_tc_map));
        memcpy(opt.count, mqprio->queue_count, sizeof(opt.count));
        memcpy(opt.offset, mqprio->queue_offset, sizeof(opt.offset));

        return sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(opt));
}

static int mqprio_verify(QDisc *qdisc) {
        MultiQueuePriorityQDisc *mqprio;

        assert(qdisc);

        mqprio = MQPRIO(qdisc);

        if (mqprio->num_tc == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NumberOfTrafficClasses= must be specified. "
                                         "Ignoring [MultiQueuePriorityQDisc] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (mqprio->num_tc > TC_QOPT_MAX_QUEUE)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NumberOfTrafficClasses= must be <= %d. "
                                         "Ignoring [MultiQueuePriorityQDisc] section from line %u.",
                                         qdisc->section->filename, TC_QOPT_MAX_QUEUE, qdisc->section->line);

        for (unsigned i = 0; i < mqprio->n_priority_map; i++)
                if (mqprio->priority_map[i] >= mqprio->num_tc)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: PriorityMap= element %u is out of range (must be < NumberOfTrafficClasses=). "
                                                 "Ignoring [MultiQueuePriorityQDisc] section from line %u.",
                                                 qdisc->section->filename, mqprio->priority_map[i], qdisc->section->line);

        return 0;
}

int config_parse_mqprio_num_tc(
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
        MultiQueuePriorityQDisc *mqprio;
        Network *network = ASSERT_PTR(data);
        uint8_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_MQPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        mqprio = MQPRIO(qdisc);

        if (isempty(rvalue)) {
                mqprio->num_tc = 0;

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
        if (v > TC_QOPT_MAX_QUEUE) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s='. The value must be <= %d, ignoring assignment: %s",
                           lvalue, TC_QOPT_MAX_QUEUE, rvalue);
                return 0;
        }

        mqprio->num_tc = v;

        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_mqprio_priority_map(
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
        MultiQueuePriorityQDisc *mqprio;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_MQPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        mqprio = MQPRIO(qdisc);

        if (isempty(rvalue)) {
                memzero(mqprio->priority_map, sizeof(mqprio->priority_map));
                mqprio->n_priority_map = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        mqprio->n_priority_map = 0;

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint8_t v;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        break;
                }
                if (r == 0)
                        break;

                r = safe_atou8(word, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (mqprio->n_priority_map > TC_QOPT_BITMASK) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many elements in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }

                mqprio->priority_map[mqprio->n_priority_map++] = v;
        }

        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_mqprio_queues(
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
        MultiQueuePriorityQDisc *mqprio;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_MQPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        mqprio = MQPRIO(qdisc);

        if (isempty(rvalue)) {
                memzero(mqprio->queue_count, sizeof(mqprio->queue_count));
                memzero(mqprio->queue_offset, sizeof(mqprio->queue_offset));
                mqprio->n_queues = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        mqprio->n_queues = 0;

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint16_t count, offset;
                char *at;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract next value, ignoring: %m");
                        break;
                }
                if (r == 0)
                        break;

                /* Expected format: count@offset (e.g. "2@0 1@2 1@3") */
                at = strchr(word, '@');
                if (!at) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid queue specification '%s', expected format count@offset, ignoring.",
                                   word);
                        continue;
                }

                *at = '\0';

                r = safe_atou16(word, &count);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse queue count in '%s=', ignoring: %s@%s",
                                   lvalue, word, at + 1);
                        continue;
                }

                r = safe_atou16(at + 1, &offset);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse queue offset in '%s=', ignoring: %s@%s",
                                   lvalue, word, at + 1);
                        continue;
                }

                if (mqprio->n_queues >= TC_QOPT_MAX_QUEUE) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many queue specifications in '%s=', ignoring: %s@%s",
                                   lvalue, word, at + 1);
                        continue;
                }

                mqprio->queue_count[mqprio->n_queues] = count;
                mqprio->queue_offset[mqprio->n_queues] = offset;
                mqprio->n_queues++;
        }

        TAKE_PTR(qdisc);
        return 0;
}

int config_parse_mqprio_hw(
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
        MultiQueuePriorityQDisc *mqprio;
        Network *network = ASSERT_PTR(data);
        uint8_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_MQPRIO, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        mqprio = MQPRIO(qdisc);

        if (isempty(rvalue)) {
                mqprio->hw = 0;

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
        if (v > TC_MQPRIO_HW_OFFLOAD_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s='. The value must be <= %d, ignoring assignment: %s",
                           lvalue, TC_MQPRIO_HW_OFFLOAD_MAX, rvalue);
                return 0;
        }

        mqprio->hw = v;

        TAKE_PTR(qdisc);
        return 0;
}

const QDiscVTable mqprio_vtable = {
        .object_size = sizeof(MultiQueuePriorityQDisc),
        .tca_kind = "mqprio",
        .fill_message = mqprio_fill_message,
        .verify = mqprio_verify,
};

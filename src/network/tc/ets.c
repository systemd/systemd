/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "ets.h"
#include "extract-word.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "string-util.h"
#include "tc-util.h"

static int enhanced_transmission_selection_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        EnhancedTransmissionSelection *ets;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(ets = ETS(qdisc));

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "ets");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(req, TCA_ETS_NBANDS, ets->n_bands);
        if (r < 0)
                return r;

        if (ets->n_strict > 0) {
                r = sd_netlink_message_append_u8(req, TCA_ETS_NSTRICT, ets->n_strict);
                if (r < 0)
                        return r;
        }

        if (ets->n_quanta > 0) {
                r = sd_netlink_message_open_container(req, TCA_ETS_QUANTA);
                if (r < 0)
                        return r;

                for (unsigned i = 0; i < ets->n_quanta; i++) {
                        r = sd_netlink_message_append_u32(req, TCA_ETS_QUANTA_BAND, ets->quanta[i]);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        if (ets->n_prio > 0) {
                r = sd_netlink_message_open_container(req, TCA_ETS_PRIOMAP);
                if (r < 0)
                        return r;

                for (unsigned i = 0; i < ets->n_prio; i++) {
                        r = sd_netlink_message_append_u8(req, TCA_ETS_PRIOMAP_BAND, ets->prio[i]);
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

int config_parse_ets_u8(
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
        EnhancedTransmissionSelection *ets;
        Network *network = ASSERT_PTR(data);
        uint8_t v, *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_ETS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ets = ETS(qdisc);
        if (streq(lvalue, "Bands"))
                p = &ets->n_bands;
        else if (streq(lvalue, "StrictBands"))
                p = &ets->n_strict;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *p = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou8(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (v > TCQ_ETS_MAX_BANDS) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s='. The value must be <= %d, ignoring assignment: %s",
                           lvalue, TCQ_ETS_MAX_BANDS, rvalue);
                return 0;
        }

        *p = v;
        qdisc = NULL;

        return 0;
}

int config_parse_ets_quanta(
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
        EnhancedTransmissionSelection *ets;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_ETS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ets = ETS(qdisc);

        if (isempty(rvalue)) {
                memzero(ets->quanta, sizeof(uint32_t) * TCQ_ETS_MAX_BANDS);
                ets->n_quanta = 0;

                qdisc = NULL;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint64_t v;

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

                r = parse_size(word, 1024, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (v == 0 || v > UINT32_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }
                if (ets->n_quanta >= TCQ_ETS_MAX_BANDS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many quanta in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }

                ets->quanta[ets->n_quanta++] = v;
        }

        qdisc = NULL;

        return 0;
}

int config_parse_ets_prio(
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
        EnhancedTransmissionSelection *ets;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_ETS, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        ets = ETS(qdisc);

        if (isempty(rvalue)) {
                memzero(ets->prio, sizeof(uint8_t) * (TC_PRIO_MAX + 1));
                ets->n_prio = 0;

                qdisc = NULL;
                return 0;
        }

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
                if (ets->n_prio > TC_PRIO_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many priomap in '%s=', ignoring assignment: %s",
                                   lvalue, word);
                        continue;
                }

                ets->prio[ets->n_prio++] = v;
        }

        qdisc = NULL;

        return 0;
}

static int enhanced_transmission_selection_verify(QDisc *qdisc) {
        EnhancedTransmissionSelection *ets;

        assert(qdisc);

        ets = ETS(qdisc);

        if (ets->n_bands == 0)
                ets->n_bands = ets->n_strict + ets->n_quanta;

        if (ets->n_bands == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: At least one of Band=, Strict=, or Quanta= must be specified. "
                                         "Ignoring [EnhancedTransmissionSelection] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        if (ets->n_bands < ets->n_strict + ets->n_quanta)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Not enough total bands to cover all the strict bands and quanta. "
                                         "Ignoring [EnhancedTransmissionSelection] section from line %u.",
                                         qdisc->section->filename, qdisc->section->line);

        for (unsigned i = 0; i < ets->n_prio; i++)
                if (ets->prio[i] >= ets->n_bands)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: PriorityMap= element is out of bands. "
                                                 "Ignoring [EnhancedTransmissionSelection] section from line %u.",
                                                 qdisc->section->filename, qdisc->section->line);

        return 0;
}

const QDiscVTable ets_vtable = {
        .object_size = sizeof(EnhancedTransmissionSelection),
        .tca_kind = "ets",
        .fill_message = enhanced_transmission_selection_fill_message,
        .verify = enhanced_transmission_selection_verify,
};

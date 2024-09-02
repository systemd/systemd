/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "parse-util.h"
#include "qdisc.h"
#include "htb.h"
#include "string-util.h"
#include "tc-util.h"

#define HTB_DEFAULT_RATE_TO_QUANTUM  10
#define HTB_DEFAULT_MTU              1600  /* Ethernet packet length */

static int hierarchy_token_bucket_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        HierarchyTokenBucket *htb;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        assert_se(htb = HTB(qdisc));

        struct tc_htb_glob opt = {
                .version = 3,
                .rate2quantum = htb->rate_to_quantum,
                .defcls = htb->default_class,
        };

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "htb");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_HTB_INIT, &opt, sizeof(opt));
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;
        return 0;
}

int config_parse_hierarchy_token_bucket_default_class(
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
        HierarchyTokenBucket *htb;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_HTB, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        htb = HTB(qdisc);

        if (isempty(rvalue)) {
                htb->default_class = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32_full(rvalue, 16, &htb->default_class);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

int config_parse_hierarchy_token_bucket_u32(
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
        HierarchyTokenBucket *htb;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = qdisc_new_static(QDISC_KIND_HTB, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        htb = HTB(qdisc);

        if (isempty(rvalue)) {
                htb->rate_to_quantum = HTB_DEFAULT_RATE_TO_QUANTUM;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou32(rvalue, &htb->rate_to_quantum);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(qdisc);

        return 0;
}

static int hierarchy_token_bucket_init(QDisc *qdisc) {
        HierarchyTokenBucket *htb;

        assert(qdisc);

        htb = HTB(qdisc);

        htb->rate_to_quantum = HTB_DEFAULT_RATE_TO_QUANTUM;

        return 0;
}

const QDiscVTable htb_vtable = {
        .object_size = sizeof(HierarchyTokenBucket),
        .tca_kind = "htb",
        .fill_message = hierarchy_token_bucket_fill_message,
        .init = hierarchy_token_bucket_init,
};

static int hierarchy_token_bucket_class_fill_message(Link *link, TClass *tclass, sd_netlink_message *req) {
        HierarchyTokenBucketClass *htb;
        uint32_t rtab[256], ctab[256];
        int r;

        assert(link);
        assert(tclass);
        assert(req);

        assert_se(htb = TCLASS_TO_HTB(tclass));

        struct tc_htb_opt opt = {
                .prio = htb->priority,
                .quantum = htb->quantum,
                .rate.rate = (htb->rate >= (1ULL << 32)) ? ~0U : htb->rate,
                .ceil.rate = (htb->ceil_rate >= (1ULL << 32)) ? ~0U : htb->ceil_rate,
                .rate.overhead = htb->overhead,
                .ceil.overhead = htb->overhead,
        };

        r = tc_transmit_time(htb->rate, htb->buffer, &opt.buffer);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate buffer size: %m");

        r = tc_transmit_time(htb->ceil_rate, htb->ceil_buffer, &opt.cbuffer);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate ceil buffer size: %m");

        r = tc_fill_ratespec_and_table(&opt.rate, rtab, htb->mtu);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate rate table: %m");

        r = tc_fill_ratespec_and_table(&opt.ceil, ctab, htb->mtu);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to calculate ceil rate table: %m");

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "htb");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_HTB_PARMS, &opt, sizeof(opt));
        if (r < 0)
                return r;

        if (htb->rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_u64(req, TCA_HTB_RATE64, htb->rate);
                if (r < 0)
                        return r;
        }

        if (htb->ceil_rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_u64(req, TCA_HTB_CEIL64, htb->ceil_rate);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_data(req, TCA_HTB_RTAB, rtab, sizeof(rtab));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(req, TCA_HTB_CTAB, ctab, sizeof(ctab));
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_hierarchy_token_bucket_class_u32(
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

        _cleanup_(tclass_unref_or_set_invalidp) TClass *tclass = NULL;
        HierarchyTokenBucketClass *htb;
        Network *network = ASSERT_PTR(data);
        uint32_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_HTB, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        htb = TCLASS_TO_HTB(tclass);

        if (isempty(rvalue)) {
                htb->priority = 0;
                tclass = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        htb->priority = v;
        tclass = NULL;

        return 0;
}

int config_parse_hierarchy_token_bucket_class_size(
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

        _cleanup_(tclass_unref_or_set_invalidp) TClass *tclass = NULL;
        HierarchyTokenBucketClass *htb;
        Network *network = ASSERT_PTR(data);
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_HTB, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        htb = TCLASS_TO_HTB(tclass);

        if (isempty(rvalue)) {
                if (streq(lvalue, "QuantumBytes"))
                        htb->quantum = 0;
                else if (streq(lvalue, "MTUBytes"))
                        htb->mtu = HTB_DEFAULT_MTU;
                else if (streq(lvalue, "OverheadBytes"))
                        htb->overhead = 0;
                else if (streq(lvalue, "BufferBytes"))
                        htb->buffer = 0;
                else if (streq(lvalue, "CeilBufferBytes"))
                        htb->ceil_buffer = 0;
                else
                        assert_not_reached();

                tclass = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1024, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if ((streq(lvalue, "OverheadBytes") && v > UINT16_MAX) || v > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "QuantumBytes"))
                htb->quantum = v;
        else if (streq(lvalue, "OverheadBytes"))
                htb->overhead = v;
        else if (streq(lvalue, "MTUBytes"))
                htb->mtu = v;
        else if (streq(lvalue, "BufferBytes"))
                htb->buffer = v;
        else if (streq(lvalue, "CeilBufferBytes"))
                htb->ceil_buffer = v;
        else
                assert_not_reached();

        tclass = NULL;

        return 0;
}

int config_parse_hierarchy_token_bucket_class_rate(
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

        _cleanup_(tclass_unref_or_set_invalidp) TClass *tclass = NULL;
        HierarchyTokenBucketClass *htb;
        Network *network = ASSERT_PTR(data);
        uint64_t *v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(TCLASS_KIND_HTB, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        htb = TCLASS_TO_HTB(tclass);
        if (streq(lvalue, "Rate"))
                v = &htb->rate;
        else if (streq(lvalue, "CeilRate"))
                v = &htb->ceil_rate;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *v = 0;

                tclass = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1000, v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *v /= 8;
        tclass = NULL;

        return 0;
}

static int hierarchy_token_bucket_class_init(TClass *tclass) {
        HierarchyTokenBucketClass *htb;

        assert(tclass);

        htb = TCLASS_TO_HTB(tclass);

        htb->mtu = HTB_DEFAULT_MTU;

        return 0;
}

static int hierarchy_token_bucket_class_verify(TClass *tclass) {
        HierarchyTokenBucketClass *htb;
        uint32_t hz;
        int r;

        assert(tclass);

        htb = TCLASS_TO_HTB(tclass);

        if (htb->rate == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Rate= is mandatory. "
                                         "Ignoring [HierarchyTokenBucketClass] section from line %u.",
                                         tclass->section->filename, tclass->section->line);

        /* if CeilRate= setting is missing, use the same as Rate= */
        if (htb->ceil_rate == 0)
                htb->ceil_rate = htb->rate;

        r = tc_init(NULL, &hz);
        if (r < 0)
                return log_error_errno(r, "Failed to read /proc/net/psched: %m");

        if (htb->buffer == 0)
                htb->buffer = htb->rate / hz + htb->mtu;
        if (htb->ceil_buffer == 0)
                htb->ceil_buffer = htb->ceil_rate / hz + htb->mtu;

        return 0;
}

const TClassVTable htb_tclass_vtable = {
        .object_size = sizeof(HierarchyTokenBucketClass),
        .tca_kind = "htb",
        .fill_message = hierarchy_token_bucket_class_fill_message,
        .init = hierarchy_token_bucket_class_init,
        .verify = hierarchy_token_bucket_class_verify,
};

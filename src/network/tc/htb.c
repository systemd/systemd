/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "htb.h"
#include "string-util.h"
#include "tc-util.h"

static int hierarchy_token_bucket_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        HierarchyTokenBucket *htb;
        struct tc_htb_glob opt = {
                .rate2quantum = 10,
                .version = 3,
        };
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        htb = HTB(qdisc);

        opt.defcls = htb->default_class;

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "htb");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_append_data(req, TCA_HTB_INIT, &opt, sizeof(opt));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_HTB_INIT attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");
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

        _cleanup_(qdisc_free_or_set_invalidp) QDisc *qdisc = NULL;
        HierarchyTokenBucket *htb;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_HTB, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "More than one kind of queueing discipline, ignoring assignment: %m");

        htb = HTB(qdisc);

        if (isempty(rvalue)) {
                htb->default_class = 0;

                qdisc = NULL;
                return 0;
        }

        r = safe_atou32_full(rvalue, 16, &htb->default_class);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        qdisc = NULL;

        return 0;
}

const QDiscVTable htb_vtable = {
        .object_size = sizeof(HierarchyTokenBucket),
        .tca_kind = "htb",
        .fill_message = hierarchy_token_bucket_fill_message,
};

static int hierarchy_token_bucket_class_fill_message(Link *link, TClass *tclass, sd_netlink_message *req) {
        HierarchyTokenBucketClass *htb;
        struct tc_htb_opt opt = {};
        uint32_t rtab[256], ctab[256], mtu = 1600; /* Ethernet packet length */
        int r;

        assert(link);
        assert(tclass);
        assert(req);

        htb = TCLASS_TO_HTB(tclass);

        if (htb->ceil_rate == 0)
                htb->ceil_rate = htb->rate;

        opt.prio = htb->priority;
        opt.rate.rate = (htb->rate >= (1ULL << 32)) ? ~0U : htb->rate;
        opt.ceil.rate = (htb->ceil_rate >= (1ULL << 32)) ? ~0U : htb->ceil_rate;
        r = tc_transmit_time(htb->rate, mtu, &opt.buffer);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to calculate buffer size: %m");

        r = tc_transmit_time(htb->ceil_rate, mtu, &opt.cbuffer);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to calculate ceil buffer size: %m");

        r = tc_fill_ratespec_and_table(&opt.rate, rtab, mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to calculate rate table: %m");

        r = tc_fill_ratespec_and_table(&opt.ceil, ctab, mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to calculate ceil rate table: %m");

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "htb");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_append_data(req, TCA_HTB_PARMS, &opt, sizeof(opt));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_HTB_PARMS attribute: %m");

        if (htb->rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_u64(req, TCA_HTB_RATE64, htb->rate);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_HTB_RATE64 attribute: %m");
        }

        if (htb->ceil_rate >= (1ULL << 32)) {
                r = sd_netlink_message_append_u64(req, TCA_HTB_CEIL64, htb->ceil_rate);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append TCA_HTB_CEIL64 attribute: %m");
        }

        r = sd_netlink_message_append_data(req, TCA_HTB_RTAB, rtab, sizeof(rtab));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_HTB_RTAB attribute: %m");

        r = sd_netlink_message_append_data(req, TCA_HTB_CTAB, ctab, sizeof(ctab));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_HTB_CTAB attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        HierarchyTokenBucketClass *htb;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tclass_new_static(TCLASS_KIND_HTB, network, filename, section_line, &tclass);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to create traffic control class, ignoring assignment: %m");

        htb = TCLASS_TO_HTB(tclass);

        if (isempty(rvalue)) {
                htb->priority = 0;

                tclass = NULL;
                return 0;
        }

        r = safe_atou32(rvalue, &htb->priority);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        tclass = NULL;

        return 0;
}

int config_parse_hierarchy_token_bucket_rate(
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        HierarchyTokenBucketClass *htb;
        Network *network = data;
        uint64_t *v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tclass_new_static(TCLASS_KIND_HTB, network, filename, section_line, &tclass);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to create traffic control class, ignoring assignment: %m");

        htb = TCLASS_TO_HTB(tclass);
        if (streq(lvalue, "Rate"))
                v = &htb->rate;
        else if (streq(lvalue, "CeilRate"))
                v = &htb->ceil_rate;
        else
                assert_not_reached("Invalid lvalue");

        if (isempty(rvalue)) {
                *v = 0;

                tclass = NULL;
                return 0;
        }

        r = parse_size(rvalue, 1000, v);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *v /= 8;
        tclass = NULL;

        return 0;
}

const TClassVTable htb_tclass_vtable = {
        .object_size = sizeof(HierarchyTokenBucketClass),
        .tca_kind = "htb",
        .fill_message = hierarchy_token_bucket_class_fill_message,
};

/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "qdisc.h"
#include "htb.h"
#include "string-util.h"

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

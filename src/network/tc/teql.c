/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "teql.h"

static int trivial_link_equalizer_fill_tca_kind(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        char kind[STRLEN("teql") + DECIMAL_STR_MAX(unsigned)];
        TrivialLinkEqualizer *teql;
        int r;

        assert(link);
        assert(qdisc);
        assert(req);

        teql = TEQL(qdisc);

        xsprintf(kind, "teql%u", teql->id);
        r = sd_netlink_message_append_string(req, TCA_KIND, kind);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append TCA_KIND attribute: %m");

        return 0;
}

const QDiscVTable teql_vtable = {
        .object_size = sizeof(TrivialLinkEqualizer),
        .fill_tca_kind = trivial_link_equalizer_fill_tca_kind,
};

int config_parse_trivial_link_equalizer_id(
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
        TrivialLinkEqualizer *teql;
        Network *network = data;
        unsigned id;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = qdisc_new_static(QDISC_KIND_TEQL, network, filename, section_line, &qdisc);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "More than one kind of queueing discipline, ignoring assignment: %m");
                return 0;
        }

        teql = TEQL(qdisc);

        if (isempty(rvalue)) {
                teql->id = 0;

                TAKE_PTR(qdisc);
                return 0;
        }

        r = safe_atou(rvalue, &id);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s=', ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (id > INT_MAX)
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "'%s=' is too large, ignoring assignment: %s",
                           lvalue, rvalue);

        teql->id = id;

        TAKE_PTR(qdisc);
        return 0;
}

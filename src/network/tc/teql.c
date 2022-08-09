/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "networkd-link.h"
#include "parse-util.h"
#include "string-util.h"
#include "teql.h"

static int trivial_link_equalizer_verify(QDisc *qdisc) {
        _cleanup_free_ char *tca_kind = NULL;
        TrivialLinkEqualizer *teql;

        teql = TEQL(ASSERT_PTR(qdisc));

        if (asprintf(&tca_kind, "teql%u", teql->id) < 0)
                return log_oom();

        return free_and_replace(qdisc->tca_kind, tca_kind);
}

static int trivial_link_equalizer_is_ready(QDisc *qdisc, Link *link) {
        Link *teql;

        assert(qdisc);
        assert(qdisc->tca_kind);
        assert(link);
        assert(link->manager);

        if (link_get_by_name(link->manager, qdisc->tca_kind, &teql) < 0)
                return false;

        return link_is_ready_to_configure(teql, /* allow_unmanaged = */ true);
}

const QDiscVTable teql_vtable = {
        .object_size = sizeof(TrivialLinkEqualizer),
        .verify = trivial_link_equalizer_verify,
        .is_ready = trivial_link_equalizer_is_ready,
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
        Network *network = ASSERT_PTR(data);
        unsigned id;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

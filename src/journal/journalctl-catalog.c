/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "catalog.h"
#include "journalctl.h"
#include "journalctl-catalog.h"
#include "path-util.h"

int action_update_catalog(void) {
        _cleanup_free_ char *database = NULL;
        const char *e;
        int r;

        assert(arg_action == ACTION_UPDATE_CATALOG);

        database = path_join(arg_root, secure_getenv("SYSTEMD_CATALOG") ?: CATALOG_DATABASE);
        if (!database)
                return log_oom();

        e = secure_getenv("SYSTEMD_CATALOG_SOURCES");
        r = catalog_update(database,
                           arg_root,
                           e ? STRV_MAKE_CONST(e) : NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to update catalog: %m");

        return 0;
}

int action_list_catalog(char **items) {
        _cleanup_free_ char *database = NULL;
        int r;

        assert(IN_SET(arg_action, ACTION_LIST_CATALOG, ACTION_DUMP_CATALOG));

        database = path_join(arg_root, secure_getenv("SYSTEMD_CATALOG") ?: CATALOG_DATABASE);
        if (!database)
                return log_oom();

        bool oneline = arg_action == ACTION_LIST_CATALOG;

        pager_open(arg_pager_flags);

        if (items)
                r = catalog_list_items(/* f = */ NULL, database, oneline, items);
        else
                r = catalog_list(/* f = */ NULL, database, oneline);
        if (r < 0)
                return log_error_errno(r, "Failed to list catalog: %m");

        return 0;
}

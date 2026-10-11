/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chase.h"
#include "coredumpctl-util.h"
#include "log.h"
#include "string-util.h"

int resolve_filename(const char *root, char **p) {
        char *resolved = NULL;
        int r;

        assert(p);

        if (!*p)
                return 0;

        r = chase(*p, root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve \"%s%s\": %m", strempty(root), *p);

        free_and_replace(*p, resolved);

        /* chase() with flag CHASE_NONEXISTENT will return 0 if the file doesn't exist and 1 if it does.
         * Return that to the caller. */
        return r;
}

int retrieve(const void *data, size_t len, const char *name, char **var) {
        size_t ident;
        char *v;

        assert(var);

        ident = strlen(name) + 1; /* name + "=" */

        if (len < ident)
                return 0;

        if (memcmp(data, name, ident - 1) != 0)
                return 0;

        if (((const char*) data)[ident - 1] != '=')
                return 0;

        v = strndup((const char*) data + ident, len - ident);
        if (!v)
                return log_oom();

        free_and_replace(*var, v);
        return 1;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "string-util.h"
#include "umask-util.h"

int current_umask(mode_t *ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(ret);

        r = get_proc_field("/proc/self/status", "Umask", WHITESPACE, &p);
        if (r < 0)
                return r;

        return parse_mode(p, ret);
}

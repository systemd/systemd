/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

enum {
        PATH_CHECK_FATAL    = 1 << 0,  /* If not set, then error message is appended with 'ignoring'. */
        PATH_CHECK_ABSOLUTE = 1 << 1,
        PATH_CHECK_RELATIVE = 1 << 2,
};

int path_simplify_and_warn(
                char *path,
                unsigned flag,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue);

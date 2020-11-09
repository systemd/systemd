/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "alloc-util.h"
#include "apparmor-util.h"
#include "fileio.h"
#include "parse-util.h"

bool mac_apparmor_use(void) {
        static int cached_use = -1;

        if (cached_use < 0) {
                _cleanup_free_ char *p = NULL;

                cached_use =
                        read_one_line_file("/sys/module/apparmor/parameters/enabled", &p) >= 0 &&
                        parse_boolean(p) > 0;
        }

        return cached_use;
}

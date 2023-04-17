/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "lsm-util.h"
#include "string-util.h"

int lsm_supported(const char *name) {
        _cleanup_free_ char *lsm_list = NULL;
        int r;

        assert(name);

        r = read_one_line_file("/sys/kernel/security/lsm", &lsm_list);
        if (r == -ENOENT) /* LSM support not available at all? */
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to read /sys/kernel/security/lsm: %m");

        for (const char *p = lsm_list;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", 0);
                if (r == 0)
                        return false;
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /sys/kernel/security/lsm: %m");

                if (streq(word, name))
                        return true;
        }
}

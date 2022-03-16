/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kbd-util.h"
#include "log.h"
#include "strv.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **maps = NULL;
        int r;

        log_show_color(true);
        test_setup_logging(LOG_DEBUG);

        r = get_keymaps(&maps);
        if (r < 0) {
                log_error_errno(r, "Failed to acquire keymaps: %m");
                return 0;
        }

        STRV_FOREACH(m, maps) {
                log_info("Found keymap: %s", *m);
                assert_se(keymap_exists(*m) > 0);
        }

        return 0;
}

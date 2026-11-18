/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kbd-util.h"
#include "log.h"
#include "strv.h"
#include "tests.h"

TEST(keymaps) {
        _cleanup_strv_free_ char **maps = NULL;
        int r;

        r = get_keymaps(&maps);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to acquire keymaps");

        STRV_FOREACH(m, maps) {
                log_info("Found keymap: %s", *m);
                ASSERT_OK_POSITIVE(keymap_exists(*m));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);

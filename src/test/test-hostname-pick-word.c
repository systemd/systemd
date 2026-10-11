/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "hostname-setup.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "tests.h"

static int run(int argc, char **argv) {
        int r;

        log_setup();

        unsigned c = 100, pos = 1;

        if (argc > 1) {
                r = safe_atou_bounded(argv[1], /* min= */ 1, /* max= */ UINT_MAX, &pos);
                if (r < 0)
                        return log_error_errno(r, "Cannot parse uint '%s': %m", argv[1]);
        }

        if (argc > 2) {
                r = safe_atou_bounded(argv[2], /* min= */ 1, /* max= */ UINT_MAX, &c);
                if (r < 0)
                        return log_error_errno(r, "Cannot parse uint '%s': %m", argv[2]);
        }

        sd_id128_t mid = SD_ID128_ARRAY(aa,bb,cc,ee,33,21,42,31,89,ba,a4,91,33,22,11,00);

        while (c-- > 0) {
                _cleanup_free_ char *w = NULL;

                ASSERT_OK(hostname_pick_word(mid, pos, &w));
                ASSERT_PTR(w);

                printf("%s\n", w);

                mid.qwords[0] += 3;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

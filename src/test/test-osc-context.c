/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "osc-context.h"
#include "tests.h"

#include "escape.h"

TEST(osc) {
        _cleanup_free_ char *seq = NULL;

        log_info("boot");
        assert_se(osc_context_open_boot(&seq) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        assert_se(osc_context_close(SD_ID128_ALLF, &seq) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("container");
        sd_id128_t id;
        assert_se(osc_context_open_container("foobar", &seq, &id) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        assert_se(osc_context_close(id, &seq) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("vm");
        assert_se(osc_context_open_vm("foobar", &seq, &id) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        assert_se(osc_context_close(id, &seq) >= 0);
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        printf("%s\n", xescape("Schöpfgefäß", NULL));
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

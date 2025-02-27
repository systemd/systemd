/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "osc-context.h"
#include "tests.h"
#include "user-util.h"

TEST(osc) {
        _cleanup_free_ char *seq = NULL;

        log_info("boot");
        ASSERT_OK(osc_context_open_boot(&seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(SD_ID128_ALLF, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("container");
        sd_id128_t id;
        ASSERT_OK(osc_context_open_container("foobar", &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("vm");
        ASSERT_OK(osc_context_open_vm("foobar", &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → root");
        ASSERT_OK(osc_context_open_chpriv("root", &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → userxyz");
        ASSERT_OK(osc_context_open_chpriv("userxyz", &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → self");
        _cleanup_free_ char *self = ASSERT_PTR(getusername_malloc());
        ASSERT_OK(osc_context_open_chpriv(self, &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("session");
        ASSERT_OK(osc_context_open_session("foobaruser", "session1", &seq, &id));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("service");
        sd_id128_t invocation_id;
        ASSERT_OK(sd_id128_randomize(&invocation_id));
        ASSERT_OK(osc_context_open_service("getty@tty1.service", invocation_id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_id_from_invocation_id(invocation_id, &id));
        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f = */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);
}

DEFINE_TEST_MAIN(LOG_INFO);

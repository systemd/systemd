/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "hexdecoct.h"
#include "osc-context.h"
#include "tests.h"
#include "user-util.h"

TEST(osc) {
        _cleanup_free_ char *seq = NULL;

        log_info("boot");
        ASSERT_OK(osc_context_open_boot(&seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(SD_ID128_ALLF, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("container");
        sd_id128_t id;
        ASSERT_OK(osc_context_open_container("foobar", &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("vm");
        ASSERT_OK(osc_context_open_vm("foobar", &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → root");
        ASSERT_OK(osc_context_open_chpriv("root", &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → userxyz");
        ASSERT_OK(osc_context_open_chpriv("userxyz", &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("chpriv → self");
        _cleanup_free_ char *self = ASSERT_PTR(getusername_malloc());
        ASSERT_OK(osc_context_open_chpriv(self, &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("session");
        ASSERT_OK(osc_context_open_session("foobaruser", "session1", &seq, &id));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        log_info("service");
        sd_id128_t invocation_id;
        ASSERT_OK(sd_id128_randomize(&invocation_id));
        ASSERT_OK(osc_context_open_service("getty@tty1.service", invocation_id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);

        ASSERT_OK(osc_context_id_from_invocation_id(invocation_id, &id));
        ASSERT_OK(osc_context_close(id, &seq));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);
}

TEST(osc_close_full) {
        _cleanup_free_ char *seq = NULL;
        sd_id128_t id;

        ASSERT_OK(sd_id128_randomize(&id));

        /* No exit information: same as the plain close */
        ASSERT_OK(osc_context_close_full(id, /* code= */ 0, /* status= */ 0, &seq));
        ASSERT_NOT_NULL(strstr(seq, "3008;end="));
        ASSERT_NULL(strstr(seq, ";exit="));
        seq = mfree(seq);

        ASSERT_OK(osc_context_close_full(id, CLD_EXITED, 0, &seq));
        ASSERT_NOT_NULL(strstr(seq, ";exit=success;status=0\x1b\\"));
        seq = mfree(seq);

        ASSERT_OK(osc_context_close_full(id, CLD_EXITED, 3, &seq));
        ASSERT_NOT_NULL(strstr(seq, ";exit=failure;status=3\x1b\\"));
        seq = mfree(seq);

        ASSERT_OK(osc_context_close_full(id, CLD_KILLED, SIGINT, &seq));
        ASSERT_NOT_NULL(strstr(seq, ";exit=interrupt;signal=SIGINT\x1b\\"));
        seq = mfree(seq);

        ASSERT_OK(osc_context_close_full(id, CLD_KILLED, SIGTERM, &seq));
        ASSERT_NOT_NULL(strstr(seq, ";exit=interrupt;signal=SIGTERM\x1b\\"));
        seq = mfree(seq);

        ASSERT_OK(osc_context_close_full(id, CLD_DUMPED, SIGSEGV, &seq));
        ASSERT_NOT_NULL(strstr(seq, ";exit=crash;signal=SIGSEGV\x1b\\"));
        hexdump(/* f= */ NULL, seq, SIZE_MAX);
        seq = mfree(seq);
}

DEFINE_TEST_MAIN(LOG_INFO);

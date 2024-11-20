/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "audit-util.h"
#include "tests.h"
#include "virt.h"

TEST(audit_loginuid_from_pid) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL, pid1 = PIDREF_NULL;
        int r;

        // Debian appears to have a really broken build/test system where they run a container inside of an
        // audit session so that the audit leaks in, and then they run our tests inside of a chroot() and
        // expect things to work. Let's simply skip this test if we detect such a weird setup. Ideally Debian
        // would address this in their build/test system (for example, set $container env var for their
        // container PID 1), but there seems to be no interest in getting the build/test system fixed, hence
        // let's just tape over this, given that the test result of such a weird system are pretty useless
        // anyway.
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Hack: running in a chroot(), skipping audit loginuid test, because we might not detect vitualization properly.");

        assert_se(pidref_set_self(&self) >= 0);
        assert_se(pidref_set_pid(&pid1, 1) >= 0);

        uid_t uid;
        r = audit_loginuid_from_pid(&self, &uid);
        assert_se(r >= 0 || r == -ENODATA);
        if (r >= 0)
                log_info("self audit login uid: " UID_FMT, uid);

        assert_se(audit_loginuid_from_pid(&pid1, &uid) == -ENODATA);

        uint32_t sessionid;
        r = audit_session_from_pid(&self, &sessionid);
        assert_se(r >= 0 || r == -ENODATA);
        if (r >= 0)
                log_info("self audit session id: %" PRIu32, sessionid);

        assert_se(audit_session_from_pid(&pid1, &sessionid) == -ENODATA);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

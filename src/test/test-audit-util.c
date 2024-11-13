/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "audit-util.h"
#include "tests.h"

TEST(audit_loginuid_from_pid) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL, pid1 = PIDREF_NULL;
        int r;

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

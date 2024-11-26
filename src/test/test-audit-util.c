/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "audit-util.h"
#include "tests.h"

TEST(audit_loginuid_from_pid) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL, pid1 = PIDREF_NULL;
        int r;

        ASSERT_OK(pidref_set_self(&self));
        ASSERT_OK(pidref_set_pid(&pid1, 1));

        uid_t uid;
        r = audit_loginuid_from_pid(&self, &uid);
        if (r != -ENODATA)
                ASSERT_OK(r);
        if (r >= 0)
                log_info("self audit login uid: " UID_FMT, uid);

        ASSERT_ERROR(audit_loginuid_from_pid(&pid1, &uid), ENODATA);

        uint32_t sessionid;
        r = audit_session_from_pid(&self, &sessionid);
        if (r != -ENODATA)
                ASSERT_OK(r);
        if (r >= 0)
                log_info("self audit session id: %" PRIu32, sessionid);

        ASSERT_ERROR(audit_session_from_pid(&pid1, &sessionid), ENODATA);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

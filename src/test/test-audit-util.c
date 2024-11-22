/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "audit-util.h"
#include "tests.h"
#include "virt.h"

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

        /* pid1 at build time does not necessarily have to be systemd, it could be anything and be in any
         * state outside of our control, as any custom-built, unknown and weird container manager stub pid1
         * might be in use. The audit helper should catch this on container-other and return -ENODATA
         * already, but we cannot have any coverage of this case, so a risk of regression is always present.
         * To be on the safe side, assert only on known container solutions (or VMs/bare-metal), and print a
         * loud warning and complain, asking to fix the audit setup of the container manager, if it is an
         * unknown one. As a specific example, on the Debian buildd network the stub pid1 is not systemd,
         * and has a sessionid. */
        r = audit_loginuid_from_pid(&pid1, &uid);
        if (detect_container() != VIRTUALIZATION_CONTAINER_OTHER)
                ASSERT_ERROR(r, ENODATA);
        else if (r != -ENODATA)
                log_error("audit_loginuid_from_pid on pid1 unexpectedly returned %d instead of -ENODATA. "
                          "This likely suggests that the container manager under which this test is run "
                          "has incorrectly set up the audit subsystem, as the stub pid1 is not supposed to "
                          "have an audit login id, and it should be fixed.", r);

        uint32_t sessionid;
        r = audit_session_from_pid(&self, &sessionid);
        if (r != -ENODATA)
                ASSERT_OK(r);
        if (r >= 0)
                log_info("self audit session id: %" PRIu32, sessionid);

        /* As above. */
        r = audit_session_from_pid(&pid1, &sessionid);
        if (detect_container() != VIRTUALIZATION_CONTAINER_OTHER)
                ASSERT_ERROR(r, ENODATA);
        else if (r != -ENODATA)
                log_error("audit_session_from_pid on pid1 unexpectedly returned %d instead of -ENODATA. "
                          "This likely suggests that the container manager under which this test is run "
                          "has incorrectly set up the audit subsystem, as the stub pid1 is not supposed to "
                          "have an audit session id, and it should be fixed.", r);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

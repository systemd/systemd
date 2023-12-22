/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "sd-login.h"

#include "alloc-util.h"
#include "errno-list.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "missing_syscall.h"
#include "mountpoint-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "user-util.h"

static char* format_uids(char **buf, uid_t* uids, int count) {
        int pos = 0, inc;
        size_t size = (DECIMAL_STR_MAX(uid_t) + 1) * count + 1;

        assert_se(*buf = malloc(size));

        for (int k = 0; k < count; k++) {
                sprintf(*buf + pos, "%s"UID_FMT"%n", k > 0 ? " " : "", uids[k], &inc);
                pos += inc;
        }

        assert_se(pos < (ssize_t)size);
        (*buf)[pos] = '\0';

        return *buf;
}

static const char *e(int r) {
        return r == 0 ? "OK" : errno_to_name(r);
}

TEST(login) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_free_ char *pp = NULL, *qq = NULL,
                *display_session = NULL, *cgroup = NULL,
                *display = NULL, *remote_user = NULL, *remote_host = NULL,
                *type = NULL, *class = NULL, *state = NULL, *state2 = NULL,
                *seat = NULL, *session = NULL,
                *unit = NULL, *user_unit = NULL, *slice = NULL;
        _cleanup_close_ int pidfd = -EBADF;
        int r;
        uid_t u, u2 = UID_INVALID;
        char *t, **seats = NULL, **sessions = NULL;

        r = sd_pid_get_unit(0, &unit);
        log_info("sd_pid_get_unit(0, …) → %s / \"%s\"", e(r), strnull(unit));
        assert_se(IN_SET(r, 0, -ENODATA));

        r = sd_pid_get_user_unit(0, &user_unit);
        log_info("sd_pid_get_user_unit(0, …) → %s / \"%s\"", e(r), strnull(user_unit));
        assert_se(IN_SET(r, 0, -ENODATA));

        r = sd_pid_get_slice(0, &slice);
        log_info("sd_pid_get_slice(0, …) → %s / \"%s\"", e(r), strnull(slice));
        assert_se(IN_SET(r, 0, -ENODATA));

        r = sd_pid_get_owner_uid(0, &u2);
        log_info("sd_pid_get_owner_uid(0, …) → %s / "UID_FMT, e(r), u2);
        assert_se(IN_SET(r, 0, -ENODATA));

        r = sd_pid_get_session(0, &session);
        log_info("sd_pid_get_session(0, …) → %s / \"%s\"", e(r), strnull(session));

        r = sd_pid_get_cgroup(0, &cgroup);
        log_info("sd_pid_get_cgroup(0, …) → %s / \"%s\"", e(r), strnull(cgroup));
        assert_se(IN_SET(r, 0, -ENOMEDIUM));

        pidfd = pidfd_open(getpid_cached(), 0);
        if (pidfd >= 0) {
                _cleanup_free_ char *cgroup2 = NULL, *session2 = NULL,
                        *unit2 = NULL, *user_unit2 = NULL, *slice2 = NULL;

                r = sd_pidfd_get_unit(pidfd, &unit2);
                log_info("sd_pidfd_get_unit(pidfd, …) → %s / \"%s\"", e(r), strnull(unit2));
                assert_se(IN_SET(r, 0, -ENODATA));

                r = sd_pidfd_get_user_unit(pidfd, &user_unit2);
                log_info("sd_pidfd_get_user_unit(pidfd, …) → %s / \"%s\"", e(r), strnull(user_unit2));
                assert_se(IN_SET(r, 0, -ENODATA));

                r = sd_pidfd_get_slice(pidfd, &slice2);
                log_info("sd_pidfd_get_slice(pidfd, …) → %s / \"%s\"", e(r), strnull(slice2));
                assert_se(IN_SET(r, 0, -ENODATA));

                r = sd_pidfd_get_owner_uid(pidfd, &u2);
                log_info("sd_pidfd_get_owner_uid(pidfd, …) → %s / "UID_FMT, e(r), u2);
                assert_se(IN_SET(r, 0, -ENODATA));

                r = sd_pidfd_get_session(pidfd, &session2);
                log_info("sd_pidfd_get_session(pidfd, …) → %s / \"%s\"", e(r), strnull(session2));

                r = sd_pidfd_get_cgroup(pidfd, &cgroup2);
                log_info("sd_pidfd_get_cgroup(pidfd, …) → %s / \"%s\"", e(r), strnull(cgroup2));
                assert_se(IN_SET(r, 0, -ENOMEDIUM));
        }

        r = ASSERT_RETURN_IS_CRITICAL(uid_is_valid(u2), sd_uid_get_display(u2, &display_session));
        log_info("sd_uid_get_display("UID_FMT", …) → %s / \"%s\"", u2, e(r), strnull(display_session));
        if (u2 == UID_INVALID)
                assert_se(r == -EINVAL);
        else
                assert_se(IN_SET(r, 0, -ENODATA));

        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        sd_peer_get_session(pair[0], &pp);
        sd_peer_get_session(pair[1], &qq);
        assert_se(streq_ptr(pp, qq));

        r = ASSERT_RETURN_IS_CRITICAL(uid_is_valid(u2), sd_uid_get_sessions(u2, false, &sessions));
        assert_se(t = strv_join(sessions, " "));
        log_info("sd_uid_get_sessions("UID_FMT", …) → %s \"%s\"", u2, e(r), t);
        if (u2 == UID_INVALID)
                assert_se(r == -EINVAL);
        else {
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(sessions));
        }
        sessions = strv_free(sessions);
        free(t);

        assert_se(r == ASSERT_RETURN_IS_CRITICAL(uid_is_valid(u2), sd_uid_get_sessions(u2, false, NULL)));

        r = ASSERT_RETURN_IS_CRITICAL(uid_is_valid(u2), sd_uid_get_seats(u2, false, &seats));
        assert_se(t = strv_join(seats, " "));
        log_info("sd_uid_get_seats("UID_FMT", …) → %s \"%s\"", u2, e(r), t);
        if (u2 == UID_INVALID)
                assert_se(r == -EINVAL);
        else {
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(seats));
        }
        seats = strv_free(seats);
        free(t);

        assert_se(r == ASSERT_RETURN_IS_CRITICAL(uid_is_valid(u2), sd_uid_get_seats(u2, false, NULL)));

        if (session) {
                r = sd_session_is_active(session);
                if (r == -ENXIO)
                        log_notice("sd_session_is_active() failed with ENXIO, it seems logind is not running.");
                else {
                        /* All those tests will fail with ENXIO, so let's skip them. */

                        assert_se(r >= 0);
                        log_info("sd_session_is_active(\"%s\") → %s", session, yes_no(r));

                        r = sd_session_is_remote(session);
                        assert_se(r >= 0);
                        log_info("sd_session_is_remote(\"%s\") → %s", session, yes_no(r));

                        r = sd_session_get_state(session, &state);
                        assert_se(r == 0);
                        log_info("sd_session_get_state(\"%s\") → \"%s\"", session, state);

                        assert_se(sd_session_get_uid(session, &u) >= 0);
                        log_info("sd_session_get_uid(\"%s\") → "UID_FMT, session, u);
                        assert_se(u == u2);

                        assert_se(sd_session_get_type(session, &type) >= 0);
                        log_info("sd_session_get_type(\"%s\") → \"%s\"", session, type);

                        assert_se(sd_session_get_class(session, &class) >= 0);
                        log_info("sd_session_get_class(\"%s\") → \"%s\"", session, class);

                        r = sd_session_get_display(session, &display);
                        assert_se(IN_SET(r, 0, -ENODATA));
                        log_info("sd_session_get_display(\"%s\") → \"%s\"", session, strna(display));

                        r = sd_session_get_remote_user(session, &remote_user);
                        assert_se(IN_SET(r, 0, -ENODATA));
                        log_info("sd_session_get_remote_user(\"%s\") → \"%s\"",
                                 session, strna(remote_user));

                        r = sd_session_get_remote_host(session, &remote_host);
                        assert_se(IN_SET(r, 0, -ENODATA));
                        log_info("sd_session_get_remote_host(\"%s\") → \"%s\"",
                                 session, strna(remote_host));

                        r = sd_session_get_seat(session, &seat);
                        if (r >= 0) {
                                assert_se(seat);

                                log_info("sd_session_get_seat(\"%s\") → \"%s\"", session, seat);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                                r = sd_seat_can_multi_session(seat);
#pragma GCC diagnostic pop
                                assert_se(r == 1);
                                log_info("sd_session_can_multi_seat(\"%s\") → %s", seat, yes_no(r));

                                r = sd_seat_can_tty(seat);
                                assert_se(r >= 0);
                                log_info("sd_session_can_tty(\"%s\") → %s", seat, yes_no(r));

                                r = sd_seat_can_graphical(seat);
                                assert_se(r >= 0);
                                log_info("sd_session_can_graphical(\"%s\") → %s", seat, yes_no(r));
                        } else {
                                log_info_errno(r, "sd_session_get_seat(\"%s\"): %m", session);
                                assert_se(r == -ENODATA);
                        }

                        assert_se(sd_uid_get_state(u, &state2) == 0);
                        log_info("sd_uid_get_state("UID_FMT", …) → %s", u, state2);
                }
        }

        if (seat) {
                _cleanup_free_ char *session2 = NULL, *buf = NULL;
                _cleanup_free_ uid_t *uids = NULL;
                unsigned n;

                assert_se(sd_uid_is_on_seat(u, 0, seat) > 0);

                r = sd_seat_get_active(seat, &session2, &u2);
                assert_se(r == 0);
                log_info("sd_seat_get_active(\"%s\", …) → \"%s\", "UID_FMT, seat, session2, u2);

                r = sd_uid_is_on_seat(u, 1, seat);
                assert_se(IN_SET(r, 0, 1));
                assert_se(!!r == streq(session, session2));

                r = sd_seat_get_sessions(seat, &sessions, &uids, &n);
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(sessions));
                assert_se(t = strv_join(sessions, " "));
                strv_free(sessions);
                log_info("sd_seat_get_sessions(\"%s\", …) → %s, \"%s\", [%u] {%s}",
                         seat, e(r), t, n, format_uids(&buf, uids, n));
                free(t);

                assert_se(sd_seat_get_sessions(seat, NULL, NULL, NULL) == r);
        }

        r = sd_get_seats(&seats);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(seats));
        assert_se(t = strv_join(seats, ", "));
        strv_free(seats);
        log_info("sd_get_seats(…) → [%i] \"%s\"", r, t);
        t = mfree(t);

        assert_se(sd_get_seats(NULL) == r);

        r = sd_seat_get_active(NULL, &t, NULL);
        assert_se(IN_SET(r, 0, -ENODATA, -ENXIO));
        log_info("sd_seat_get_active(NULL, …) (active session on current seat) → %s / \"%s\"", e(r), strnull(t));
        free(t);

        r = sd_get_sessions(&sessions);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(sessions));
        assert_se(t = strv_join(sessions, ", "));
        strv_free(sessions);
        log_info("sd_get_sessions(…) → [%i] \"%s\"", r, t);
        free(t);

        assert_se(sd_get_sessions(NULL) == r);

        {
                _cleanup_free_ uid_t *uids = NULL;
                _cleanup_free_ char *buf = NULL;

                r = sd_get_uids(&uids);
                assert_se(r >= 0);
                log_info("sd_get_uids(…) → [%i] {%s}", r, format_uids(&buf, uids, r));

                assert_se(sd_get_uids(NULL) == r);
        }

        {
                _cleanup_strv_free_ char **machines = NULL;
                _cleanup_free_ char *buf = NULL;

                r = sd_get_machine_names(&machines);
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(machines));
                assert_se(buf = strv_join(machines, " "));
                log_info("sd_get_machines(…) → [%i] \"%s\"", r, buf);

                assert_se(sd_get_machine_names(NULL) == r);
        }
}

TEST(monitor) {
        sd_login_monitor *m = NULL;
        int r;

        if (!streq_ptr(saved_argv[1], "-m"))
                return;

        assert_se(sd_login_monitor_new("session", &m) == 0);

        for (unsigned n = 0; n < 5; n++) {
                struct pollfd pollfd = {};
                usec_t timeout, nw;

                assert_se((pollfd.fd = sd_login_monitor_get_fd(m)) >= 0);
                assert_se((pollfd.events = sd_login_monitor_get_events(m)) >= 0);

                assert_se(sd_login_monitor_get_timeout(m, &timeout) >= 0);

                nw = now(CLOCK_MONOTONIC);

                r = poll(&pollfd, 1,
                         timeout == UINT64_MAX ? -1 :
                         timeout > nw ? (int) ((timeout - nw) / 1000) :
                         0);

                assert_se(r >= 0);

                sd_login_monitor_flush(m);
                printf("Wake!\n");
        }

        sd_login_monitor_unref(m);
}

static int intro(void) {
        if (IN_SET(cg_unified(), -ENOENT, -ENOMEDIUM))
                return log_tests_skipped("cgroupfs is not mounted");

        log_info("/* Information printed is from the live system */");
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

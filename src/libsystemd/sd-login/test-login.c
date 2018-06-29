/* SPDX-License-Identifier: LGPL-2.1+ */

#include <poll.h>
#include <string.h>

#include "sd-login.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static char* format_uids(char **buf, uid_t* uids, int count) {
        int pos = 0, k, inc;
        size_t size = (DECIMAL_STR_MAX(uid_t) + 1) * count + 1;

        assert_se(*buf = malloc(size));

        for (k = 0; k < count; k++) {
                sprintf(*buf + pos, "%s"UID_FMT"%n", k > 0 ? " " : "", uids[k], &inc);
                pos += inc;
        }

        assert_se(pos < (ssize_t)size);
        (*buf)[pos] = '\0';

        return *buf;
}

static void test_login(void) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_free_ char *pp = NULL, *qq = NULL,
                *display_session = NULL, *cgroup = NULL,
                *display = NULL, *remote_user = NULL, *remote_host = NULL,
                *type = NULL, *class = NULL, *state = NULL, *state2 = NULL,
                *seat = NULL, *session = NULL,
                *unit = NULL, *user_unit = NULL, *slice = NULL;
        int r;
        uid_t u, u2;
        char *t, **seats, **sessions;

        r = sd_pid_get_unit(0, &unit);
        assert_se(r >= 0 || r == -ENODATA);
        log_info("sd_pid_get_unit(0, …) → \"%s\"", strna(unit));

        r = sd_pid_get_user_unit(0, &user_unit);
        assert_se(r >= 0 || r == -ENODATA);
        log_info("sd_pid_get_user_unit(0, …) → \"%s\"", strna(user_unit));

        r = sd_pid_get_slice(0, &slice);
        assert_se(r >= 0 || r == -ENODATA);
        log_info("sd_pid_get_slice(0, …) → \"%s\"", strna(slice));

        r = sd_pid_get_session(0, &session);
        if (r < 0) {
                log_warning_errno(r, "sd_pid_get_session(0, …): %m");
                if (r == -ENODATA)
                        log_info("Seems we are not running in a session, skipping some tests.");
        } else {
                log_info("sd_pid_get_session(0, …) → \"%s\"", session);

                assert_se(sd_pid_get_owner_uid(0, &u2) == 0);
                log_info("sd_pid_get_owner_uid(0, …) → "UID_FMT, u2);

                assert_se(sd_pid_get_cgroup(0, &cgroup) == 0);
                log_info("sd_pid_get_cgroup(0, …) → \"%s\"", cgroup);

                r = sd_uid_get_display(u2, &display_session);
                assert_se(r >= 0 || r == -ENODATA);
                log_info("sd_uid_get_display("UID_FMT", …) → \"%s\"",
                         u2, strnull(display_session));

                assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
                sd_peer_get_session(pair[0], &pp);
                sd_peer_get_session(pair[1], &qq);
                assert_se(streq_ptr(pp, qq));

                r = sd_uid_get_sessions(u2, false, &sessions);
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(sessions));
                assert_se(t = strv_join(sessions, " "));
                strv_free(sessions);
                log_info("sd_uid_get_sessions("UID_FMT", …) → [%i] \"%s\"", u2, r, t);
                free(t);

                assert_se(r == sd_uid_get_sessions(u2, false, NULL));

                r = sd_uid_get_seats(u2, false, &seats);
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(seats));
                assert_se(t = strv_join(seats, " "));
                strv_free(seats);
                log_info("sd_uid_get_seats("UID_FMT", …) → [%i] \"%s\"", u2, r, t);
                free(t);

                assert_se(r == sd_uid_get_seats(u2, false, NULL));
        }

        if (session) {
                r = sd_session_is_active(session);
                assert_se(r >= 0);
                log_info("sd_session_is_active(\"%s\") → %s", session, yes_no(r));

                r = sd_session_is_remote(session);
                assert_se(r >= 0);
                log_info("sd_session_is_remote(\"%s\") → %s", session, yes_no(r));

                r = sd_session_get_state(session, &state);
                assert_se(r >= 0);
                log_info("sd_session_get_state(\"%s\") → \"%s\"", session, state);

                assert_se(sd_session_get_uid(session, &u) >= 0);
                log_info("sd_session_get_uid(\"%s\") → "UID_FMT, session, u);
                assert_se(u == u2);

                assert_se(sd_session_get_type(session, &type) >= 0);
                log_info("sd_session_get_type(\"%s\") → \"%s\"", session, type);

                assert_se(sd_session_get_class(session, &class) >= 0);
                log_info("sd_session_get_class(\"%s\") → \"%s\"", session, class);

                r = sd_session_get_display(session, &display);
                assert_se(r >= 0 || r == -ENODATA);
                log_info("sd_session_get_display(\"%s\") → \"%s\"", session, strna(display));

                r = sd_session_get_remote_user(session, &remote_user);
                assert_se(r >= 0 || r == -ENODATA);
                log_info("sd_session_get_remote_user(\"%s\") → \"%s\"",
                         session, strna(remote_user));

                r = sd_session_get_remote_host(session, &remote_host);
                assert_se(r >= 0 || r == -ENODATA);
                log_info("sd_session_get_remote_host(\"%s\") → \"%s\"",
                         session, strna(remote_host));

                r = sd_session_get_seat(session, &seat);
                if (r >= 0) {
                        assert_se(seat);

                        log_info("sd_session_get_seat(\"%s\") → \"%s\"", session, seat);

                        r = sd_seat_can_multi_session(seat);
                        assert_se(r >= 0);
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

                assert_se(sd_uid_get_state(u, &state2) >= 0);
                log_info("sd_uid_get_state("UID_FMT", …) → %s", u, state2);
        }

        if (seat) {
                _cleanup_free_ char *session2 = NULL, *buf = NULL;
                _cleanup_free_ uid_t *uids = NULL;
                unsigned n;

                assert_se(sd_uid_is_on_seat(u, 0, seat) > 0);

                r = sd_seat_get_active(seat, &session2, &u2);
                assert_se(r >= 0);
                log_info("sd_seat_get_active(\"%s\", …) → \"%s\", "UID_FMT, seat, session2, u2);

                r = sd_uid_is_on_seat(u, 1, seat);
                assert_se(r >= 0);
                assert_se(!!r == streq(session, session2));

                r = sd_seat_get_sessions(seat, &sessions, &uids, &n);
                assert_se(r >= 0);
                assert_se(r == (int) strv_length(sessions));
                assert_se(t = strv_join(sessions, " "));
                strv_free(sessions);
                log_info("sd_seat_get_sessions(\"%s\", …) → %i, \"%s\", [%i] {%s}",
                         seat, r, t, n, format_uids(&buf, uids, n));
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
        assert_se(IN_SET(r, 0, -ENODATA));
        log_info("sd_seat_get_active(NULL, …) (active session on current seat) → %s", strnull(t));
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

static void test_monitor(void) {
        sd_login_monitor *m = NULL;
        unsigned n;
        int r;

        r = sd_login_monitor_new("session", &m);
        assert_se(r >= 0);

        for (n = 0; n < 5; n++) {
                struct pollfd pollfd = {};
                usec_t timeout, nw;

                assert_se((pollfd.fd = sd_login_monitor_get_fd(m)) >= 0);
                assert_se((pollfd.events = sd_login_monitor_get_events(m)) >= 0);

                assert_se(sd_login_monitor_get_timeout(m, &timeout) >= 0);

                nw = now(CLOCK_MONOTONIC);

                r = poll(&pollfd, 1,
                         timeout == (uint64_t) -1 ? -1 :
                         timeout > nw ? (int) ((timeout - nw) / 1000) :
                         0);

                assert_se(r >= 0);

                sd_login_monitor_flush(m);
                printf("Wake!\n");
        }

        sd_login_monitor_unref(m);
}

int main(int argc, char* argv[]) {
        log_parse_environment();
        log_open();

        log_info("/* Information printed is from the live system */");

        test_login();

        if (streq_ptr(argv[1], "-m"))
                test_monitor();

        return 0;
}

/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/poll.h>
#include <string.h>

#include <systemd/sd-login.h>

#include "util.h"
#include "strv.h"

static void test_login(void) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_free_ char *pp = NULL, *qq = NULL;
        int r, k;
        uid_t u, u2;
        char *seat, *type, *class, *display, *remote_user, *remote_host;
        char *session;
        char *state;
        char *session2;
        char *t;
        char **seats, **sessions, **machines;
        uid_t *uids;
        unsigned n;
        struct pollfd pollfd;
        sd_login_monitor *m = NULL;

        assert_se(sd_pid_get_session(0, &session) == 0);
        printf("session = %s\n", session);

        assert_se(sd_pid_get_owner_uid(0, &u2) == 0);
        printf("user = "UID_FMT"\n", u2);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        sd_peer_get_session(pair[0], &pp);
        sd_peer_get_session(pair[1], &qq);
        assert_se(streq_ptr(pp, qq));

        r = sd_uid_get_sessions(u2, false, &sessions);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(sessions));
        assert_se(t = strv_join(sessions, ", "));
        strv_free(sessions);
        printf("sessions = %s\n", t);
        free(t);

        assert_se(r == sd_uid_get_sessions(u2, false, NULL));

        r = sd_uid_get_seats(u2, false, &seats);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(seats));
        assert_se(t = strv_join(seats, ", "));
        strv_free(seats);
        printf("seats = %s\n", t);
        free(t);

        assert_se(r == sd_uid_get_seats(u2, false, NULL));

        r = sd_session_is_active(session);
        assert_se(r >= 0);
        printf("active = %s\n", yes_no(r));

        r = sd_session_is_remote(session);
        assert_se(r >= 0);
        printf("remote = %s\n", yes_no(r));

        r = sd_session_get_state(session, &state);
        assert_se(r >= 0);
        printf("state = %s\n", state);
        free(state);

        assert_se(sd_session_get_uid(session, &u) >= 0);
        printf("uid = "UID_FMT"\n", u);
        assert_se(u == u2);

        assert_se(sd_session_get_type(session, &type) >= 0);
        printf("type = %s\n", type);
        free(type);

        assert_se(sd_session_get_class(session, &class) >= 0);
        printf("class = %s\n", class);
        free(class);

        assert_se(sd_session_get_display(session, &display) >= 0);
        printf("display = %s\n", display);
        free(display);

        assert_se(sd_session_get_remote_user(session, &remote_user) >= 0);
        printf("remote_user = %s\n", remote_user);
        free(remote_user);

        assert_se(sd_session_get_remote_host(session, &remote_host) >= 0);
        printf("remote_host = %s\n", remote_host);
        free(remote_host);

        assert_se(sd_session_get_seat(session, &seat) >= 0);
        printf("seat = %s\n", seat);

        r = sd_seat_can_multi_session(seat);
        assert_se(r >= 0);
        printf("can do multi session = %s\n", yes_no(r));

        r = sd_seat_can_tty(seat);
        assert_se(r >= 0);
        printf("can do tty = %s\n", yes_no(r));

        r = sd_seat_can_graphical(seat);
        assert_se(r >= 0);
        printf("can do graphical = %s\n", yes_no(r));

        assert_se(sd_uid_get_state(u, &state) >= 0);
        printf("state = %s\n", state);

        assert_se(sd_uid_is_on_seat(u, 0, seat) > 0);

        k = sd_uid_is_on_seat(u, 1, seat);
        assert_se(k >= 0);
        assert_se(!!r == !!r);

        assert_se(sd_seat_get_active(seat, &session2, &u2) >= 0);
        printf("session2 = %s\n", session2);
        printf("uid2 = "UID_FMT"\n", u2);

        r = sd_seat_get_sessions(seat, &sessions, &uids, &n);
        assert_se(r >= 0);
        printf("n_sessions = %i\n", r);
        assert_se(r == (int) strv_length(sessions));
        assert_se(t = strv_join(sessions, ", "));
        strv_free(sessions);
        printf("sessions = %s\n", t);
        free(t);
        printf("uids =");
        for (k = 0; k < (int) n; k++)
                printf(" "UID_FMT, uids[k]);
        printf("\n");
        free(uids);

        assert_se(sd_seat_get_sessions(seat, NULL, NULL, NULL) == r);

        free(session);
        free(state);
        free(session2);
        free(seat);

        r = sd_get_seats(&seats);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(seats));
        assert_se(t = strv_join(seats, ", "));
        strv_free(seats);
        printf("n_seats = %i\n", r);
        printf("seats = %s\n", t);
        free(t);

        assert_se(sd_get_seats(NULL) == r);

        r = sd_seat_get_active(NULL, &t, NULL);
        assert_se(r >= 0);
        printf("active session on current seat = %s\n", t);
        free(t);

        r = sd_get_sessions(&sessions);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(sessions));
        assert_se(t = strv_join(sessions, ", "));
        strv_free(sessions);
        printf("n_sessions = %i\n", r);
        printf("sessions = %s\n", t);
        free(t);

        assert_se(sd_get_sessions(NULL) == r);

        r = sd_get_uids(&uids);
        assert_se(r >= 0);

        printf("uids =");
        for (k = 0; k < r; k++)
                printf(" "UID_FMT, uids[k]);
        printf("\n");
        free(uids);

        printf("n_uids = %i\n", r);
        assert_se(sd_get_uids(NULL) == r);

        r = sd_get_machine_names(&machines);
        assert_se(r >= 0);
        assert_se(r == (int) strv_length(machines));
        assert_se(t = strv_join(machines, ", "));
        strv_free(machines);
        printf("n_machines = %i\n", r);
        printf("machines = %s\n", t);
        free(t);

        r = sd_login_monitor_new("session", &m);
        assert_se(r >= 0);

        for (n = 0; n < 5; n++) {
                usec_t timeout, nw;

                zero(pollfd);
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

        test_login();

        return 0;
}

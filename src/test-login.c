/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-login.h"
#include "util.h"

int main(int argc, char* argv[]) {
    int r, k;
    uid_t u, u2;
        char *seat;
        char *session;
        char *state;
        char *session2;

        assert_se(sd_pid_get_session(0, &session) == 0);
        printf("session = %s\n", session);

        r = sd_session_is_active(session);
        assert_se(r >= 0);
        printf("active = %s\n", yes_no(r));

        assert_se(sd_session_get_uid(session, &u) >= 0);
        printf("uid = %lu\n", (unsigned long) u);

        assert_se(sd_session_get_seat(session, &seat) >= 0);
        printf("seat = %s\n", seat);

        assert_se(sd_uid_get_state(u, &state) >= 0);
        printf("state = %s\n", state);

        assert_se(sd_uid_is_on_seat(u, seat) > 0);

        k = sd_uid_is_active_on_seat(u, seat);
        assert_se(k >= 0);
        assert_se(!!r == !!r);

        assert_se(sd_seat_get_active(seat, &session2, &u2) >= 0);
        printf("session2 = %s\n", session2);
        printf("uid2 = %lu\n", (unsigned long) u2);

        free(session);
        free(state);
        free(session2);
        free(seat);

        return 0;
}

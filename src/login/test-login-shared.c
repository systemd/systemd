/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include "login-util.h"
#include "macro.h"

static void test_session_id_valid(void) {
        assert_se(session_id_valid("c1"));
        assert_se(session_id_valid("1234"));

        assert_se(!session_id_valid("1-2"));
        assert_se(!session_id_valid(""));
        assert_se(!session_id_valid("\tid"));
}

int main(int argc, char* argv[]) {
        log_parse_environment();
        log_open();

        test_session_id_valid();

        return 0;
}

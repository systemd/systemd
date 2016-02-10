/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include "alloc-util.h"
#include "ask-password-api.h"
#include "log.h"

static void ask_password(void) {
        int r;
        _cleanup_free_ char *ret;

        r = ask_password_tty("hello?", "da key", 0, 0, NULL, &ret);
        assert(r >= 0);

        log_info("Got %s", ret);
}

int main(int argc, char **argv) {
        log_parse_environment();

        ask_password();
}

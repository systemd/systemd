/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stddef.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

int main(int argc, char* argv[]) {

        log_set_target(LOG_TARGET_CONSOLE);
        log_open();

        log_struct(LOG_INFO,
                   "MESSAGE=Waldo PID="PID_FMT, getpid(),
                   "SERVICE=piepapo",
                   NULL);

        log_set_target(LOG_TARGET_JOURNAL);
        log_open();

        log_struct(LOG_INFO,
                   "MESSAGE=Foobar PID="PID_FMT, getpid(),
                   "SERVICE=foobar",
                   NULL);

        log_struct(LOG_INFO,
                   "MESSAGE=Foobar PID="PID_FMT, getpid(),
                   "FORMAT_STR_TEST=1=%i A=%c 2=%hi 3=%li 4=%lli 1=%p foo=%s 2.5=%g 3.5=%g 4.5=%Lg",
                   (int) 1, 'A', (short) 2, (long int) 3, (long long int) 4, (void*) 1, "foo", (float) 2.5f, (double) 3.5, (long double) 4.5,
                   "SUFFIX=GOT IT",
                   NULL);

        return 0;
}

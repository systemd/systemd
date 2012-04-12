/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdio.h>

#include "util.h"

int main(int argc, char *argv[]) {
        struct dual_timestamp t;

        /* This is mostly useful for stuff like init ram disk scripts
         * which want to take a proper timestamp to do minimal bootup
         * profiling. */

        dual_timestamp_get(&t);
        printf("%llu %llu\n",
               (unsigned long long) t.realtime,
               (unsigned long long) t.monotonic);

        return 0;
}

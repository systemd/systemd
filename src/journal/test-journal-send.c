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

#include <systemd/sd-journal.h>

#include "log.h"

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);

        sd_journal_print(LOG_INFO, "piepapo");

        sd_journal_send("MESSAGE=foobar",
                        "VALUE=%i", 7,
                        NULL);

        errno = ENOENT;
        sd_journal_perror("Foobar");

        sd_journal_perror("");

        return 0;
}

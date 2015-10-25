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

#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "log.h"

int main(int argc, char *argv[]) {
        char huge[4096*1024];

        log_set_max_level(LOG_DEBUG);

        sd_journal_print(LOG_INFO, "piepapo");

        sd_journal_send("MESSAGE=foobar",
                        "VALUE=%i", 7,
                        NULL);

        errno = ENOENT;
        sd_journal_perror("Foobar");

        sd_journal_perror("");

        memset(huge, 'x', sizeof(huge));
        memcpy(huge, "HUGE=", 5);
        char_array_0(huge);

        sd_journal_send("MESSAGE=Huge field attached",
                        huge,
                        NULL);

        sd_journal_send("MESSAGE=uiui",
                        "VALUE=A",
                        "VALUE=B",
                        "VALUE=C",
                        "SINGLETON=1",
                        "OTHERVALUE=X",
                        "OTHERVALUE=Y",
                        "WITH_BINARY=this is a binary value \a",
                        NULL);

        syslog(LOG_NOTICE, "Hello World!");

        sd_journal_print(LOG_NOTICE, "Hello World");

        sd_journal_send("MESSAGE=Hello World!",
                        "MESSAGE_ID=52fb62f99e2c49d89cfbf9d6de5e3555",
                        "PRIORITY=5",
                        "HOME=%s", getenv("HOME"),
                        "TERM=%s", getenv("TERM"),
                        "PAGE_SIZE=%li", sysconf(_SC_PAGESIZE),
                        "N_CPUS=%li", sysconf(_SC_NPROCESSORS_ONLN),
                        NULL);

        sleep(1);

        return 0;
}

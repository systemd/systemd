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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "macro.h"

int main(int argc, char *argv[]) {
        char huge[4096*1024];

        /* utf-8 and non-utf-8, message-less and message-ful iovecs */
        struct iovec graph1[] = {
                {(char*) "GRAPH=graph", strlen("GRAPH=graph")}
        };
        struct iovec graph2[] = {
                {(char*) "GRAPH=graph\n", strlen("GRAPH=graph\n")}
        };
        struct iovec message1[] = {
                {(char*) "MESSAGE=graph", strlen("MESSAGE=graph")}
        };
        struct iovec message2[] = {
                {(char*) "MESSAGE=graph\n", strlen("MESSAGE=graph\n")}
        };

        assert_se(sd_journal_print(LOG_INFO, "piepapo") == 0);

        assert_se(sd_journal_send("MESSAGE=foobar",
                                  "VALUE=%i", 7,
                                  NULL) == 0);

        errno = ENOENT;
        assert_se(sd_journal_perror("Foobar") == 0);

        assert_se(sd_journal_perror("") == 0);

        memset(huge, 'x', sizeof(huge));
        memcpy(huge, "HUGE=", 5);
        char_array_0(huge);

        assert_se(sd_journal_send("MESSAGE=Huge field attached",
                                  huge,
                                  NULL) == 0);

        assert_se(sd_journal_send("MESSAGE=uiui",
                                  "VALUE=A",
                                  "VALUE=B",
                                  "VALUE=C",
                                  "SINGLETON=1",
                                  "OTHERVALUE=X",
                                  "OTHERVALUE=Y",
                                  "WITH_BINARY=this is a binary value \a",
                                  NULL) == 0);

        syslog(LOG_NOTICE, "Hello World!");

        assert_se(sd_journal_print(LOG_NOTICE, "Hello World") == 0);

        assert_se(sd_journal_send("MESSAGE=Hello World!",
                                  "MESSAGE_ID=52fb62f99e2c49d89cfbf9d6de5e3555",
                                  "PRIORITY=5",
                                  "HOME=%s", getenv("HOME"),
                                  "TERM=%s", getenv("TERM"),
                                  "PAGE_SIZE=%li", sysconf(_SC_PAGESIZE),
                                  "N_CPUS=%li", sysconf(_SC_NPROCESSORS_ONLN),
                                  NULL) == 0);

        assert_se(sd_journal_sendv(graph1, 1) == 0);
        assert_se(sd_journal_sendv(graph2, 1) == 0);
        assert_se(sd_journal_sendv(message1, 1) == 0);
        assert_se(sd_journal_sendv(message2, 1) == 0);

        /* test without location fields */
#undef sd_journal_sendv
        assert_se(sd_journal_sendv(graph1, 1) == 0);
        assert_se(sd_journal_sendv(graph2, 1) == 0);
        assert_se(sd_journal_sendv(message1, 1) == 0);
        assert_se(sd_journal_sendv(message2, 1) == 0);

        sleep(1);

        return 0;
}

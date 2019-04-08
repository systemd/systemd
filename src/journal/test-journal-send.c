/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "macro.h"

int main(int argc, char *argv[]) {
        char huge[4096*1024];

        /* utf-8 and non-utf-8, message-less and message-ful iovecs */
        struct iovec graph1[] = {
                {(char*) "GRAPH=graph", STRLEN("GRAPH=graph")}
        };
        struct iovec graph2[] = {
                {(char*) "GRAPH=graph\n", STRLEN("GRAPH=graph\n")}
        };
        struct iovec message1[] = {
                {(char*) "MESSAGE=graph", STRLEN("MESSAGE=graph")}
        };
        struct iovec message2[] = {
                {(char*) "MESSAGE=graph\n", STRLEN("MESSAGE=graph\n")}
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

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"

static void test_journal_print(void) {
        assert_se(sd_journal_print(LOG_INFO, "XXX") == 0);
        assert_se(sd_journal_print(LOG_INFO, "%s", "YYY") == 0);
        assert_se(sd_journal_print(LOG_INFO, "X%4094sY", "ZZZ") == 0);
        assert_se(sd_journal_print(LOG_INFO, "X%*sY", LONG_LINE_MAX - 8 - 3, "ZZZ") == 0);
        assert_se(sd_journal_print(LOG_INFO, "X%*sY", LONG_LINE_MAX - 8 - 2, "ZZZ") == -ENOBUFS);
}

static void test_journal_send(void) {
        _cleanup_free_ char *huge = NULL;

#define HUGE_SIZE (4096*1024)
        assert_se(huge = malloc(HUGE_SIZE));

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

        memcpy(huge, "HUGE=", STRLEN("HUGE="));
        memset(&huge[STRLEN("HUGE=")], 'x', HUGE_SIZE - STRLEN("HUGE=") - 1);
        huge[HUGE_SIZE - 1] = '\0';

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
}

int main(int argc, char *argv[]) {
        test_journal_print();
        test_journal_send();

        /* Sleep a bit to make it easy for journald to collect metadata. */
        sleep(1);

        return 0;
}

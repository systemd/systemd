/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "fileio.h"
#include "journal-send.h"
#include "tests.h"

TEST(journal_print) {
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "XXX"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "%s", "YYY"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "X%4094sY", "ZZZ"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "X%*sY", (int) LONG_LINE_MAX - 8 - 3, "ZZZ"));
        ASSERT_ERROR(sd_journal_print(LOG_INFO, "X%*sY", (int) LONG_LINE_MAX - 8 - 2, "ZZZ"), ENOBUFS);
}

TEST(journal_send) {
        _cleanup_free_ char *huge = NULL;

#define HUGE_SIZE (4096*1024)
        ASSERT_NOT_NULL(huge = malloc(HUGE_SIZE));

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

        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "piepapo"));

        ASSERT_OK_ZERO(sd_journal_send("MESSAGE=foobar",
                                       "VALUE=%i", 7,
                                       NULL));

        errno = ENOENT;
        ASSERT_OK_ZERO(sd_journal_perror("Foobar"));

        ASSERT_OK_ZERO(sd_journal_perror(""));

        memcpy(huge, "HUGE=", STRLEN("HUGE="));
        memset(&huge[STRLEN("HUGE=")], 'x', HUGE_SIZE - STRLEN("HUGE=") - 1);
        huge[HUGE_SIZE - 1] = '\0';

        ASSERT_OK_ZERO(sd_journal_send("MESSAGE=Huge field attached",
                                       huge,
                                       NULL));

        ASSERT_OK_ZERO(sd_journal_send("MESSAGE=uiui",
                                       "VALUE=A",
                                       "VALUE=B",
                                       "VALUE=C",
                                       "SINGLETON=1",
                                       "OTHERVALUE=X",
                                       "OTHERVALUE=Y",
                                       "WITH_BINARY=this is a binary value \a",
                                       NULL));

        syslog(LOG_NOTICE, "Hello World!");

        ASSERT_OK_ZERO(sd_journal_print(LOG_NOTICE, "Hello World"));

        ASSERT_OK_ZERO(sd_journal_send("MESSAGE=Hello World!",
                                       "MESSAGE_ID=52fb62f99e2c49d89cfbf9d6de5e3555",
                                       "PRIORITY=5",
                                       "HOME=%s", getenv("HOME"),
                                       "TERM=%s", getenv("TERM"),
                                       "PAGE_SIZE=%li", sysconf(_SC_PAGESIZE),
                                       "N_CPUS=%li", sysconf(_SC_NPROCESSORS_ONLN),
                                       NULL));

        ASSERT_OK_ZERO(sd_journal_sendv(graph1, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(graph2, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(message1, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(message2, 1));

        /* test without location fields */
#undef sd_journal_sendv
        ASSERT_OK_ZERO(sd_journal_sendv(graph1, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(graph2, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(message1, 1));
        ASSERT_OK_ZERO(sd_journal_sendv(message2, 1));

        /* The above syslog() opens a fd which is stored in libc, and the valgrind reports the fd is
         * leaked when we do not call closelog(). */
        closelog();
}

static int outro(void) {
        /* Sleep a bit to make it easy for journald to collect metadata. */
        sleep(1);

        close_journal_fd();

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_INFO, NULL, outro);

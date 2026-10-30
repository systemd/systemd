/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "journal-send.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "tests.h"

TEST(journal_print) {
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "XXX"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "%s", "YYY"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "X%4094sY", "ZZZ"));
        ASSERT_OK_ZERO(sd_journal_print(LOG_INFO, "X%*sY", (int) LONG_LINE_MAX - 8 - 3, "ZZZ"));
        ASSERT_ERROR(sd_journal_print(LOG_INFO, "X%*sY", (int) LONG_LINE_MAX - 8 - 2, "ZZZ"), ENOBUFS);
}

TEST(journal_send) {
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

#define HUGE_MESSAGE "MESSAGE=Huge field attached"
#define HUGE_FIELD "HUGE="
#define HUGE_SIZE (16U * 1024U * 1024U)

TEST(journal_send_huge) {
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r;

        /* A message that does not fit into a datagram is passed to journald as a memfd. The child sends it
         * to its own socket in a private mount namespace, so that each run of the test does not add the
         * message to the journal of the host. The message is larger than the send buffer that journal_fd()
         * asks for, so that the memfd is used even if the kernel grants that buffer. */

        r = ASSERT_OK(pidref_safe_fork("(journal-send-huge)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &child));
        if (r == 0) {
                _cleanup_free_ char *huge = NULL, *received = NULL;
                _cleanup_close_ int sock = -EBADF, fd = -EBADF;
                union sockaddr_union sa;
                size_t received_size;

                r = detach_mount_namespace_harder(0, 0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to detach mount namespace: %m");
                        _exit(EXIT_TEST_SKIP);
                }

                ASSERT_OK_ERRNO(mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"));
                ASSERT_OK(mkdir_p("/run/systemd/journal", 0755));

                sock = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0));
                r = ASSERT_OK(sockaddr_un_set_path(&sa.un, "/run/systemd/journal/socket"));
                ASSERT_OK_ERRNO(bind(sock, &sa.sa, r));

                huge = ASSERT_NOT_NULL(malloc(HUGE_SIZE));
                memcpy(huge, HUGE_FIELD, STRLEN(HUGE_FIELD));
                memset(huge + STRLEN(HUGE_FIELD), 'x', HUGE_SIZE - STRLEN(HUGE_FIELD) - 1);
                huge[HUGE_SIZE - 1] = '\0';

                ASSERT_OK_ZERO(sd_journal_send(HUGE_MESSAGE, huge, NULL));

                fd = ASSERT_OK(receive_one_fd(sock, MSG_DONTWAIT));
                ASSERT_OK_POSITIVE(memfd_get_sealed(fd));

                ASSERT_OK(read_full_file_at(fd, /* filename= */ NULL, &received, &received_size));
                ASSERT_NOT_NULL(memmem_safe(received, received_size,
                                            HUGE_MESSAGE "\n", STRLEN(HUGE_MESSAGE "\n")));
                ASSERT_NOT_NULL(memmem_safe(received, received_size, huge, HUGE_SIZE - 1));

                _exit(EXIT_SUCCESS);
        }

        r = pidref_wait_for_terminate_and_check("(journal-send-huge)", &child, WAIT_LOG_ABNORMAL);
        if (r == EXIT_TEST_SKIP)
                return (void) log_tests_skipped("Cannot create a private mount namespace");
        ASSERT_OK_ZERO(r);
}

static int outro(void) {
        /* Sleep a bit to make it easy for journald to collect metadata. */
        sleep(1);

        close_journal_fd();

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_INFO, NULL, outro);

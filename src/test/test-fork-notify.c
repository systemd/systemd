/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fork-notify.h"
#include "io-util.h"
#include "path-util.h"
#include "pidref.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

#define MESSAGE "Hello from a socket path longer than sun_path"

TEST(fork_journal_remote_long_path) {
        /* fork_journal_remote() must listen on a socket path that doesn't fit into sun_path. Create a
         * directory whose path is longer than sun_path, start systemd-journal-remote on a socket in it,
         * and send a journal entry in the export format to the socket. The entry must show up in the
         * output directory of systemd-journal-remote. */

        _cleanup_free_ char *journal_remote = NULL;
        if (find_executable("systemd-journal-remote", &journal_remote) < 0)
                return (void) log_tests_skipped("systemd-journal-remote not found");

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL, *output = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-fork-notify-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxXXXXXX", &t));
        ASSERT_OK(mkdtemp_malloc("/tmp/test-fork-notify-journal-XXXXXX", &output));

        _cleanup_free_ char *socket_path = path_join(t, "socket");
        ASSERT_NOT_NULL(socket_path);
        ASSERT_GE(strlen(socket_path), SUN_PATH_LEN);

        _cleanup_(fork_notify_terminate) PidRef pidref = PIDREF_NULL;
        ASSERT_OK(fork_journal_remote(
                        socket_path,
                        output,
                        /* max_use= */ UINT64_MAX,
                        /* keep_free= */ UINT64_MAX,
                        /* max_file_size= */ UINT64_MAX,
                        /* max_files= */ UINT64_MAX,
                        &pidref));

        /* Send the entry. systemd-journal-remote doesn't write an entry without valid timestamps. */
        sd_id128_t boot_id;
        ASSERT_OK(sd_id128_get_boot(&boot_id));

        _cleanup_free_ char *entry = asprintf_safe(
                        "__REALTIME_TIMESTAMP=" USEC_FMT "\n"
                        "__MONOTONIC_TIMESTAMP=" USEC_FMT "\n"
                        "_BOOT_ID=" SD_ID128_FORMAT_STR "\n"
                        "MESSAGE=" MESSAGE "\n"
                        "\n",
                        now(CLOCK_REALTIME),
                        now(CLOCK_MONOTONIC),
                        SD_ID128_FORMAT_VAL(boot_id));
        ASSERT_NOT_NULL(entry);

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        ASSERT_OK_ERRNO(fd);
        ASSERT_OK(connect_unix_path(fd, AT_FDCWD, socket_path));
        ASSERT_OK(loop_write(fd, entry, SIZE_MAX));

        /* Wait until systemd-journal-remote has written the entry. */
        for (usec_t end = usec_add(now(CLOCK_MONOTONIC), 30 * USEC_PER_SEC);;) {
                _cleanup_(sd_journal_closep) sd_journal *j = NULL;
                ASSERT_OK(sd_journal_open_directory(&j, output, /* flags= */ 0));
                ASSERT_OK(sd_journal_add_match(j, "MESSAGE=" MESSAGE, SIZE_MAX));

                int r = sd_journal_next(j);
                ASSERT_OK(r);
                if (r > 0)
                        break;

                ASSERT_LT(now(CLOCK_MONOTONIC), end);
                usleep_safe(50 * USEC_PER_MSEC);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);

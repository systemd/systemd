/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "event-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "notify-recv.h"
#include "pidref.h"
#include "process-util.h"
#include "strv.h"
#include "tests.h"

typedef struct Context {
        unsigned data;
        PidRef pidref;
} Context;

static void context_done(Context *c) {
        assert(c);

        pidref_done(&c->pidref);
}

static int on_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        _cleanup_(fdset_free_asyncp) FDSet *fds = NULL;
        _cleanup_(pidref_done) PidRef sender = PIDREF_NULL;
        _cleanup_strv_free_ char **l = NULL;
        struct ucred ucred;
        ASSERT_OK(notify_recv_with_fds_strv(fd, &l, &ucred, &sender, &fds));

        ASSERT_TRUE(pidref_equal(&c->pidref, &sender));

        ASSERT_EQ(ucred.gid, getgid());
        ASSERT_EQ(ucred.pid, c->pidref.pid);
        ASSERT_EQ(ucred.uid, getuid());

        _cleanup_free_ char *joined = strv_join(l, ", ");
        ASSERT_NOT_NULL(joined);
        log_info("Received message: %s", joined);

        if (strv_contains(l, "FIRST_MESSAGE=1")) {
                ASSERT_STREQ(l[0], "FIRST_MESSAGE=1");
                ASSERT_NULL(l[1]);
                ASSERT_EQ(++c->data, 1u);
                ASSERT_NULL(fds);
        } else if (strv_contains(l, "SECOND_MESSAGE=1")) {
                ASSERT_STREQ(l[0], "SECOND_MESSAGE=1");
                ASSERT_STREQ(l[1], "ADDITIONAL_DATA=hoge");
                ASSERT_EQ(++c->data, 2u);
                ASSERT_NOT_NULL(fds);
                ASSERT_EQ(fdset_size(fds), 2u);

                int i;
                FDSET_FOREACH(i, fds) {
                        _cleanup_free_ char *path = NULL;
                        ASSERT_OK(fd_get_path(i, &path));
                        ASSERT_TRUE(STR_IN_SET(path, "/tmp", "/dev/null"));
                }
        }

        return 0;
}

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_EQ(si->si_code, CLD_EXITED);
        ASSERT_EQ(si->si_status, EXIT_SUCCESS);

        ASSERT_EQ(c->data, 2u);

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

TEST(notify_socket_prepare) {
        int r;

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(context_done) Context c = {
                .pidref = PIDREF_NULL,
        };
        _cleanup_free_ char *path = NULL;
        ASSERT_OK(notify_socket_prepare_full(e, SD_EVENT_PRIORITY_NORMAL - 10, on_recv, &c, true, &path, NULL));

        ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD));

        ASSERT_OK(r = pidref_safe_fork("(test-notify-recv-child)", FORK_DEATHSIG_SIGTERM|FORK_LOG, &c.pidref));
        if (r == 0) {
                ASSERT_OK_ERRNO(setenv("NOTIFY_SOCKET", path, /* overwrite = */ true));
                ASSERT_OK_POSITIVE(sd_notify(/* unset_environment = */ false, "FIRST_MESSAGE=1"));

                _cleanup_close_ int fd1 = open("/tmp", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                ASSERT_OK_ERRNO(fd1);
                _cleanup_close_ int fd2 = open("/dev/null", O_RDONLY|O_CLOEXEC);
                ASSERT_OK_ERRNO(fd2);

                ASSERT_OK_POSITIVE(
                        sd_pid_notify_with_fds(
                                0, /* unset_environment = */ false,
                                "SECOND_MESSAGE=1\nADDITIONAL_DATA=hoge", (int[]) { fd1, fd2 }, 2));
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(event_add_child_pidref(e, NULL, &c.pidref, WEXITED, on_sigchld, &c));
        ASSERT_OK(sd_event_loop(e));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

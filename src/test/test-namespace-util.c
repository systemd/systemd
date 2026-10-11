/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "tests.h"

TEST(namespace_enter) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        r = pidref_safe_fork(
                        "test-ns-enter-1",
                        FORK_NEW_USERNS|FORK_NEW_MOUNTNS|FORK_LOG|FORK_FREEZE|FORK_DEATHSIG_SIGKILL,
                        &pidref);
        if (ERRNO_IS_NEG_PRIVILEGE(r) || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "Unable to unshare user namespace");

        ASSERT_OK(r);

        _cleanup_close_ int mntns_fd = -EBADF, userns_fd = -EBADF, root_fd = -EBADF;
        ASSERT_OK(pidref_namespace_open(&pidref, NULL, &mntns_fd, NULL, &userns_fd, &root_fd));

        /* Without any mapping the namespace is still being set up, we can't tell yet if root is mapped. */
        ASSERT_ERROR(userns_has_root_mapping(userns_fd), ENODATA);

        /* The user namespace maps nothing, hence becoming root in it must fail, with or without CAP_SYS_ADMIN. */
        r = ASSERT_OK(pidref_safe_fork(
                        "test-ns-enter-2",
                        FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                        NULL));
        if (r == 0) {
                ASSERT_ERROR(namespace_enter(-EBADF, mntns_fd, -EBADF, userns_fd, root_fd), EINVAL);
                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork(
                        "test-ns-enter-3",
                        FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                        NULL));
        if (r == 0) {
                ASSERT_OK(drop_capability(CAP_SYS_ADMIN));
                ASSERT_ERROR(namespace_enter(-EBADF, mntns_fd, -EBADF, userns_fd, root_fd), EINVAL);
                _exit(EXIT_SUCCESS);
        }
}

TEST(namespace_enter_mapped) {
        static const struct {
                uid_t uid;
                gid_t gid;
                NamespaceEnterFlags flags;
                int error;
        } cases[] = {
                /* Root is mapped: we become root. */
                { 0, 0, 0,                                             0      },
                /* Root is not mapped: entering fails instead of silently keeping our identity. */
                { 1, 1, 0,                                             EINVAL },
                /* Root is mapped: the flag has no effect, we still become root. */
                { 0, 0, NAMESPACE_ENTER_KEEP_UID_GID_IF_ROOT_UNMAPPED, 0      },
                /* Root is not mapped: the flag lets us enter and keep our identity. */
                { 1, 1, NAMESPACE_ENTER_KEEP_UID_GID_IF_ROOT_UNMAPPED, 0      },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
                _cleanup_close_ int userns_fd = -EBADF;
                int r;

                /* Map ourselves either to root or to a nonzero identity. This also works unprivileged. */
                ASSERT_OK(asprintf(&uid_map, UID_FMT " " UID_FMT " 1", c->uid, getuid()));
                ASSERT_OK(asprintf(&gid_map, GID_FMT " " GID_FMT " 1", c->gid, getgid()));

                userns_fd = userns_acquire(uid_map, gid_map, /* setgroups_deny= */ true);
                if (ERRNO_IS_NEG_PRIVILEGE(userns_fd) || ERRNO_IS_NEG_NOT_SUPPORTED(userns_fd))
                        return (void) log_tests_skipped_errno(userns_fd, "Unable to acquire user namespace");
                ASSERT_OK(userns_fd);

                r = namespace_fork_full(
                                "test-ns-mapped", "test-ns-mapped-inner",
                                /* except_fds= */ NULL, /* n_except_fds= */ 0,
                                FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                                /* pidns_fd= */ -EBADF, /* mntns_fd= */ -EBADF, /* netns_fd= */ -EBADF,
                                userns_fd, /* root_fd= */ -EBADF, c->flags, /* ret= */ NULL);
                if (r == 0) {
                        uid_t ruid, euid, suid;
                        gid_t rgid, egid, sgid;

                        ASSERT_EQ(c->error, 0);
                        ASSERT_OK_ERRNO(getresuid(&ruid, &euid, &suid));
                        ASSERT_EQ(ruid, c->uid);
                        ASSERT_EQ(euid, c->uid);
                        ASSERT_EQ(suid, c->uid);
                        ASSERT_OK_ERRNO(getresgid(&rgid, &egid, &sgid));
                        ASSERT_EQ(rgid, c->gid);
                        ASSERT_EQ(egid, c->gid);
                        ASSERT_EQ(sgid, c->gid);

                        _exit(EXIT_SUCCESS);
                }

                if (c->error > 0)
                        ASSERT_ERROR(r, c->error);
                else
                        ASSERT_OK(r);
        }
}

TEST(namespace_enter_peercred) {
        _cleanup_close_pair_ int transport[2] = EBADF_PAIR;
        _cleanup_close_ int userns_fd = -EBADF, fd = -EBADF;
        struct ucred ucred;
        int r;

        /* Map root to identities different from ours, so the parent can verify that the reset changed the
         * underlying credentials. Unlike the other cases, configuring these mappings requires privileges. */
        uid_t uid = getuid() == 1 ? 2 : 1;
        gid_t gid = getgid() == 2 ? 1 : 2;
        _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
        ASSERT_OK(asprintf(&uid_map, "0 " UID_FMT " 1", uid));
        ASSERT_OK(asprintf(&gid_map, "0 " GID_FMT " 1", gid));

        userns_fd = userns_acquire(uid_map, gid_map, /* setgroups_deny= */ true);
        if (ERRNO_IS_NEG_PRIVILEGE(userns_fd) || ERRNO_IS_NEG_NOT_SUPPORTED(userns_fd))
                return (void) log_tests_skipped_errno(userns_fd, "Unable to map other UID/GID into user namespace");
        ASSERT_OK(userns_fd);

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, transport));

        r = ASSERT_OK(namespace_fork(
                        "test-ns-peercred", "test-ns-peercred-inner",
                        FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL,
                        /* pidns_fd= */ -EBADF, /* mntns_fd= */ -EBADF, /* netns_fd= */ -EBADF,
                        userns_fd, /* root_fd= */ -EBADF, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_close_pair_ int pair[2] = EBADF_PAIR;

                /* Capture credentials after namespace entry, then let the parent inspect them from outside. */
                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, pair));
                ASSERT_OK(send_one_fd(transport[1], pair[0], 0));
                _exit(EXIT_SUCCESS);
        }

        transport[1] = safe_close(transport[1]);
        fd = ASSERT_OK(receive_one_fd(transport[0], 0));
        ASSERT_OK(getpeercred(fd, &ucred));
        ASSERT_EQ(ucred.uid, uid);
        ASSERT_EQ(ucred.gid, gid);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

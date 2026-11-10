/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fd-util.h"
#include "io-uring-filter.h"
#include "io-uring-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "set.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static int ring_submit(IoUring *ring, const struct io_uring_sqe *template) {
        union io_uring_cqe32 *cqe;
        unsigned n = 0;
        int res = 0;

        union io_uring_sqe128 *sqe = ASSERT_NOT_NULL(io_uring_get_sqe(ring));
        sqe->sqe = *template;

        ASSERT_OK(io_uring_submit_and_wait(ring, USEC_INFINITY));

        IO_URING_FOREACH_CQE(cqe, ring) {
                res = cqe->cqe.res;
                n++;
        }
        ASSERT_EQ(n, 1u);
        io_uring_cq_advance(ring, n);

        return res;
}

static int submit_nop(IoUring *ring) {
        return ring_submit(ring, &(struct io_uring_sqe) { .opcode = IORING_OP_NOP });
}

static int submit_socket(IoUring *ring, int family) {
        return ring_submit(ring, &(struct io_uring_sqe) {
                .opcode = IORING_OP_SOCKET,
                .fd = family,
                .off = SOCK_DGRAM|SOCK_CLOEXEC,
        });
}

static int submit_openat(IoUring *ring, int dir_fd, const char *path, int flags, mode_t mode) {
        return ring_submit(ring, &(struct io_uring_sqe) {
                .opcode = IORING_OP_OPENAT,
                .fd = dir_fd,
                .addr = PTR_TO_UINT64(path),
                .len = mode,
                .open_flags = flags,
        });
}

static int submit_openat2(IoUring *ring, int dir_fd, const char *path, int flags, mode_t mode) {
        struct open_how how = {
                .flags = flags,
                .mode = mode,
        };

        return ring_submit(ring, &(struct io_uring_sqe) {
                .opcode = IORING_OP_OPENAT2,
                .fd = dir_fd,
                .addr = PTR_TO_UINT64(path),
                .addr2 = PTR_TO_UINT64(&how),
                .len = sizeof(how),
        });
}

static void assert_fd_and_close(int fd) {
        ASSERT_OK(fd);
        safe_close(fd);
}

/* Task filters require no_new_privs or CAP_SYS_ADMIN, so every test sets no_new_privs in a child. */
static bool have_io_uring_bpf_filters(void) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        r = ASSERT_OK(pidref_safe_fork("(probe)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;

                ASSERT_OK(proc_set_nnp());

                if (io_uring_bpf_filter_supported() <= 0 || io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0) < 0)
                        _exit(EXIT_TEST_SKIP);

                _exit(EXIT_SUCCESS);
        }

        return ASSERT_OK(pidref_wait_for_terminate_and_check("(probe)", &pidref, WAIT_LOG_ABNORMAL)) == EXIT_SUCCESS;
}

#define CHECK_IO_URING_BPF_FILTERS()                                                    \
        if (!have_io_uring_bpf_filters())                                               \
                return (void) log_tests_skipped("io_uring BPF filters are not available")

TEST(io_uring_op_names) {
        for (int op = 0; op < IORING_OP_LAST; op++) {
                const char *name = ASSERT_NOT_NULL(io_uring_op_to_string(op));
                ASSERT_EQ(io_uring_op_from_string(name), op);
        }

        ASSERT_NULL(io_uring_op_to_string(IORING_OP_LAST));
        ASSERT_ERROR(io_uring_op_from_string("foobar"), EINVAL);
}

TEST(restrict_ops_deny_list) {
        int r;

        CHECK_IO_URING_BPF_FILTERS();

        r = ASSERT_OK(pidref_safe_fork("(deny-list)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring before = IO_URING_NULL, after = IO_URING_NULL;
                _cleanup_set_free_ Set *ops = NULL;

                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(io_uring_init(&before, /* entries= */ 1, /* flags= */ 0));

                ASSERT_OK(set_ensure_put(&ops, /* hash_ops= */ NULL, INT_TO_PTR(IORING_OP_NOP + 1)));
                ASSERT_OK(io_uring_restrict_ops(ops, /* allow_list= */ false));

                ASSERT_OK(io_uring_init(&after, /* entries= */ 1, /* flags= */ 0));
                ASSERT_ERROR(submit_nop(&after), EACCES);
                assert_fd_and_close(submit_socket(&after, AF_UNIX));

                /* The kernel copies the task filters when it creates a ring, so older rings are not filtered. */
                ASSERT_OK_ZERO(submit_nop(&before));

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_ops_allow_list) {
        int r;

        CHECK_IO_URING_BPF_FILTERS();

        r = ASSERT_OK(pidref_safe_fork("(allow-list)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
                _cleanup_set_free_ Set *ops = NULL;

                ASSERT_OK(proc_set_nnp());

                ASSERT_OK(set_ensure_put(&ops, /* hash_ops= */ NULL, INT_TO_PTR(IORING_OP_NOP + 1)));
                ASSERT_OK(io_uring_restrict_ops(ops, /* allow_list= */ true));

                ASSERT_OK(io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0));
                ASSERT_OK_ZERO(submit_nop(&ring));
                ASSERT_ERROR(submit_socket(&ring, AF_UNIX), EACCES);

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_address_families) {
        int r;

        CHECK_IO_URING_BPF_FILTERS();

        r = ASSERT_OK(pidref_safe_fork("(allow-list)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
                _cleanup_set_free_ Set *families = NULL;

                ASSERT_OK(proc_set_nnp());

                ASSERT_OK(set_ensure_put(&families, /* hash_ops= */ NULL, INT_TO_PTR(AF_UNIX)));
                ASSERT_OK(set_ensure_put(&families, /* hash_ops= */ NULL, INT_TO_PTR(AF_NETLINK)));
                ASSERT_OK(io_uring_restrict_address_families(families, /* allow_list= */ true));

                ASSERT_OK(io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0));
                assert_fd_and_close(submit_socket(&ring, AF_UNIX));
                assert_fd_and_close(submit_socket(&ring, AF_NETLINK));
                ASSERT_ERROR(submit_socket(&ring, AF_INET), EACCES);
                ASSERT_ERROR(submit_socket(&ring, AF_INET6), EACCES);

                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(deny-list)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
                _cleanup_set_free_ Set *families = NULL;

                ASSERT_OK(proc_set_nnp());

                ASSERT_OK(set_ensure_put(&families, /* hash_ops= */ NULL, INT_TO_PTR(AF_UNIX)));
                ASSERT_OK(io_uring_restrict_address_families(families, /* allow_list= */ false));

                ASSERT_OK(io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0));
                ASSERT_ERROR(submit_socket(&ring, AF_UNIX), EACCES);
                assert_fd_and_close(submit_socket(&ring, AF_NETLINK));

                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(empty)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;

                ASSERT_OK(proc_set_nnp());

                ASSERT_OK(io_uring_restrict_address_families(/* address_families= */ NULL, /* allow_list= */ true));

                ASSERT_OK(io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0));
                ASSERT_ERROR(submit_socket(&ring, AF_UNIX), EACCES);

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_suid_sgid) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        int r;

        CHECK_IO_URING_BPF_FILTERS();

        dir_fd = ASSERT_OK(mkdtemp_open("/var/tmp/test-io-uring-XXXXXX", O_PATH, &tmp));

        r = ASSERT_OK(pidref_safe_fork("(suid-sgid)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(io_uring_done) IoUring ring = IO_URING_NULL;
                mode_t mode;

                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(io_uring_restrict_suid_sgid());
                ASSERT_OK(io_uring_init(&ring, /* entries= */ 1, /* flags= */ 0));

                FOREACH_ARGUMENT(mode, S_ISUID, S_ISGID, S_ISUID|S_ISGID) {
                        ASSERT_ERROR(submit_openat(&ring, dir_fd, "file", O_CREAT|O_RDWR|O_CLOEXEC, 0755|mode), EACCES);
                        ASSERT_ERROR(submit_openat2(&ring, dir_fd, "file", O_CREAT|O_RDWR|O_CLOEXEC, 0755|mode), EACCES);
                        ASSERT_ERROR(submit_openat(&ring, dir_fd, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0755|mode), EACCES);
                        ASSERT_ERROR(submit_openat2(&ring, dir_fd, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0755|mode), EACCES);
                }

                assert_fd_and_close(submit_openat(&ring, dir_fd, "file", O_CREAT|O_RDWR|O_CLOEXEC, 0755));
                assert_fd_and_close(submit_openat2(&ring, dir_fd, "file", O_CREAT|O_RDWR|O_CLOEXEC, 0755));
                assert_fd_and_close(submit_openat(&ring, dir_fd, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0755));

                /* Without O_CREAT or O_TMPFILE, the kernel ignores the mode. */
                assert_fd_and_close(submit_openat(&ring, dir_fd, "file", O_RDONLY|O_CLOEXEC, 0755|S_ISUID));

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);

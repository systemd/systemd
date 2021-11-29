/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fileio.h"
#include "fs-util.h"
#include "limits-util.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

TEST(LOG2ULL) {
        assert_se(LOG2ULL(0) == 0);
        assert_se(LOG2ULL(1) == 0);
        assert_se(LOG2ULL(8) == 3);
        assert_se(LOG2ULL(9) == 3);
        assert_se(LOG2ULL(15) == 3);
        assert_se(LOG2ULL(16) == 4);
        assert_se(LOG2ULL(1024*1024) == 20);
        assert_se(LOG2ULL(1024*1024+5) == 20);
}

TEST(CONST_LOG2ULL) {
        assert_se(CONST_LOG2ULL(0) == 0);
        assert_se(CONST_LOG2ULL(1) == 0);
        assert_se(CONST_LOG2ULL(8) == 3);
        assert_se(CONST_LOG2ULL(9) == 3);
        assert_se(CONST_LOG2ULL(15) == 3);
        assert_se(CONST_LOG2ULL(16) == 4);
        assert_se(CONST_LOG2ULL(1024*1024) == 20);
        assert_se(CONST_LOG2ULL(1024*1024+5) == 20);
}

TEST(NONCONST_LOG2ULL) {
        assert_se(NONCONST_LOG2ULL(0) == 0);
        assert_se(NONCONST_LOG2ULL(1) == 0);
        assert_se(NONCONST_LOG2ULL(8) == 3);
        assert_se(NONCONST_LOG2ULL(9) == 3);
        assert_se(NONCONST_LOG2ULL(15) == 3);
        assert_se(NONCONST_LOG2ULL(16) == 4);
        assert_se(NONCONST_LOG2ULL(1024*1024) == 20);
        assert_se(NONCONST_LOG2ULL(1024*1024+5) == 20);
}

TEST(log2u64) {
        assert_se(log2u64(0) == 0);
        assert_se(log2u64(1) == 0);
        assert_se(log2u64(8) == 3);
        assert_se(log2u64(9) == 3);
        assert_se(log2u64(15) == 3);
        assert_se(log2u64(16) == 4);
        assert_se(log2u64(1024*1024) == 20);
        assert_se(log2u64(1024*1024+5) == 20);
}

TEST(log2u) {
        assert_se(log2u(0) == 0);
        assert_se(log2u(1) == 0);
        assert_se(log2u(2) == 1);
        assert_se(log2u(3) == 1);
        assert_se(log2u(4) == 2);
        assert_se(log2u(32) == 5);
        assert_se(log2u(33) == 5);
        assert_se(log2u(63) == 5);
        assert_se(log2u(INT_MAX) == sizeof(int)*8-2);
}

TEST(log2i) {
        assert_se(log2i(0) == 0);
        assert_se(log2i(1) == 0);
        assert_se(log2i(2) == 1);
        assert_se(log2i(3) == 1);
        assert_se(log2i(4) == 2);
        assert_se(log2i(32) == 5);
        assert_se(log2i(33) == 5);
        assert_se(log2i(63) == 5);
        assert_se(log2i(INT_MAX) == sizeof(int)*8-2);
}

TEST(protect_errno) {
        errno = 12;
        {
                PROTECT_ERRNO;
                errno = 11;
        }
        assert_se(errno == 12);
}

static void test_unprotect_errno_inner_function(void) {
        PROTECT_ERRNO;

        errno = 2222;
}

TEST(unprotect_errno) {
        errno = 4711;

        PROTECT_ERRNO;

        errno = 815;

        UNPROTECT_ERRNO;

        assert_se(errno == 4711);

        test_unprotect_errno_inner_function();

        assert_se(errno == 4711);
}

TEST(eqzero) {
        const uint32_t zeros[] = {0, 0, 0};
        const uint32_t ones[] = {1, 1};
        const uint32_t mixed[] = {0, 1, 0, 0, 0};
        const uint8_t longer[] = {[55] = 255};

        assert_se(eqzero(zeros));
        assert_se(!eqzero(ones));
        assert_se(!eqzero(mixed));
        assert_se(!eqzero(longer));
}

TEST(raw_clone) {
        pid_t parent, pid, pid2;

        parent = getpid();
        log_info("before clone: getpid()→"PID_FMT, parent);
        assert_se(raw_getpid() == parent);

        pid = raw_clone(0);
        assert_se(pid >= 0);

        pid2 = raw_getpid();
        log_info("raw_clone: "PID_FMT" getpid()→"PID_FMT" raw_getpid()→"PID_FMT,
                 pid, getpid(), pid2);
        if (pid == 0) {
                assert_se(pid2 != parent);
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                assert_se(pid2 == parent);
                waitpid(pid, &status, __WCLONE);
                assert_se(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
        }

        errno = 0;
        assert_se(raw_clone(CLONE_FS|CLONE_NEWNS) == -1);
        assert_se(errno == EINVAL || ERRNO_IS_PRIVILEGE(errno)); /* Certain container environments prohibit namespaces to us, don't fail in that case */
}

TEST(physical_memory) {
        uint64_t p;

        p = physical_memory();
        assert_se(p > 0);
        assert_se(p < UINT64_MAX);
        assert_se(p % page_size() == 0);

        log_info("Memory: %s (%" PRIu64 ")", FORMAT_BYTES(p), p);
}

TEST(physical_memory_scale) {
        uint64_t p;

        p = physical_memory();

        assert_se(physical_memory_scale(0, 100) == 0);
        assert_se(physical_memory_scale(100, 100) == p);

        log_info("Memory original: %" PRIu64, physical_memory());
        log_info("Memory scaled by 50%%: %" PRIu64, physical_memory_scale(50, 100));
        log_info("Memory divided by 2: %" PRIu64, physical_memory() / 2);
        log_info("Page size: %zu", page_size());

        /* There might be an uneven number of pages, hence permit these calculations to be half a page off... */
        assert_se(page_size()/2 + physical_memory_scale(50, 100) - p/2 <= page_size());
        assert_se(physical_memory_scale(200, 100) == p*2);

        assert_se(physical_memory_scale(0, 1) == 0);
        assert_se(physical_memory_scale(1, 1) == p);
        assert_se(physical_memory_scale(2, 1) == p*2);

        assert_se(physical_memory_scale(0, 2) == 0);

        assert_se(page_size()/2 + physical_memory_scale(1, 2) - p/2 <= page_size());
        assert_se(physical_memory_scale(2, 2) == p);
        assert_se(physical_memory_scale(4, 2) == p*2);

        assert_se(physical_memory_scale(0, UINT32_MAX) == 0);
        assert_se(physical_memory_scale(UINT32_MAX, UINT32_MAX) == p);

        /* overflow */
        assert_se(physical_memory_scale(UINT64_MAX/4, UINT64_MAX) == UINT64_MAX);
}

TEST(system_tasks_max) {
        uint64_t t;

        t = system_tasks_max();
        assert_se(t > 0);
        assert_se(t < UINT64_MAX);

        log_info("Max tasks: %" PRIu64, t);
}

TEST(system_tasks_max_scale) {
        uint64_t t;

        t = system_tasks_max();

        assert_se(system_tasks_max_scale(0, 100) == 0);
        assert_se(system_tasks_max_scale(100, 100) == t);

        assert_se(system_tasks_max_scale(0, 1) == 0);
        assert_se(system_tasks_max_scale(1, 1) == t);
        assert_se(system_tasks_max_scale(2, 1) == 2*t);

        assert_se(system_tasks_max_scale(0, 2) == 0);
        assert_se(system_tasks_max_scale(1, 2) == t/2);
        assert_se(system_tasks_max_scale(2, 2) == t);
        assert_se(system_tasks_max_scale(3, 2) == (3*t)/2);
        assert_se(system_tasks_max_scale(4, 2) == t*2);

        assert_se(system_tasks_max_scale(0, UINT32_MAX) == 0);
        assert_se(system_tasks_max_scale((UINT32_MAX-1)/2, UINT32_MAX-1) == t/2);
        assert_se(system_tasks_max_scale(UINT32_MAX, UINT32_MAX) == t);

        /* overflow */

        assert_se(system_tasks_max_scale(UINT64_MAX/4, UINT64_MAX) == UINT64_MAX);
}

DEFINE_TEST_MAIN(LOG_INFO);

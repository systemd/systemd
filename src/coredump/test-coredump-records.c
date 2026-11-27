/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/coredump.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "coredump-records.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "memory-util.h"
#include "tests.h"
#include "tmpfile-util.h"

/* Small enough that a whole test coredump fits into the default socket buffer. */
#define CHUNK (16U * U64_KB)

static uint8_t data[CHUNK];

static void send_record(int fd, uint32_t type, uint64_t offset, uint64_t len) {
        struct coredump_record_header h = {
                .size = sizeof(h),
                .type = type,
                .offset = offset,
                .len = len,
        };

        ASSERT_OK(loop_write(fd, &h, sizeof(h)));
        if (type == COREDUMP_RECORD_DATA)
                ASSERT_OK(loop_write(fd, data, len));
}

/* Sends DATA, ZERO, DATA, ZERO, optionally followed by END, so there is a hole in the middle and one at the
 * end of the coredump. */
static void send_coredump(int fd, bool end) {
        send_record(fd, COREDUMP_RECORD_DATA, 0, CHUNK);
        send_record(fd, COREDUMP_RECORD_ZERO, CHUNK, 2 * CHUNK);
        send_record(fd, COREDUMP_RECORD_DATA, 3 * CHUNK, CHUNK);
        send_record(fd, COREDUMP_RECORD_ZERO, 4 * CHUNK, CHUNK);
        if (end)
                send_record(fd, COREDUMP_RECORD_END, 5 * CHUNK, 0);
}

static int copy_from_socket(void (*sender)(int fd), uint64_t max_size, int *ret_fd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* The records fit into the socket buffer, so no separate sender is needed. */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, pair));
        sender(pair[1]);
        pair[1] = safe_close(pair[1]);

        fd = ASSERT_OK(open_tmpfile_unlinkable("/var/tmp", O_RDWR|O_CLOEXEC));

        r = coredump_copy_records(pair[0], fd, max_size);
        if (r >= 0 && ret_fd)
                *ret_fd = TAKE_FD(fd);
        return r;
}

static void assert_chunk(int fd, uint64_t offset, bool zero) {
        _cleanup_free_ uint8_t *buf = ASSERT_NOT_NULL(malloc(CHUNK));

        ASSERT_OK_EQ_ERRNO(pread(fd, buf, CHUNK, offset), (ssize_t) CHUNK);
        if (zero)
                ASSERT_TRUE(memeqzero(buf, CHUNK));
        else
                ASSERT_EQ(memcmp(buf, data, CHUNK), 0);
}

static int holes_supported(void) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        fd = ASSERT_OK(open_tmpfile_unlinkable("/var/tmp", O_RDWR|O_CLOEXEC));

        r = RET_NERRNO(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 1));
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return false;
        ASSERT_OK(r);

        ASSERT_OK_ERRNO(fstat(fd, &st));
        return (size_t) st.st_blksize <= CHUNK;
}

static void send_complete(int fd) {
        send_coredump(fd, /* end= */ true);
}

TEST(complete) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        ASSERT_OK_ZERO(copy_from_socket(send_complete, UINT64_MAX, &fd));

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, (uint64_t) (5 * CHUNK));

        assert_chunk(fd, 0, /* zero= */ false);
        assert_chunk(fd, CHUNK, /* zero= */ true);
        assert_chunk(fd, 2 * CHUNK, /* zero= */ true);
        assert_chunk(fd, 3 * CHUNK, /* zero= */ false);
        assert_chunk(fd, 4 * CHUNK, /* zero= */ true);

        if (!holes_supported())
                return (void) log_tests_skipped("Filesystem doesn't support holes of the test's size");

        /* The zero records must not have been written. */
        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_HOLE), (off_t) CHUNK);
        ASSERT_OK_EQ_ERRNO(lseek(fd, CHUNK, SEEK_DATA), (off_t) (3 * CHUNK));
        ASSERT_OK_EQ_ERRNO(lseek(fd, 3 * CHUNK, SEEK_HOLE), (off_t) (4 * CHUNK));
        ASSERT_ERROR_ERRNO(lseek(fd, 4 * CHUNK, SEEK_DATA), ENXIO);
}

TEST(truncated) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        /* Cut off in the middle of the first zero record. */
        ASSERT_OK_EQ(copy_from_socket(send_complete, 2 * CHUNK, &fd), 1);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, (uint64_t) (2 * CHUNK));
        assert_chunk(fd, 0, /* zero= */ false);
        assert_chunk(fd, CHUNK, /* zero= */ true);
        fd = safe_close(fd);

        /* Cut off in the middle of the second data record. */
        ASSERT_OK_EQ(copy_from_socket(send_complete, 3 * CHUNK + CHUNK / 2, &fd), 1);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, (uint64_t) (3 * CHUNK + CHUNK / 2));
}

static void send_without_end(int fd) {
        send_coredump(fd, /* end= */ false);
}

TEST(incomplete) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        /* Without an end record the coredump is incomplete, but what arrived is kept. */
        ASSERT_OK_EQ(copy_from_socket(send_without_end, UINT64_MAX, &fd), 1);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, (uint64_t) (5 * CHUNK));
}

static void send_larger_header(int fd) {
        struct {
                struct coredump_record_header h;
                uint64_t unknown_field;
        } big = {
                .h.size = sizeof(big),
                .h.type = COREDUMP_RECORD_DATA,
                .h.len = CHUNK,
                .unknown_field = UINT64_MAX,
        };

        ASSERT_OK(loop_write(fd, &big, sizeof(big)));
        ASSERT_OK(loop_write(fd, data, CHUNK));
        send_record(fd, COREDUMP_RECORD_END, CHUNK, 0);
}

TEST(larger_header) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        /* A header from a newer kernel may be larger, the unknown fields are skipped. */
        ASSERT_OK_ZERO(copy_from_socket(send_larger_header, UINT64_MAX, &fd));
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, (uint64_t) CHUNK);
        assert_chunk(fd, 0, /* zero= */ false);
}

static void send_bad_offset(int fd) {
        send_record(fd, COREDUMP_RECORD_DATA, 0, CHUNK);
        send_record(fd, COREDUMP_RECORD_END, 2 * CHUNK, 0);
}

static void send_bad_type(int fd) {
        send_record(fd, COREDUMP_RECORD_ZERO + 1, 0, CHUNK);
}

static void send_bad_flags(int fd) {
        struct coredump_record_header h = {
                .size = sizeof(h),
                .type = COREDUMP_RECORD_ZERO,
                .flags = 1,
                .len = CHUNK,
        };

        ASSERT_OK(loop_write(fd, &h, sizeof(h)));
}

static void send_small_header(int fd) {
        struct coredump_record_header h = {
                .size = COREDUMP_RECORD_HEADER_SIZE_VER0 - 1,
        };

        ASSERT_OK(loop_write(fd, &h, sizeof(h)));
}

TEST(invalid) {
        ASSERT_ERROR(copy_from_socket(send_bad_offset, UINT64_MAX, NULL), EBADMSG);
        ASSERT_ERROR(copy_from_socket(send_bad_type, UINT64_MAX, NULL), EBADMSG);
        ASSERT_ERROR(copy_from_socket(send_bad_flags, UINT64_MAX, NULL), EBADMSG);
        ASSERT_ERROR(copy_from_socket(send_small_header, UINT64_MAX, NULL), EBADMSG);
}

static int intro(void) {
        memset(data, 'x', sizeof(data));
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);

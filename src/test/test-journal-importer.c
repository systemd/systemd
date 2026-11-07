/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-importer.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"

#define LINE_SZ (512U*1024U)

static void assert_iovec_entry(const struct iovec *iovec, const char* content) {
        ASSERT_MEMEQ_NN(content, strlen(content), iovec->iov_base, iovec->iov_len);
}

#define COREDUMP_PROC_GROUP                                             \
        "COREDUMP_PROC_CGROUP=1:name=systemd:/\n"                       \
        "0::/user.slice/user-1002.slice/user@1002.service/gnome-terminal-server.service\n"

TEST(basic_parsing) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-1);
        _cleanup_free_ char *journal_data_path = NULL;
        int r;

        ASSERT_OK(get_testdata_dir("journal-data/journal-1.txt", &journal_data_path));
        imp.fd = ASSERT_OK(xopenat(AT_FDCWD, journal_data_path, O_RDONLY));

        do
                r = journal_importer_process_data(&imp);
        while (r == 0 && !journal_importer_eof(&imp));
        ASSERT_OK_EQ(r, 1);

        /* We read one entry, so we should get EOF on next read, but not yet */
        ASSERT_FALSE(journal_importer_eof(&imp));

        ASSERT_EQ(imp.iovw.count, 6U);
        assert_iovec_entry(&imp.iovw.iovec[0], "_BOOT_ID=1531fd22ec84429e85ae888b12fadb91");
        assert_iovec_entry(&imp.iovw.iovec[1], "_TRANSPORT=journal");
        assert_iovec_entry(&imp.iovw.iovec[2], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[3], "COREDUMP_RLIMIT=-1");
        assert_iovec_entry(&imp.iovw.iovec[4], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[5], "_SOURCE_REALTIME_TIMESTAMP=1478389147837945");

        /* Let's check if we get EOF now */
        ASSERT_OK_ZERO(journal_importer_process_data(&imp));
        ASSERT_TRUE(journal_importer_eof(&imp));
}

TEST(bad_input) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-1);
        _cleanup_free_ char *journal_data_path = NULL;
        int r;

        ASSERT_OK(get_testdata_dir("journal-data/journal-1.txt", &journal_data_path));
        imp.fd = ASSERT_OK(xopenat(AT_FDCWD, journal_data_path, O_RDONLY));

        do
                r = journal_importer_process_data(&imp);
        while (!journal_importer_eof(&imp));
        ASSERT_OK_ZERO(r); /* If we don't have enough input, 0 is returned */

        ASSERT_TRUE(journal_importer_eof(&imp));
}

static int open_tmp(void) {
        char path[] = "/tmp/test-journal-importer.XXXXXX";
        int fd;

        fd = ASSERT_OK(mkostemp_safe(path));
        ASSERT_OK_ERRNO(unlink(path));

        return fd;
}

static void write_binary_field_header(int fd, const char *name, uint64_t size) {
        uint8_t hdr[sizeof(uint64_t)];

        /* A binary journal-export field is "<name>\n" followed by a little-endian 64-bit length, then the
         * payload, then a trailing "\n". This writes everything up to (but not including) the payload. */

        ASSERT_OK(loop_write(fd, name, strlen(name)));
        ASSERT_OK(loop_write(fd, "\n", 1));

        unaligned_write_le64(hdr, size);
        ASSERT_OK(loop_write(fd, hdr, sizeof hdr));
}

static void write_zeros(int fd, uint64_t size) {
        static const uint8_t zeros[64U*1024U] = {};

        while (size > 0) {
                size_t k = MIN(size, sizeof zeros);

                ASSERT_OK(loop_write(fd, zeros, k));
                size -= k;
        }
}

static int process_all(JournalImporter *imp) {
        int r;

        do
                r = journal_importer_process_data(imp);
        while (r == 0 && !journal_importer_eof(imp));

        return r;
}

TEST(entry_size_max) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-EBADF);
        _cleanup_close_ int fd = -EBADF;

        /* Craft a stream with two individually valid binary fields whose combined size exceeds
         * ENTRY_SIZE_MAX, and deliberately omit the terminating blank line. The importer must reject the
         * entry as soon as the second field's *declared* size pushes it over the limit, i.e. before
         * allocating and reading that field's payload. */

        fd = open_tmp();

        /* Large enough that one more DATA_SIZE_MAX-sized field tips us over ENTRY_SIZE_MAX. */
        uint64_t d1 = ENTRY_SIZE_MAX - DATA_SIZE_MAX + 1;
        ASSERT_LE(d1, (uint64_t) DATA_SIZE_MAX);

        write_binary_field_header(fd, "FIELDA", d1);
        write_zeros(fd, d1);
        ASSERT_OK(loop_write(fd, "\n", 1));

        /* Declares a DATA_SIZE_MAX payload that we never actually provide. */
        write_binary_field_header(fd, "FIELDB", DATA_SIZE_MAX);

        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        imp.fd = TAKE_FD(fd);

        ASSERT_ERROR(process_all(&imp), ENOBUFS);

        /* Only the first field should have made it into the iovec array. */
        ASSERT_EQ(imp.iovw.count, 1U);
}

TEST(entry_size_max_ignored_fields) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-EBADF);
        _cleanup_close_ int fd = -EBADF;

        /* Same as above, but the bulk of the entry is made up of fields the importer *discards* (dunder
         * lines). They never land in the iovec array, yet they do occupy the buffer until the entry is
         * terminated, so they have to be accounted for too - otherwise a client could pad an entry with
         * arbitrary junk and still get a full-sized binary field on top of it. */

        fd = open_tmp();

        _cleanup_free_ char *line = ASSERT_NOT_NULL(malloc(LINE_SZ));
        memset(line, 'x', LINE_SZ);
        memcpy(line, "__JUNK=", STRLEN("__JUNK="));
        line[LINE_SZ-1] = '\n';

        /* Comfortably more than ENTRY_SIZE_MAX - DATA_SIZE_MAX, so that the field below can't fit. */
        uint64_t junk = 0;
        while (junk < (uint64_t) (ENTRY_SIZE_MAX - DATA_SIZE_MAX) + LINE_SZ) {
                ASSERT_OK(loop_write(fd, line, LINE_SZ));
                junk += LINE_SZ;
        }

        write_binary_field_header(fd, "FIELDB", DATA_SIZE_MAX);

        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        imp.fd = TAKE_FD(fd);

        ASSERT_ERROR(process_all(&imp), ENOBUFS);

        /* Nothing was ever accepted, yet we still refused the entry. */
        ASSERT_EQ(imp.iovw.count, 0U);
}

TEST(entry_size_budget_is_per_entry) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-EBADF);
        _cleanup_close_ int fd = -EBADF;

        /* The budget has to be reset for every entry, otherwise a long-lived connection would eventually
         * start rejecting perfectly fine entries. Push a couple of complete entries through a single
         * importer and make sure they all make it. */

        fd = open_tmp();

        for (unsigned i = 0; i < 3; i++) {
                ASSERT_OK(loop_write(fd, "__CURSOR=ignored\n", STRLEN("__CURSOR=ignored\n")));
                ASSERT_OK(loop_write(fd, "MESSAGE=hello\n", STRLEN("MESSAGE=hello\n")));
                write_binary_field_header(fd, "BINARY", 4);
                ASSERT_OK(loop_write(fd, "data\n", 5));
                ASSERT_OK(loop_write(fd, "\n", 1));
        }

        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        imp.fd = TAKE_FD(fd);

        for (unsigned i = 0; i < 3; i++) {
                ASSERT_OK_POSITIVE(process_all(&imp));
                ASSERT_EQ(imp.iovw.count, 2U);
                assert_iovec_entry(&imp.iovw.iovec[0], "MESSAGE=hello");
                assert_iovec_entry(&imp.iovw.iovec[1], "BINARY=data");

                journal_importer_drop_iovw(&imp);
                ASSERT_EQ(imp.entry_offset, imp.offset);
        }

        ASSERT_OK_ZERO(process_all(&imp));
        ASSERT_TRUE(journal_importer_eof(&imp));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

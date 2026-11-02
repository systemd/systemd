/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "journal-importer.h"
#include "tests.h"

static void assert_iovec_entry(const struct iovec *iovec, const char* content) {
        ASSERT_EQ(strlen(content), iovec->iov_len);
        ASSERT_EQ(memcmp(content, iovec->iov_base, iovec->iov_len), 0);
}

#define COREDUMP_PROC_GROUP                                             \
        "COREDUMP_PROC_CGROUP=1:name=systemd:/\n"                       \
        "0::/user.slice/user-1002.slice/user@1002.service/gnome-terminal-server.service\n"

TEST(basic_parsing) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-1);
        _cleanup_free_ char *journal_data_path = NULL;
        int r;

        ASSERT_OK(get_testdata_dir("journal-data/journal-1.txt", &journal_data_path));
        imp.fd = ASSERT_OK_ERRNO(open(journal_data_path, O_RDONLY|O_CLOEXEC));

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
        imp.fd = ASSERT_OK_ERRNO(open(journal_data_path, O_RDONLY|O_CLOEXEC));

        do
                r = journal_importer_process_data(&imp);
        while (!journal_importer_eof(&imp));
        ASSERT_OK_ZERO(r); /* If we don't have enough input, 0 is returned */

        ASSERT_TRUE(journal_importer_eof(&imp));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

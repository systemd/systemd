/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "alloc-util.h"
#include "log.h"
#include "journal-importer.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"

static void assert_iovec_entry(const struct iovec *iovec, const char* content) {
        assert_se(strlen(content) == iovec->iov_len);
        assert_se(memcmp(content, iovec->iov_base, iovec->iov_len) == 0);
}

#define COREDUMP_PROC_GROUP                                             \
        "COREDUMP_PROC_CGROUP=1:name=systemd:/\n"                       \
        "0::/user.slice/user-1002.slice/user@1002.service/gnome-terminal-server.service\n"

TEST(basic_parsing) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-1);
        _cleanup_free_ char *journal_data_path = NULL;
        int r;

        assert_se(get_testdata_dir("journal-data/journal-1.txt", &journal_data_path) >= 0);
        imp.fd = open(journal_data_path, O_RDONLY|O_CLOEXEC);
        assert_se(imp.fd >= 0);

        do
                r = journal_importer_process_data(&imp);
        while (r == 0 && !journal_importer_eof(&imp));
        assert_se(r == 1);

        /* We read one entry, so we should get EOF on next read, but not yet */
        assert_se(!journal_importer_eof(&imp));

        assert_se(imp.iovw.count == 6);
        assert_iovec_entry(&imp.iovw.iovec[0], "_BOOT_ID=1531fd22ec84429e85ae888b12fadb91");
        assert_iovec_entry(&imp.iovw.iovec[1], "_TRANSPORT=journal");
        assert_iovec_entry(&imp.iovw.iovec[2], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[3], "COREDUMP_RLIMIT=-1");
        assert_iovec_entry(&imp.iovw.iovec[4], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[5], "_SOURCE_REALTIME_TIMESTAMP=1478389147837945");

        /* Let's check if we get EOF now */
        r = journal_importer_process_data(&imp);
        assert_se(r == 0);
        assert_se(journal_importer_eof(&imp));
}

TEST(bad_input) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = JOURNAL_IMPORTER_INIT(-1);
        _cleanup_free_ char *journal_data_path = NULL;
        int r;

        assert_se(get_testdata_dir("journal-data/journal-1.txt", &journal_data_path) >= 0);
        imp.fd = open(journal_data_path, O_RDONLY|O_CLOEXEC);
        assert_se(imp.fd >= 0);

        do
                r = journal_importer_process_data(&imp);
        while (!journal_importer_eof(&imp));
        assert_se(r == 0); /* If we don't have enough input, 0 is returned */

        assert_se(journal_importer_eof(&imp));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "journal-file.h"
#include "tests.h"

static void test_journal_file_parse_uid_from_filename_simple(
                const char *path,
                uid_t expected_uid,
                int expected_error) {

        uid_t uid = UID_INVALID;
        int r;

        log_info("testing %s", path);

        r = journal_file_parse_uid_from_filename(path, &uid);
        assert_se(r == expected_error);
        if (r < 0)
                assert_se(uid == UID_INVALID);
        else
                assert_se(uid == expected_uid);
}

TEST(journal_file_parse_uid_from_filename) {

        test_journal_file_parse_uid_from_filename_simple("/var/log/journal/", 0, -EISDIR);

        /* The helper should return -EREMOTE for any filenames that don't look like an online or offline user
         * journals. This includes archived and disposed journal files. */
        test_journal_file_parse_uid_from_filename_simple("/etc/password", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("system.journal", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@0005d26980bdce6e-2f2a4939583822ef.journal~", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@xxx-yyy-zzz.journal", 0, -EREMOTE);

        test_journal_file_parse_uid_from_filename_simple("user-1000.journal", 1000, 0);
        test_journal_file_parse_uid_from_filename_simple("user-foo.journal", 0, -EINVAL);
        test_journal_file_parse_uid_from_filename_simple("user-65535.journal", 0, -ENXIO);
}

DEFINE_TEST_MAIN(LOG_INFO);

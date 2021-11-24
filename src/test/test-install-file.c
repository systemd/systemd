/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fileio.h"
#include "install-file.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "umask-util.h"

TEST(install_file) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL;
        struct stat stat1, stat2;

        assert_se(mkdtemp_malloc(NULL, &p) >= 0);
        assert_se(a = path_join(p, "foo"));
        assert_se(b = path_join(p, "bar"));

        RUN_WITH_UMASK(0077)
                assert_se(write_string_file(a, "wups", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(lstat(a, &stat1) >= 0);
        assert_se(S_ISREG(stat1.st_mode));

        assert_se(install_file(AT_FDCWD, a, AT_FDCWD, b, 0) >= 0);
        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC) >= 0);

        assert_se(write_string_file(b, "ttss", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(install_file(AT_FDCWD, a, AT_FDCWD, b, INSTALL_FSYNC_FULL) == -EEXIST);
        assert_se(install_file(AT_FDCWD, a, AT_FDCWD, b, INSTALL_FSYNC_FULL|INSTALL_REPLACE) >= 0);

        assert_se(stat(b, &stat2) >= 0);
        assert_se(stat1.st_dev == stat2.st_dev);
        assert_se(stat1.st_ino == stat2.st_ino);
        assert_se((stat2.st_mode & 0222) != 0); /* writable */

        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE|INSTALL_READ_ONLY) >= 0);

        assert_se(stat(a, &stat2) >= 0);
        assert_se(stat1.st_dev == stat2.st_dev);
        assert_se(stat1.st_ino == stat2.st_ino);
        assert_se((stat2.st_mode & 0222) == 0); /* read-only */

        assert_se(mkdir(b, 0755) >= 0);
        assert_se(c = path_join(b, "dir"));
        assert_se(mkdir(c, 0755) >= 0);
        free(c);
        assert_se(c = path_join(b, "reg"));
        assert_se(mknod(c, S_IFREG|0755, 0) >= 0);
        free(c);
        assert_se(c = path_join(b, "fifo"));
        assert_se(mknod(c, S_IFIFO|0755, 0) >= 0);

        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL) == -EEXIST);
        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE) == 0);

        assert_se(write_string_file(b, "ttss", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL) == -EEXIST);
        assert_se(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);

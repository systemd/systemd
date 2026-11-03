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

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &p));
        ASSERT_NOT_NULL(a = path_join(p, "foo"));
        ASSERT_NOT_NULL(b = path_join(p, "bar"));

        WITH_UMASK(0077)
                ASSERT_OK(write_string_file(a, "wups", WRITE_STRING_FILE_CREATE));

        ASSERT_OK_ERRNO(lstat(a, &stat1));
        ASSERT_TRUE(S_ISREG(stat1.st_mode));

        ASSERT_OK(install_file(AT_FDCWD, a, AT_FDCWD, b, /* flags= */ 0));
        ASSERT_OK(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC));

        ASSERT_OK(write_string_file(b, "ttss", WRITE_STRING_FILE_CREATE));
        ASSERT_ERROR(install_file(AT_FDCWD, a, AT_FDCWD, b, INSTALL_FSYNC_FULL), EEXIST);
        ASSERT_OK(install_file(AT_FDCWD, a, AT_FDCWD, b, INSTALL_FSYNC_FULL|INSTALL_REPLACE));

        ASSERT_OK_ERRNO(stat(b, &stat2));
        ASSERT_EQ(stat1.st_dev, stat2.st_dev);
        ASSERT_EQ(stat1.st_ino, stat2.st_ino);
        ASSERT_NE(stat2.st_mode & 0222, 0U); /* writable */

        ASSERT_OK(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE|INSTALL_READ_ONLY));

        ASSERT_OK_ERRNO(stat(a, &stat2));
        ASSERT_EQ(stat1.st_dev, stat2.st_dev);
        ASSERT_EQ(stat1.st_ino, stat2.st_ino);
        ASSERT_EQ(stat2.st_mode & 0222, 0U); /* read-only */

        ASSERT_OK_ERRNO(mkdir(b, 0755));
        ASSERT_NOT_NULL(c = path_join(b, "dir"));
        ASSERT_OK_ERRNO(mkdir(c, 0755));
        free(c);
        ASSERT_NOT_NULL(c = path_join(b, "reg"));
        ASSERT_OK_ERRNO(mknod(c, S_IFREG|0755, 0));
        free(c);
        ASSERT_NOT_NULL(c = path_join(b, "fifo"));
        ASSERT_OK_ERRNO(mknod(c, S_IFIFO|0755, 0));

        ASSERT_ERROR(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL), EEXIST);
        ASSERT_OK_ZERO(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE));

        ASSERT_OK(write_string_file(b, "ttss", WRITE_STRING_FILE_CREATE));

        ASSERT_ERROR(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL), EEXIST);
        ASSERT_OK_ZERO(install_file(AT_FDCWD, b, AT_FDCWD, a, INSTALL_FSYNC_FULL|INSTALL_REPLACE));
}

DEFINE_TEST_MAIN(LOG_INFO);

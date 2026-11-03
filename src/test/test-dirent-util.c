/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "dirent-util.h"
#include "errno-util.h"
#include "fs-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(test_dirent_ensure_type) {
        int dir_fd;
        static struct dirent de = {
                .d_type = DT_UNKNOWN,
                .d_name = "test",
        };

        dir_fd = 0;
        ASSERT_ERROR(dirent_ensure_type(dir_fd, &de), ENOTDIR);

        /* Test when d_name is "." or ".." */
        strcpy(de.d_name, ".");
        ASSERT_OK_ZERO(dirent_ensure_type(dir_fd, &de));
        ASSERT_EQ(de.d_type, DT_DIR);

        strcpy(de.d_name, "..");
        ASSERT_OK_ZERO(dirent_ensure_type(dir_fd, &de));
        ASSERT_EQ(de.d_type, DT_DIR);
}

TEST(test_dirent_is_file) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        const char *name, *dotfile, *name_alias, *bakfile, *tilda;
        const struct dirent *de_reg, *de_lnk, *de_dot, *de_bak, *de_tilda;
        DIR *dir;

        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        name = strjoina(t, "/test.txt");
        dotfile = strjoina(t, "/.hidden_file");
        bakfile = strjoina(t, "/test.bak");
        tilda = strjoina(t, "/test~");
        name_alias = strjoina(t, "/test_link");

        ASSERT_OK(touch(name));
        ASSERT_OK(touch(dotfile));
        ASSERT_OK(touch(bakfile));
        ASSERT_OK(touch(tilda));

        if (symlink(name, name_alias) < 0) {
                ASSERT_TRUE(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
        }

        dir = opendir(t);
        if (!dir) {
                log_error_errno(errno, "Failed to open directory '%s': %m", t);
                exit(EXIT_FAILURE);
        }

        rewinddir(dir);
        while ((de_reg = readdir_ensure_type(dir)))
                if (streq(de_reg->d_name, "test.txt"))
                        break;

        rewinddir(dir);
        while ((de_lnk = readdir_ensure_type(dir)))
                if (streq(de_lnk->d_name, "test_link"))
                        break;

        rewinddir(dir);
        while ((de_dot = readdir_ensure_type(dir)))
                if (streq(de_dot->d_name, ".hidden_file"))
                        break;

        rewinddir(dir);
        while ((de_bak = readdir(dir)))
                if (streq(de_bak->d_name, "test.bak"))
                        break;

        rewinddir(dir);
        while ((de_tilda = readdir(dir)))
                if (streq(de_tilda->d_name, "test~"))
                        break;

        /* Test when d_type is DT_REG, DT_LNK, or DT_UNKNOWN */
        ASSERT_TRUE(dirent_is_file(de_reg));
        if (de_lnk)
                ASSERT_TRUE(dirent_is_file(de_lnk));
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        ASSERT_TRUE(dirent_is_file(&de_unknown));

        /* Test for hidden files */
        ASSERT_FALSE(dirent_is_file(de_dot));
        ASSERT_FALSE(dirent_is_file(de_bak));
        ASSERT_FALSE(dirent_is_file(de_tilda));

        closedir(dir);
}

TEST(test_dirent_is_file_with_suffix) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        const char *name, *dotfile, *name_alias, *dotdot, *chr;
        const struct dirent *de_reg, *de_lnk, *de_dot, *de_dotdot, *de_chr;
        DIR *dir;

        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        name = strjoina(t, "/test.txt");
        dotfile = strjoina(t, "/.hidden_file");
        dotdot = strjoina(t, "/..dotdot");
        chr = strjoina(t, "/test_chr");
        name_alias = strjoina(t, "/test_link");

        ASSERT_OK(touch(name));
        ASSERT_OK(touch(dotfile));
        ASSERT_OK(touch(dotdot));
        /* This can fail in containers/build systems */
        if (mknod(chr, 0775 | S_IFCHR, makedev(0, 0)) < 0) {
                assert(ERRNO_IS_PRIVILEGE(errno));
                chr = NULL;
        }

        if (symlink(name, name_alias) < 0) {
                ASSERT_TRUE(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
        }

        dir = opendir(t);
        if (!dir) {
                log_error_errno(errno, "Failed to open directory '%s': %m", t);
                exit(EXIT_FAILURE);
        }

        rewinddir(dir);
        while ((de_reg = readdir_ensure_type(dir)))
                if (streq(de_reg->d_name, "test.txt"))
                        break;

        rewinddir(dir);
        while ((de_lnk = readdir_ensure_type(dir)))
                if (streq(de_lnk->d_name, "test_link"))
                        break;

        rewinddir(dir);
        while ((de_dot = readdir_ensure_type(dir)))
                if (streq(de_dot->d_name, ".hidden_file"))
                        break;

        rewinddir(dir);
        while ((de_dotdot = readdir(dir)))
                if (streq(de_dotdot->d_name, "..dotdot"))
                        break;

        if (chr) {
                rewinddir(dir);
                while ((de_chr = readdir(dir)))
                        if (streq(de_chr->d_name, "test_chr"))
                                break;

                /* Test when d_type is not DT_REG, DT_LNK, or DT_UNKNOWN */
                assert(de_chr);
                ASSERT_FALSE(dirent_is_file_with_suffix(de_chr, /* suffix= */ NULL));
        }

        /* Test when suffix is NULL */
        ASSERT_TRUE(dirent_is_file_with_suffix(de_reg, /* suffix= */ NULL));
        if (de_lnk)
                ASSERT_TRUE(dirent_is_file_with_suffix(de_lnk, /* suffix= */ NULL));
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        ASSERT_TRUE(dirent_is_file_with_suffix(&de_unknown, /* suffix= */ NULL));

        /* Test for present suffix */
        ASSERT_TRUE(dirent_is_file_with_suffix(de_reg, "txt"));
        if (de_lnk)
                ASSERT_TRUE(dirent_is_file_with_suffix(de_lnk, "link"));
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        ASSERT_TRUE(dirent_is_file_with_suffix(&de_unknown, "unknown"));

        /* Test for absent suffix */
        ASSERT_FALSE(dirent_is_file_with_suffix(de_reg, "svg"));
        if (de_lnk)
                ASSERT_FALSE(dirent_is_file_with_suffix(de_lnk, "pdf"));
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        ASSERT_FALSE(dirent_is_file_with_suffix(&de_unknown, "yes"));

        /* Test for dot and dot-dot */
        ASSERT_FALSE(dirent_is_file_with_suffix(de_dot, /* suffix= */ NULL));
        ASSERT_FALSE(dirent_is_file_with_suffix(de_dotdot, /* suffix= */ NULL));

        closedir(dir);
}

DEFINE_TEST_MAIN(LOG_INFO);

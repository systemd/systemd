/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "tests.h"

TEST (test_dirent_ensure_type) {
        int r, dir_fd;
        static struct dirent de = {
                .d_type = DT_UNKNOWN,
                .d_name = "test",
        };

        dir_fd = 0;
        assert_se(dirent_ensure_type(dir_fd, &de) == -ENOTDIR);

        /* Test when d_name is "." or ".." */
        strcpy(de.d_name, ".");
        r = dirent_ensure_type(dir_fd, &de);
        assert_se(r == 0);
        assert_se(de.d_type == DT_DIR);

        strcpy(de.d_name, "..");
        r = dirent_ensure_type(dir_fd, &de);
        assert_se(r == 0);
        assert_se(de.d_type == DT_DIR);
}

TEST (test_dirent_is_file) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        const char *name, *dotfile, *name_alias, *bakfile, *tilda;
        const struct dirent *de_reg, *de_lnk, *de_dot, *de_bak, *de_tilda;
        DIR *dir;

        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        name = strjoina(t, "/test.txt");
        dotfile = strjoina(t, "/.hidden_file");
        bakfile = strjoina(t, "/test.bak");
        tilda = strjoina(t, "/test~");
        name_alias = strjoina(t, "/test_link");

        assert_se(touch(name) >= 0);
        assert_se(touch(dotfile) >= 0);
        assert_se(touch(bakfile) >= 0);
        assert_se(touch(tilda) >= 0);

        if (symlink(name, name_alias) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
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
        assert_se(dirent_is_file(de_reg) == true);
        if (de_lnk)
                assert_se(dirent_is_file(de_lnk) == true);
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        assert_se(dirent_is_file(&de_unknown) == true);

        /* Test for hidden files */
        assert_se(dirent_is_file(de_dot) == false);
        assert_se(dirent_is_file(de_bak) == false);
        assert_se(dirent_is_file(de_tilda) == false);

        closedir(dir);
}

TEST (test_dirent_is_file_with_suffix) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        const char *name, *dotfile, *name_alias, *dotdot, *chr;
        const struct dirent *de_reg, *de_lnk, *de_dot, *de_dotdot, *de_chr;
        DIR *dir;

        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        name = strjoina(t, "/test.txt");
        dotfile = strjoina(t, "/.hidden_file");
        dotdot = strjoina(t, "/..dotdot");
        chr = strjoina(t, "/test_chr");
        name_alias = strjoina(t, "/test_link");

        assert_se(touch(name) >= 0);
        assert_se(touch(dotfile) >= 0);
        assert_se(touch(dotdot) >= 0);
        /* This can fail in containers/build systems */
        if (mknod(chr, 0775 | S_IFCHR, makedev(0, 0)) < 0) {
                assert(ERRNO_IS_PRIVILEGE(errno));
                chr = NULL;
        }

        if (symlink(name, name_alias) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
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
                assert_se(!dirent_is_file_with_suffix(de_chr, NULL));
        }

        /* Test when suffix is NULL */
        assert_se(dirent_is_file_with_suffix(de_reg, NULL) == true);
        if (de_lnk)
                assert_se(dirent_is_file_with_suffix(de_lnk, NULL) == true);
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        assert_se(dirent_is_file_with_suffix(&de_unknown, NULL) == true);

        /* Test for present suffix */
        assert_se(dirent_is_file_with_suffix(de_reg, "txt") == true);
        if (de_lnk)
                assert_se(dirent_is_file_with_suffix(de_lnk, "link") == true);
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        assert_se(dirent_is_file_with_suffix(&de_unknown, "unknown") == true);

        /* Test for absent suffix */
        assert_se(dirent_is_file_with_suffix(de_reg, "svg") == false);
        if (de_lnk)
                assert_se(dirent_is_file_with_suffix(de_lnk, "pdf") == false);
        else
                log_tests_skipped("de_lnk is NULL, skipping test");
        assert_se(dirent_is_file_with_suffix(&de_unknown, "yes") == false);

        /* Test for dot and dot-dot */
        assert_se(dirent_is_file_with_suffix(de_dot, NULL) == false);
        assert_se(dirent_is_file_with_suffix(de_dotdot, NULL) == false);

        closedir(dir);
}

DEFINE_TEST_MAIN(LOG_INFO);

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
#include "tests.h"



TEST (test_dirent_ensure_type) {
        int result;
        static struct dirent de = {
                .d_type = DT_UNKNOWN,
                .d_name = "test",
        };

        assert_se(de.d_type == DT_UNKNOWN);
        int dir_fd;

        dir_fd = 0;
        dirent_ensure_type(dir_fd, &de);

        /* Test when d_name is "." or ".." */
        strcpy(de.d_name, ".");
        result = dirent_ensure_type(dir_fd, &de);
        assert_se(result == 0);
        assert_se(de.d_type == DT_DIR);

        strcpy(de.d_name, "..");
        result = dirent_ensure_type(dir_fd, &de);
        assert_se(result == 0);
        assert_se(de.d_type == DT_DIR);
}

TEST (test_dirent_is_file) {
        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        static const char *arg_test_dir = NULL;

        const char *tempdir, *name, *dotfile, *name_alias, *bakfile, *tilda;
        DIR *dir;

        tempdir = strjoina(arg_test_dir ?: "/tmp", "/test-dirent_is_file");
        name = strjoina(tempdir, "/test.txt");
        dotfile = strjoina(tempdir, "/.hidden_file");
        bakfile = strjoina(tempdir, "/test.bak");
        tilda = strjoina(tempdir, "/test~");
        name_alias = strjoina(arg_test_dir ?: "/tmp", "/test-dirent_is_file/test_link");

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid(), MKDIR_WARN_MODE) >= 0);
        assert_se(touch(name) >= 0);
        assert_se(touch(dotfile) >= 0);
        assert_se(touch(bakfile) >= 0);
        assert_se(touch(tilda) >= 0);


        if (symlink(name, name_alias) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");}

        dir = opendir(tempdir);
        if (dir == NULL) {
                perror("opendir");
                exit(EXIT_FAILURE);
        }

        const struct dirent *de_reg, *de_lnk, *de_dot, *de_bak, *de_tilda;
        rewinddir(dir);
        while ((de_reg = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_reg->d_name, "test.txt") == 0) break;
        }

        rewinddir(dir);
        while ((de_lnk = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_lnk->d_name, "test_link") == 0) break;
        }

        rewinddir(dir);
        while ((de_dot = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_dot->d_name, ".hidden_file") == 0) break;
        }

        rewinddir(dir);
        while ((de_bak = readdir(dir)) != NULL) {
                if (strcmp(de_bak->d_name, "test.bak") == 0) break;
        }

        rewinddir(dir);
        while ((de_tilda = readdir(dir)) != NULL) {
                if (strcmp(de_tilda->d_name, "test~") == 0) break;
        }

        /* Test when d_type is DT_REG, DT_LNK, or DT_UNKNOWN */
        assert_se(dirent_is_file(de_reg) == true);
        assert_se(dirent_is_file(de_lnk) == true);
        assert_se(dirent_is_file(&de_unknown) == true);


        /* Test for hidden files */
        assert_se(dirent_is_file(de_dot) == false);
        assert_se(dirent_is_file(de_bak) == false);
        assert_se(dirent_is_file(de_tilda) == false);

        closedir(dir);
        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

TEST (test_dirent_is_file_with_suffix) {
        static const struct dirent de_unknown = {
                .d_type = DT_UNKNOWN,
                .d_name = "test_unknown",
        };

        static const char *arg_test_dir = NULL;

        const char *tempdir, *name, *dotfile, *name_alias, *dotdot, *chr;
        DIR *dir;

        tempdir = strjoina(arg_test_dir ?: "/tmp", "/test-dirent_is_file");
        name = strjoina(tempdir, "/test.txt");
        dotfile = strjoina(tempdir, "/.hidden_file");
        dotdot = strjoina(tempdir, "/..dotdot");
        chr = strjoina(tempdir, "/test_chr");
        name_alias = strjoina(arg_test_dir ?: "/tmp", "/test-dirent_is_file/test_link");

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid(), MKDIR_WARN_MODE) >= 0);
        assert_se(touch(name) >= 0);
        assert_se(touch(dotfile) >= 0);
        assert_se(touch(dotdot) >= 0);
        assert_se(mknod(chr, 0775 | S_IFCHR, makedev(0, 0)) >= 0);


        if (symlink(name, name_alias) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");}

        dir = opendir(tempdir);
        if (dir == NULL) {
                perror("opendir");
                exit(EXIT_FAILURE);
        }

        const struct dirent *de_reg, *de_lnk, *de_dot, *de_dotdot, *de_chr;
        rewinddir(dir);
        while ((de_reg = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_reg->d_name, "test.txt") == 0) break;
        }

        rewinddir(dir);
        while ((de_lnk = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_lnk->d_name, "test_link") == 0) break;
        }

        rewinddir(dir);
        while ((de_dot = readdir_ensure_type(dir)) != NULL) {
                if (strcmp(de_dot->d_name, ".hidden_file") == 0) break;
        }

        rewinddir(dir);
        while ((de_dotdot = readdir(dir)) != NULL) {
                if (strcmp(de_dotdot->d_name, "..dotdot") == 0) break;
        }

        rewinddir(dir);
        while ((de_chr = readdir(dir)) != NULL) {
                if (strcmp(de_chr->d_name, "test_chr") == 0) break;
        }

        /* Test when d_type is not DT_REG, DT_LNK, or DT_UNKNOWN */
        assert_se(!dirent_is_file_with_suffix(de_chr, NULL));

        /* Test when suffix is NULL */
        assert_se(dirent_is_file_with_suffix(de_reg, NULL) == true);
        assert_se(dirent_is_file_with_suffix(de_lnk, NULL) == true);
        assert_se(dirent_is_file_with_suffix(&de_unknown, NULL) == true);

        /* Test for present suffix */
        assert_se(dirent_is_file_with_suffix(de_reg, "txt") == true);
        assert_se(dirent_is_file_with_suffix(de_lnk, "link") == true);
        assert_se(dirent_is_file_with_suffix(&de_unknown, "unknown") == true);

        /* Test for absent suffix */
        assert_se(dirent_is_file_with_suffix(de_reg, "svg") == false);
        assert_se(dirent_is_file_with_suffix(de_lnk, "pdf") == false);
        assert_se(dirent_is_file_with_suffix(&de_unknown, "yes") == false);

        /* Test for dot and dot-dot */
        assert_se(dirent_is_file_with_suffix(de_dot, NULL) == false);
        assert_se(dirent_is_file_with_suffix(de_dotdot, NULL) == false);

        closedir(dir);
        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

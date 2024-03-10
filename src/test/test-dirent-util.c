/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"

static void test_dirent_ensure_type(void) {
        struct dirent de;
        int result;

        de.d_type = DT_UNKNOWN;
        strcpy(de.d_name, "test");
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

static void test_dirent_is_file(void) {
        /* Test when d_type is DT_REG, DT_LNK, or DT_UNKNOWN */
        struct dirent de_reg, de_lnk, de_unknown;

        de_reg.d_type = DT_REG;
        strcpy(de_reg.d_name, "test.txt");

        de_lnk.d_type = DT_LNK;
        strcpy(de_lnk.d_name, "test_link");

        de_unknown.d_type = DT_UNKNOWN;
        strcpy(de_unknown.d_name, "test_unknown");

        assert_se(dirent_is_file(&de_reg) == true);
        assert_se(dirent_is_file(&de_lnk) == true);
        assert_se(dirent_is_file(&de_unknown) == true);

        /* Test hidden or backup file "." */
        struct dirent de_dot;

        de_dot.d_type = DT_REG;
        strcpy(de_dot.d_name, ".hidden_file");
        assert_se(dirent_is_file(&de_dot) == false);

        strcpy(de_dot.d_name, "test.bak");
        assert_se(dirent_is_file(&de_dot) == false);

        strcpy(de_dot.d_name, "test~");
        assert_se(dirent_is_file(&de_dot) == false);
}

static void test_dirent_is_file_with_suffix(void) {
        struct dirent de_reg, de_lnk, de_unknown, de_chr;

        de_reg.d_type = DT_REG;
        strcpy(de_reg.d_name, "test.txt");

        de_lnk.d_type = DT_LNK;
        strcpy(de_lnk.d_name, "test_link");

        de_unknown.d_type = DT_UNKNOWN;
        strcpy(de_unknown.d_name, "test_unknown");

        de_chr.d_type = DT_CHR;

        /* Test when d_type is DT_REG, DT_LNK, or DT_UNKNOWN */
        assert_se(!dirent_is_file_with_suffix(&de_chr, NULL));

        /* Test when suffix is NULL */
        assert_se(dirent_is_file_with_suffix(&de_reg, NULL) == true);
        assert_se(dirent_is_file_with_suffix(&de_lnk, NULL) == true);
        assert_se(dirent_is_file_with_suffix(&de_unknown, NULL) == true);

        /* Test for present suffix */
        assert_se(dirent_is_file_with_suffix(&de_reg, "txt") == true);
        assert_se(dirent_is_file_with_suffix(&de_lnk, "link") == true);
        assert_se(dirent_is_file_with_suffix(&de_unknown, "unknown") == true);

        /* Test for absent suffix */
        assert_se(dirent_is_file_with_suffix(&de_reg, "svg") == false);
        assert_se(dirent_is_file_with_suffix(&de_lnk, "pdf") == false);
        assert_se(dirent_is_file_with_suffix(&de_unknown, "yes") == false);

        /* Test for dot and dot-dot */
        strcpy(de_reg.d_name, ".");
        assert_se(dirent_is_file_with_suffix(&de_reg, NULL) == false);

        strcpy(de_reg.d_name, "..");
        assert_se(dirent_is_file_with_suffix(&de_reg, NULL) == false);
}

TEST (dirent_util) {
        test_dirent_is_file();
        test_dirent_ensure_type();
        test_dirent_is_file_with_suffix();
}

DEFINE_TEST_MAIN(LOG_DEBUG);

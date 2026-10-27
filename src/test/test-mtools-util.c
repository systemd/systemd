/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "mkfs-util.h"
#include "mtools-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static int mtype(const char *node, const char *path, char **ret) {
        _cleanup_free_ char *cmd = NULL;

        /* Reads a file from the image with mtools, so that we verify what we wrote independently */

        ASSERT_OK(asprintf(&cmd, "mtype -i '%s' '::%s'", node, path));

        _cleanup_pclose_ FILE *f = popen(cmd, "r");
        if (!f)
                return -errno;

        _cleanup_free_ char *contents = NULL;
        ASSERT_OK(read_full_stream_full(f, NULL, UINT64_MAX, SIZE_MAX, 0, &contents, NULL));

        *ret = TAKE_PTR(contents);
        return 0;
}

TEST_RET(mtools_util) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *image = NULL, *node = NULL, *tree = NULL, *source = NULL, *contents = NULL;
        int r;

        FOREACH_STRING(t, "mcopy", "mmd", "mtype") {
                r = find_executable(t, NULL);
                if (r < 0)
                        return log_tests_skipped_errno(r, "Could not find %s binary: %m", t);
        }

        r = mkfs_exists("vfat");
        if (r < 0)
                return log_tests_skipped_errno(r, "Could not determine if mkfs.vfat exists: %m");
        if (r == 0)
                return log_tests_skipped("mkfs.vfat not available");

        ASSERT_OK(mkdtemp_malloc(NULL, &d));

        /* An image with the FAT file system at an offset, so that the "@@" syntax is exercised too */
        ASSERT_NOT_NULL(image = path_join(d, "image.raw"));
        _cleanup_close_ int fd = open(image, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        ASSERT_OK_ERRNO(fd);
        ASSERT_OK_ERRNO(ftruncate(fd, 1024 * 1024 + 4 * 1024 * 1024));

        _cleanup_free_ char *mkfs_cmd = NULL;
        ASSERT_OK(asprintf(&mkfs_cmd, "mkfs.vfat --offset 2048 '%s' 4096 >/dev/null", image));
        ASSERT_OK_ZERO_ERRNO(system(mkfs_cmd));

        ASSERT_NOT_NULL(node = strjoin(image, "@@1048576"));

        /* Nested directories, created twice to check that existing ones are tolerated */
        ASSERT_OK(mtools_mkdir(node, "loader/addons"));
        ASSERT_OK(mtools_mkdir(node, "loader/addons"));

        ASSERT_NOT_NULL(source = path_join(d, "source.txt"));
        ASSERT_OK(write_string_file(source, "first", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(mtools_copy_file(node, source, "loader/addons/file.txt"));
        ASSERT_OK(mtype(node, "loader/addons/file.txt", &contents));
        ASSERT_STREQ(contents, "first");

        /* Copying again replaces the file */
        ASSERT_OK(write_string_file(source, "second", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(mtools_copy_file(node, source, "loader/addons/file.txt"));
        contents = mfree(contents);
        ASSERT_OK(mtype(node, "loader/addons/file.txt", &contents));
        ASSERT_STREQ(contents, "second");

        /* A whole tree */
        ASSERT_NOT_NULL(tree = path_join(d, "tree"));
        ASSERT_OK(mkdir_p(tree, 0755));
        _cleanup_free_ char *sub = path_join(tree, "sub");
        ASSERT_NOT_NULL(sub);
        ASSERT_OK(mkdir_p(sub, 0755));
        _cleanup_free_ char *a = path_join(tree, "a.txt"), *b = path_join(sub, "b.txt");
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);
        ASSERT_OK(write_string_file(a, "aaa", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(write_string_file(b, "bbb", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(mtools_copy_tree(node, tree));

        contents = mfree(contents);
        ASSERT_OK(mtype(node, "a.txt", &contents));
        ASSERT_STREQ(contents, "aaa");
        contents = mfree(contents);
        ASSERT_OK(mtype(node, "sub/b.txt", &contents));
        ASSERT_STREQ(contents, "bbb");

        return 0;
}

DEFINE_TEST_MAIN(LOG_DEBUG);

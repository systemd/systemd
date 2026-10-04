/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dropin.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

#define WRITE_EMPTY_FILE (WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE)

static void test_classify_one(
                const char *root,
                const char *dir,
                const char *entry,
                DependencyEntryType expected) {

        _cleanup_free_ char *path = NULL, *name = NULL;
        DependencyEntryType type;

        ASSERT_NOT_NULL(path = path_join(dir, entry));
        ASSERT_OK(unit_file_classify_dependency_entry(path, root, &type, &name));
        ASSERT_EQ(type, expected);
        ASSERT_STREQ(name, entry);
}

TEST(unit_file_classify_dependency_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_free_ char *wants = NULL, *missing = NULL;
        _cleanup_close_ int root_fd = -EBADF, wants_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-dropin-XXXXXX", &root));
        ASSERT_OK_ERRNO(root_fd = open(root, O_DIRECTORY|O_CLOEXEC));

        ASSERT_NOT_NULL(wants = path_join(root, "/etc/systemd/system/multi-user.target.wants"));
        ASSERT_OK(mkdir_p(wants, 0755));
        ASSERT_OK_ERRNO(wants_fd = open(wants, O_DIRECTORY|O_CLOEXEC));

        ASSERT_OK(write_string_file_at(root_fd, "etc/systemd/system/foo.service", "[Unit]",
                                       WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(root_fd, "etc/empty", "", WRITE_EMPTY_FILE));

        ASSERT_OK_ERRNO(symlinkat("../foo.service", wants_fd, "foo.service"));
        /* The root has no /dev/null, so the symlink to /dev/null dangles. */
        ASSERT_OK_ERRNO(symlinkat("/dev/null", wants_fd, "null.service"));
        ASSERT_OK_ERRNO(symlinkat("/etc/empty", wants_fd, "to-empty.service"));
        ASSERT_OK(write_string_file_at(wants_fd, "empty.service", "", WRITE_EMPTY_FILE));
        ASSERT_OK(write_string_file_at(wants_fd, "file.service", "x", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("../foo.service", wants_fd, "not-a-unit"));
        /* PID 1 cannot resolve a symlink loop. PID 1 therefore does not treat the loop as a mask. */
        ASSERT_OK_ERRNO(symlinkat("loop.service", wants_fd, "loop.service"));

        test_classify_one(root, wants, "foo.service", DEPENDENCY_ENTRY_SYMLINK);
        test_classify_one(root, wants, "null.service", DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, wants, "to-empty.service", DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, wants, "empty.service", DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, wants, "file.service", DEPENDENCY_ENTRY_NOT_SYMLINK);
        test_classify_one(root, wants, "not-a-unit", DEPENDENCY_ENTRY_INVALID_NAME);
        test_classify_one(root, wants, "loop.service", DEPENDENCY_ENTRY_SYMLINK);

        ASSERT_NOT_NULL(missing = path_join(wants, "missing.service"));
        ASSERT_ERROR(unit_file_classify_dependency_entry(missing, root, &(DependencyEntryType) {}, NULL),
                     ENOENT);
}

TEST(unit_file_find_dropin_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **lookup_path = NULL, **paths = NULL;
        _cleanup_free_ char *high = NULL, *low = NULL, *high_wants = NULL, *low_wants = NULL, *found = NULL;
        _cleanup_close_ int high_fd = -EBADF, low_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-dropin-XXXXXX", &root));

        ASSERT_NOT_NULL(high = path_join(root, "/etc/systemd/system"));
        ASSERT_NOT_NULL(low = path_join(root, "/usr/lib/systemd/system"));
        ASSERT_NOT_NULL(lookup_path = strv_new(high, low));

        ASSERT_NOT_NULL(high_wants = path_join(high, "multi-user.target.wants"));
        ASSERT_NOT_NULL(low_wants = path_join(low, "multi-user.target.wants"));
        ASSERT_OK(mkdir_p(high_wants, 0755));
        ASSERT_OK(mkdir_p(low_wants, 0755));
        ASSERT_OK_ERRNO(high_fd = open(high_wants, O_DIRECTORY|O_CLOEXEC));
        ASSERT_OK_ERRNO(low_fd = open(low_wants, O_DIRECTORY|O_CLOEXEC));

        ASSERT_OK_ERRNO(symlinkat("../foo.service", high_fd, "foo.service"));
        ASSERT_OK_ERRNO(symlinkat("../foo.service", low_fd, "foo.service"));
        ASSERT_OK_ERRNO(symlinkat("../bar.service", low_fd, "bar.service"));
        /* conf_files_list_strv() skips an entry that it cannot resolve. It returns the entry with the same
         * name in the lower directory instead. */
        ASSERT_OK_ERRNO(symlinkat("loop.service", high_fd, "loop.service"));
        ASSERT_OK_ERRNO(symlinkat("../loop.service", low_fd, "loop.service"));

        ASSERT_OK_POSITIVE(unit_file_find_dropin_paths(root, lookup_path, /* unit_path_cache= */ NULL,
                                                       ".wants", /* file_suffix= */ NULL,
                                                       "multi-user.target", /* aliases= */ NULL, &paths));

        FOREACH_STRING(entry, "foo.service", "bar.service", "loop.service") {
                ASSERT_OK_POSITIVE(unit_file_find_dropin_entry(root, lookup_path, ".wants", "multi-user.target",
                                                               /* aliases= */ NULL, entry, &found));
                ASSERT_TRUE(strv_contains(paths, found));
                ASSERT_TRUE(path_equal_filename(found, entry));
                found = mfree(found);
        }

        ASSERT_OK_ZERO(unit_file_find_dropin_entry(root, lookup_path, ".wants", "multi-user.target",
                                                   /* aliases= */ NULL, "missing.service", &found));
        ASSERT_NULL(found);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

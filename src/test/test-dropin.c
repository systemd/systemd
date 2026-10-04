/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "dropin.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_classify_one(const char *root, const char *path, DependencyEntryType expected) {
        _cleanup_free_ char *name = NULL;
        DependencyEntryType type;

        ASSERT_OK(unit_file_classify_dependency_entry(path, root, &type, &name));
        ASSERT_EQ(type, expected);
        ASSERT_NOT_NULL(name);
}

TEST(unit_file_classify_dependency_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        const char *wants;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-dropin-XXXXXX", &root));

        wants = strjoina(root, "/etc/systemd/system/multi-user.target.wants");
        ASSERT_OK(mkdir_p(wants, 0755));

        ASSERT_OK(write_string_file(strjoina(root, "/etc/systemd/system/foo.service"), "[Unit]",
                                    WRITE_STRING_FILE_CREATE));
        ASSERT_OK(touch(strjoina(root, "/etc/empty")));

        ASSERT_OK_ERRNO(symlink("../foo.service", strjoina(wants, "/foo.service")));
        /* The root has no /dev/null, so the symlink to /dev/null dangles. */
        ASSERT_OK_ERRNO(symlink("/dev/null", strjoina(wants, "/null.service")));
        ASSERT_OK_ERRNO(symlink("/etc/empty", strjoina(wants, "/to-empty.service")));
        ASSERT_OK(touch(strjoina(wants, "/empty.service")));
        ASSERT_OK(write_string_file(strjoina(wants, "/file.service"), "x", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlink("../foo.service", strjoina(wants, "/not-a-unit")));
        /* PID 1 cannot resolve a symlink loop. PID 1 therefore does not treat the loop as a mask. */
        ASSERT_OK_ERRNO(symlink("loop.service", strjoina(wants, "/loop.service")));

        test_classify_one(root, strjoina(wants, "/foo.service"), DEPENDENCY_ENTRY_SYMLINK);
        test_classify_one(root, strjoina(wants, "/null.service"), DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, strjoina(wants, "/to-empty.service"), DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, strjoina(wants, "/empty.service"), DEPENDENCY_ENTRY_MASK);
        test_classify_one(root, strjoina(wants, "/file.service"), DEPENDENCY_ENTRY_NOT_SYMLINK);
        test_classify_one(root, strjoina(wants, "/not-a-unit"), DEPENDENCY_ENTRY_INVALID_NAME);
        test_classify_one(root, strjoina(wants, "/loop.service"), DEPENDENCY_ENTRY_SYMLINK);

        ASSERT_ERROR(unit_file_classify_dependency_entry(strjoina(wants, "/missing.service"), root,
                                                         &(DependencyEntryType) {}, NULL), ENOENT);
}

TEST(unit_file_find_dropin_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **lookup_path = NULL, **paths = NULL;
        _cleanup_free_ char *found = NULL;
        const char *high, *low;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-dropin-XXXXXX", &root));

        high = strjoina(root, "/etc/systemd/system");
        low = strjoina(root, "/usr/lib/systemd/system");
        ASSERT_NOT_NULL(lookup_path = strv_new(high, low));

        ASSERT_OK(mkdir_p(strjoina(high, "/multi-user.target.wants"), 0755));
        ASSERT_OK(mkdir_p(strjoina(low, "/multi-user.target.wants"), 0755));

        ASSERT_OK_ERRNO(symlink("../foo.service", strjoina(high, "/multi-user.target.wants/foo.service")));
        ASSERT_OK_ERRNO(symlink("../foo.service", strjoina(low, "/multi-user.target.wants/foo.service")));
        ASSERT_OK_ERRNO(symlink("../bar.service", strjoina(low, "/multi-user.target.wants/bar.service")));
        /* conf_files_list_strv() skips an entry that it cannot resolve. It returns the entry with the same
         * name in the lower directory instead. */
        ASSERT_OK_ERRNO(symlink("loop.service", strjoina(high, "/multi-user.target.wants/loop.service")));
        ASSERT_OK_ERRNO(symlink("../loop.service", strjoina(low, "/multi-user.target.wants/loop.service")));

        ASSERT_OK_POSITIVE(unit_file_find_dropin_paths(root, lookup_path, /* unit_path_cache= */ NULL,
                                                       ".wants", /* file_suffix= */ NULL,
                                                       "multi-user.target", /* aliases= */ NULL, &paths));

        FOREACH_STRING(entry, "foo.service", "bar.service", "loop.service") {
                ASSERT_OK_POSITIVE(unit_file_find_dropin_entry(root, lookup_path, ".wants", "multi-user.target",
                                                               /* aliases= */ NULL, entry, &found));
                ASSERT_TRUE(strv_contains(paths, found));
                found = mfree(found);
        }

        ASSERT_OK_ZERO(unit_file_find_dropin_entry(root, lookup_path, ".wants", "multi-user.target",
                                                   /* aliases= */ NULL, "missing.service", &found));
        ASSERT_NULL(found);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

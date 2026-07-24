/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "measurement-log.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

static bool log_is_dirty(const char *path) {
        struct stat st;

        ASSERT_OK_ERRNO(stat(path, &st));
        return FLAGS_SET(st.st_mode, S_ISVTX);
}

TEST(measurement_log_lifecycle) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL, *parsed = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));

        /* Parent directories are created as needed */
        _cleanup_free_ char *path = path_join(d, "sub/dir/test.log");
        ASSERT_NOT_NULL(path);

        fd = measurement_log_open(path);
        ASSERT_OK(fd);
        ASSERT_OK_ERRNO(stat(path, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, (mode_t) 0600);

        /* dirty sets the marker, clean removes it */
        ASSERT_OK(measurement_log_dirty(fd));
        ASSERT_TRUE(log_is_dirty(path));
        ASSERT_OK(measurement_log_clean(fd, true));
        ASSERT_FALSE(log_is_dirty(path));

        /* append writes one json-seq record and cleans the marker */
        ASSERT_OK(sd_json_buildo(&record, SD_JSON_BUILD_PAIR_STRING("string", "one")));
        ASSERT_OK(measurement_log_dirty(fd));
        ASSERT_EQ(measurement_log_append(fd, record, true), 1);
        ASSERT_FALSE(log_is_dirty(path));

        /* a second append adds a record instead of replacing */
        record = sd_json_variant_unref(record);
        ASSERT_OK(sd_json_buildo(&record, SD_JSON_BUILD_PAIR_STRING("string", "two")));
        ASSERT_OK(measurement_log_dirty(fd));
        ASSERT_EQ(measurement_log_append(fd, record, true), 1);

        _cleanup_free_ char *raw = NULL;
        size_t size;
        ASSERT_OK(read_full_file(path, &raw, &size));
        ASSERT_TRUE(size > 2);
        ASSERT_EQ(raw[0], (char) 0x1E);

        char *second = memchr(raw + 1, 0x1E, size - 1);
        ASSERT_NOT_NULL(second);
        ASSERT_NULL(memchr(second + 1, 0x1E, size - (second + 1 - raw)));

        /* both records parse, in append order */
        *second = '\0';
        ASSERT_OK(sd_json_parse(raw + 1, 0, &parsed, NULL, NULL));
        sd_json_variant *v = ASSERT_PTR(sd_json_variant_by_key(parsed, "string"));
        ASSERT_STREQ(sd_json_variant_string(v), "one");

        parsed = sd_json_variant_unref(parsed);
        ASSERT_OK(sd_json_parse(second + 1, 0, &parsed, NULL, NULL));
        v = ASSERT_PTR(sd_json_variant_by_key(parsed, "string"));
        ASSERT_STREQ(sd_json_variant_string(v), "two");
}

TEST(measurement_log_torn_write) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));

        _cleanup_free_ char *path = path_join(d, "test.log");
        ASSERT_NOT_NULL(path);

        /* Simulate a writer that died between dirty and append */
        fd = measurement_log_open(path);
        ASSERT_OK(fd);
        ASSERT_OK(measurement_log_dirty(fd));
        fd = safe_close(fd);

        /* The next writer detects the torn state */
        fd2 = measurement_log_open(path);
        ASSERT_OK(fd2);
        ASSERT_ERROR(measurement_log_dirty(fd2), ESTALE);

        /* clean keeps the torn state with reset_marker=false.  */
        ASSERT_OK(measurement_log_clean(fd2, false));
        ASSERT_ERROR(measurement_log_dirty(fd2), ESTALE);

        /* Writer still appends its own record to the torn log, but must preserve
         * the marker so the earlier writer's missing record stays detectable. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL;
        ASSERT_OK(sd_json_buildo(&record, SD_JSON_BUILD_PAIR_STRING("string", "after-torn")));
        ASSERT_EQ(measurement_log_append(fd2, record, false), 1);
        ASSERT_ERROR(measurement_log_dirty(fd2), ESTALE);
        ASSERT_TRUE(log_is_dirty(path));
}

TEST(measurement_log_unavailable) {
        /* All functions silently tolerate a failed open */
        ASSERT_EQ(measurement_log_dirty(-EBADF), 0);
        ASSERT_EQ(measurement_log_clean(-EBADF, true), 0);
        ASSERT_EQ(measurement_log_append(-EBADF, NULL, true), 0);

        /* Refuses to follow symlinks */
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        ASSERT_OK(mkdtemp_malloc(NULL, &d));

        _cleanup_free_ char *target = path_join(d, "target"), *link = path_join(d, "link");
        ASSERT_NOT_NULL(target);
        ASSERT_NOT_NULL(link);
        ASSERT_OK(touch(target));
        ASSERT_OK_ERRNO(symlink(target, link));
        ASSERT_ERROR(measurement_log_open(link), ELOOP);

        /* Refuses non-regular files */
        ASSERT_ERROR(measurement_log_open(d), EISDIR);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

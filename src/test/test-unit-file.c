/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "argv-util.h"
#include "fileio.h"
#include "initrd-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "set.h"
#include "special.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "unit-file.h"

TEST(unit_validate_alias_symlink_and_warn) {
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a.service", "/other/b.service") == 0);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a.service", "/other/b.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a.service", "/other/b.foobar") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@.service", "/other/b@.service") == 0);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@.service", "/other/b@.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@XXX.service", "/other/b@YYY.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@XXX.service", "/other/b@YYY.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@.service", "/other/b@YYY.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@XXX.service", "/other/b@XXX.service") == 0);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@XXX.service", "/other/b@.service") == 0);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@.service", "/other/b.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a.service", "/other/b@.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a@.slice", "/other/b.slice") == -EINVAL);
        assert_se(unit_validate_alias_symlink_or_warn(LOG_INFO, "/path/a.slice", "/other/b.slice") == -EINVAL);
}

TEST(unit_file_build_name_map) {
        _cleanup_(lookup_paths_done) LookupPaths lp = {};
        _cleanup_hashmap_free_ Hashmap *unit_ids = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_names = NULL;
        const char *k, *dst;
        char **v, **ids;
        usec_t mtime = 0;
        int r;

        ids = strv_skip(saved_argv, 1);

        assert_se(lookup_paths_init(&lp, RUNTIME_SCOPE_SYSTEM, 0, NULL) >= 0);

        assert_se(unit_file_build_name_map(&lp, &mtime, &unit_ids, &unit_names, NULL) == 1);

        HASHMAP_FOREACH_KEY(dst, k, unit_ids)
                log_info("ids: %s → %s", k, dst);

        HASHMAP_FOREACH_KEY(v, k, unit_names) {
                _cleanup_free_ char *j = strv_join(v, ", ");
                log_info("aliases: %s ← %s", k, j);
        }

        char buf[FORMAT_TIMESTAMP_MAX];
        log_debug("Last modification time: %s", format_timestamp(buf, sizeof buf, mtime));

        r = unit_file_build_name_map(&lp, &mtime, &unit_ids, &unit_names, NULL);
        assert_se(IN_SET(r, 0, 1));
        if (r == 0)
                log_debug("Cache rebuild skipped based on mtime.");

        STRV_FOREACH(id, ids) {
                 const char *fragment, *name;
                 _cleanup_set_free_ Set *names = NULL;
                 log_info("*** %s ***", *id);
                 r = unit_file_find_fragment(unit_ids,
                                             unit_names,
                                             *id,
                                             &fragment,
                                             &names);
                 assert_se(r == 0);
                 log_info("fragment: %s", fragment);
                 log_info("names:");
                 SET_FOREACH(name, names)
                         log_info("    %s", name);
        }

        /* Make sure everything still works if we don't collect names. */
        STRV_FOREACH(id, ids) {
                 const char *fragment;
                 log_info("*** %s ***", *id);
                 r = unit_file_find_fragment(unit_ids,
                                             unit_names,
                                             *id,
                                             &fragment,
                                             NULL);
                 assert_se(r == 0);
                 log_info("fragment: %s", fragment);
        }
}

static bool test_unit_file_remove_from_name_map_trail(const LookupPaths *lp, size_t trial) {
        int r;

        log_debug("/* %s(trial=%zu) */", __func__, trial);

        _cleanup_hashmap_free_ Hashmap *unit_ids = NULL, *unit_names = NULL;
        _cleanup_set_free_ Set *path_cache = NULL;
        ASSERT_OK_POSITIVE(unit_file_build_name_map(lp, NULL, &unit_ids, &unit_names, &path_cache));

        _cleanup_free_ char *name = NULL;
        for (size_t i = 0; i < 100; i++) {
                ASSERT_OK(asprintf(&name, "test-unit-file-%"PRIx64".service", random_u64()));
                if (!hashmap_contains(unit_ids, name))
                        break;
                name = mfree(name);
        }
        ASSERT_NOT_NULL(name);

        _cleanup_free_ char *path = path_join(lp->transient, name);
        ASSERT_NOT_NULL(path);
        ASSERT_OK(write_string_file(path, "[Unit]\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        uint64_t cache_timestamp_hash = 0;
        ASSERT_OK_POSITIVE(unit_file_build_name_map(lp, &cache_timestamp_hash, &unit_ids, &unit_names, &path_cache));

        ASSERT_STREQ(hashmap_get(unit_ids, name), path);
        ASSERT_TRUE(strv_equal(hashmap_get(unit_names, name), STRV_MAKE(name)));
        ASSERT_TRUE(set_contains(path_cache, path));

        ASSERT_OK_ERRNO(unlink(path));

        ASSERT_OK(r = unit_file_remove_from_name_map(lp, &cache_timestamp_hash, &unit_ids, &unit_names, &path_cache, path));
        if (r > 0)
                return false; /* someone touches unit files. Retrying. */

        ASSERT_FALSE(hashmap_contains(unit_ids, name));
        ASSERT_FALSE(hashmap_contains(unit_names, path));
        ASSERT_FALSE(set_contains(path_cache, path));

        _cleanup_hashmap_free_ Hashmap *unit_ids_2 = NULL, *unit_names_2 = NULL;
        _cleanup_set_free_ Set *path_cache_2 = NULL;
        ASSERT_OK_POSITIVE(unit_file_build_name_map(lp, NULL, &unit_ids_2, &unit_names_2, &path_cache_2));

        if (hashmap_size(unit_ids) != hashmap_size(unit_ids_2) ||
            hashmap_size(unit_names) != hashmap_size(unit_names_2) ||
            !set_equal(path_cache, path_cache_2))
                return false;

        const char *k, *v;
        HASHMAP_FOREACH_KEY(v, k, unit_ids)
                if (!streq_ptr(hashmap_get(unit_ids_2, k), v))
                        return false;

        char **l;
        HASHMAP_FOREACH_KEY(l, k, unit_names)
                if (!strv_equal_ignore_order(hashmap_get(unit_names_2, k), l))
                        return false;

        return true;
}


TEST(unit_file_remove_from_name_map) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;

        _cleanup_(lookup_paths_done) LookupPaths lp = {};
        ASSERT_OK(lookup_paths_init(&lp, RUNTIME_SCOPE_SYSTEM, LOOKUP_PATHS_TEMPORARY_GENERATED, NULL));
        ASSERT_NOT_NULL((d = strdup(lp.temporary_dir)));

        for (size_t i = 0; i < 10; i++)
                if (test_unit_file_remove_from_name_map_trail(&lp, i))
                        return;

        assert_not_reached();
}

TEST(runlevel_to_target) {
        in_initrd_force(false);
        ASSERT_STREQ(runlevel_to_target(NULL), NULL);
        ASSERT_STREQ(runlevel_to_target("unknown-runlevel"), NULL);
        ASSERT_STREQ(runlevel_to_target("rd.unknown-runlevel"), NULL);
        ASSERT_STREQ(runlevel_to_target("3"), SPECIAL_MULTI_USER_TARGET);
        ASSERT_STREQ(runlevel_to_target("rd.rescue"), NULL);

        in_initrd_force(true);
        ASSERT_STREQ(runlevel_to_target(NULL), NULL);
        ASSERT_STREQ(runlevel_to_target("unknown-runlevel"), NULL);
        ASSERT_STREQ(runlevel_to_target("rd.unknown-runlevel"), NULL);
        ASSERT_STREQ(runlevel_to_target("3"), NULL);
        ASSERT_STREQ(runlevel_to_target("rd.rescue"), SPECIAL_RESCUE_TARGET);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);

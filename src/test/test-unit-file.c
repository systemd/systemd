/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "initrd-util.h"
#include "path-lookup.h"
#include "set.h"
#include "special.h"
#include "strv.h"
#include "tests.h"
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
                 _cleanup_set_free_free_ Set *names = NULL;
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

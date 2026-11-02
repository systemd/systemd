/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "discover-image.h"
#include "path-util.h"
#include "rm-rf.h"
#include "runtime-scope.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(image_in_search_path) {
        ASSERT_TRUE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, NULL, "/run/portables/foo.raw"));
        ASSERT_TRUE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, NULL, "/var/lib/portables/foo/"));
        ASSERT_TRUE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, "/", "/etc/portables/foo.raw"));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, NULL, "/run/portables"));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, NULL, "/run/portables/foo/bar.raw"));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, NULL, "/tmp/foo.raw"));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_MACHINE, NULL, "/run/portables/foo.raw"));

        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &root));

        _cleanup_free_ char *inside = ASSERT_NOT_NULL(path_join(root, "/run/portables/foo.raw"));
        ASSERT_TRUE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, inside));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, "/run/portables/foo.raw"));

        _cleanup_free_ char *outside = ASSERT_NOT_NULL(path_join(root, "/tmp/foo.raw"));
        ASSERT_FALSE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, outside));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

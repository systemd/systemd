/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "discover-image.h"
#include "path-util.h"
#include "rm-rf.h"
#include "runtime-scope.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(image_in_search_path) {
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/foo.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/var/lib/portables/foo/"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, "/", "/etc/portables/foo.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/foo/bar.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/tmp/foo.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_MACHINE, /* root= */ NULL, "/run/portables/foo.raw"));

        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &root));

        _cleanup_free_ char *inside = ASSERT_NOT_NULL(path_join(root, "/run/portables/foo.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, inside));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, "/run/portables/foo.raw"));

        _cleanup_free_ char *outside = ASSERT_NOT_NULL(path_join(root, "/tmp/foo.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, root, outside));
}

TEST(image_search_path_env) {
        /* Replace the built-in search path */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_IMAGE_PORTABLE_PATH", "/foo:/bar", /* overwrite= */ true));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/foo/a.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/bar/a.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/a.raw"));

        /* Other classes are not affected */
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_MACHINE, /* root= */ NULL, "/foo/a.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_MACHINE, /* root= */ NULL, "/var/lib/machines/a.raw"));

        /* Extend the built-in search path, with duplicates */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_IMAGE_PORTABLE_PATH", "/foo:+:/foo:/run/portables:+", /* overwrite= */ true));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/foo/a.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/a.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/var/lib/portables/a.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/bar/a.raw"));

        /* Empty: nothing is searched */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_IMAGE_PORTABLE_PATH", "", /* overwrite= */ true));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/a.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/foo/a.raw"));

        /* Relative and non-normalized entries are ignored, the rest is used */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_IMAGE_PORTABLE_PATH", "foo:/bar/../baz:/quux", /* overwrite= */ true));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/baz/a.raw"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/quux/a.raw"));
        ASSERT_OK_ZERO(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/a.raw"));

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_IMAGE_PORTABLE_PATH"));
        ASSERT_OK_POSITIVE(image_in_search_path(RUNTIME_SCOPE_SYSTEM, IMAGE_PORTABLE, /* root= */ NULL, "/run/portables/a.raw"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

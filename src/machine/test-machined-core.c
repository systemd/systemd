/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "discover-image.h"
#include "hashmap.h"
#include "machined.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static Image* new_test_image(const char *name, const char *path) {
        Image *image = ASSERT_PTR(new(Image, 1));
        *image = (Image) {
                .n_ref = 1,
                .type = IMAGE_DIRECTORY,
                .class = IMAGE_MACHINE,
                .usage = UINT64_MAX,
                .usage_exclusive = UINT64_MAX,
                .limit = UINT64_MAX,
                .limit_exclusive = UINT64_MAX,
        };
        image->name = ASSERT_PTR(strdup(name));
        image->path = ASSERT_PTR(strdup(path));
        return image;
}

TEST(rename_image_and_update_cache_failure_keeps_image) {
        /* A failing rename must not free the caller's borrowed image nor drop it from the cache: the
         * callers keep using both the pointer and the cache entry after we return. */

        Manager m = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
        };

        /* A path below /usr/ marks the image as a vendor image, so that image_rename() fails early with
         * -EROFS without doing any filesystem work. */
        _cleanup_(image_unrefp) Image *image = new_test_image("testimg", "/usr/lib/machines/testimg");
        image->userdata = &m;

        ASSERT_OK(hashmap_ensure_put(&m.image_cache, &image_hash_ops, image->name, image));
        Image *borrowed = TAKE_PTR(image); /* the cache owns the reference now, we keep a borrowed pointer */

        ASSERT_ERROR(rename_image_and_update_cache(&m, borrowed, "newname"), EROFS);

        /* The image must still be cached under its unchanged name, so the borrowed pointer stays valid. */
        ASSERT_PTR_EQ(hashmap_get(m.image_cache, "testimg"), borrowed);
        ASSERT_STREQ(borrowed->name, "testimg");

        hashmap_free(m.image_cache);
}

TEST(rename_image_and_update_cache_evicts_stale_target) {
        /* If the destination name is still present in the cache as a stale entry (its on-disk image was
         * removed out of band before the idle cache flush ran), rename_image_and_update_cache() must
         * evict that bogus entry and cache the freshly renamed image, rather than aborting or leaving a
         * dangling pointer behind. */

        /* image_rename() would otherwise try to take real image locks, so disable them for the test. */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_NSPAWN_LOCK", "0", /* overwrite= */ true));

        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machined-core.XXXXXX", &tmp));

        /* Point the per-user image search and settings paths at the temp dir, so that image_rename()'s
         * internal image_find() looks there (and finds nothing) instead of scanning */
        FOREACH_STRING(e, "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME")
                ASSERT_OK_ERRNO(setenv(e, tmp, /* overwrite= */ true));

        _cleanup_free_ char *src_path = ASSERT_PTR(path_join(tmp, "test-rename-src"));
        ASSERT_OK(mkdir_p(src_path, 0755));

        Manager m = {
                .runtime_scope = RUNTIME_SCOPE_USER,
        };

        /* The image we rename, backed by a real directory so image_rename() actually succeeds. */
        _cleanup_(image_unrefp) Image *image = new_test_image("test-rename-src", src_path);
        image->userdata = &m;
        ASSERT_OK(hashmap_ensure_put(&m.image_cache, &image_hash_ops, image->name, image));
        Image *borrowed = TAKE_PTR(image);

        /* A stale cache entry under the destination name, pointing at a different Image object. */
        _cleanup_(image_unrefp) Image *stale = new_test_image("test-rename-dst", "/nonexistent/test-rename-dst");
        stale->userdata = &m;
        ASSERT_OK(hashmap_ensure_put(&m.image_cache, &image_hash_ops, stale->name, stale));
        TAKE_PTR(stale); /* owned by the cache; evicted and freed by the call below */

        ASSERT_OK(rename_image_and_update_cache(&m, borrowed, "test-rename-dst"));

        /* The renamed image is now cached under the destination name; the old name is gone. */
        ASSERT_PTR_EQ(hashmap_get(m.image_cache, "test-rename-dst"), borrowed);
        ASSERT_STREQ(borrowed->name, "test-rename-dst");
        ASSERT_NULL(hashmap_get(m.image_cache, "test-rename-src"));

        hashmap_free(m.image_cache);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "discover-image.h"
#include "hashmap.h"
#include "machined.h"
#include "string-util.h"
#include "tests.h"

TEST(rename_image_and_update_cache_failure_keeps_image) {
        /* A failing rename must not free the caller's borrowed image nor drop it from the cache: the
         * callers keep using both the pointer and the cache entry after we return. */

        Manager m = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
        };
        _cleanup_(image_unrefp) Image *image = NULL;

        ASSERT_NOT_NULL(image = new(Image, 1));
        *image = (Image) {
                .n_ref = 1,
                .type = IMAGE_DIRECTORY,
                .class = IMAGE_MACHINE,
                .usage = UINT64_MAX,
                .usage_exclusive = UINT64_MAX,
                .limit = UINT64_MAX,
                .limit_exclusive = UINT64_MAX,
        };
        /* A path below /usr/ marks the image as a vendor image, so that image_rename() fails early with
         * -EROFS without doing any filesystem work. */
        ASSERT_NOT_NULL(image->name = strdup("testimg"));
        ASSERT_NOT_NULL(image->path = strdup("/usr/lib/machines/testimg"));
        image->userdata = &m;

        ASSERT_OK(hashmap_ensure_put(&m.image_cache, &image_hash_ops, image->name, image));
        Image *borrowed = TAKE_PTR(image); /* the cache owns the reference now, we keep a borrowed pointer */

        ASSERT_ERROR(rename_image_and_update_cache(&m, borrowed, "newname"), EROFS);

        /* The image must still be cached under its unchanged name, so the borrowed pointer stays valid. */
        ASSERT_PTR_EQ(hashmap_get(m.image_cache, "testimg"), borrowed);
        ASSERT_STREQ(borrowed->name, "testimg");

        hashmap_free(m.image_cache);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

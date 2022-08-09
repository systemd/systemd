/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "portable.h"
#include "portabled-image.h"
#include "portabled.h"

Image *manager_image_cache_get(Manager *m, const char *name_or_path) {
        assert(m);

        return hashmap_get(m->image_cache, name_or_path);
}

static int image_cache_flush(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        hashmap_clear(m->image_cache);
        return 0;
}

static int manager_image_cache_initialize(Manager *m) {
        int r;

        assert(m);

        r = hashmap_ensure_allocated(&m->image_cache, &image_hash_ops);
        if (r < 0)
                return r;

        /* We flush the cache as soon as we are idle again */
        if (!m->image_cache_defer_event) {
                r = sd_event_add_defer(m->event, &m->image_cache_defer_event, image_cache_flush, m);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(m->image_cache_defer_event, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(m->image_cache_defer_event, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        return 0;
}

int manager_image_cache_add(Manager *m, Image *image) {
        int r;

        assert(m);

        /* We add the specified image to the cache under two keys.
         *
         * 1. Always under its path
         *
         * 2. If the image was discovered in the search path (i.e. its discoverable boolean set) we'll also add it
         *    under its short name.
         */

        r = manager_image_cache_initialize(m);
        if (r < 0)
                return r;

        image->userdata = m;

        r = hashmap_put(m->image_cache, image->path, image);
        if (r < 0)
                return r;

        image_ref(image);

        if (image->discoverable) {
                r = hashmap_put(m->image_cache, image->name, image);
                if (r < 0)
                        return r;

                image_ref(image);
        }

        return 0;
}

int manager_image_cache_discover(Manager *m, Hashmap *images, sd_bus_error *error) {
        Image *image;
        int r;

        assert(m);

        /* A wrapper around image_discover() (for finding images in search path) and portable_discover_attached() (for
         * finding attached images). */

        r = image_discover(IMAGE_PORTABLE, NULL, images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images)
                (void) manager_image_cache_add(m, image);

        return 0;
}

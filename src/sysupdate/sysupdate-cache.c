/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util.h"
#include "sysupdate-cache.h"

#define WEB_CACHE_ENTRIES_MAX 64U
#define WEB_CACHE_ITEM_SIZE_MAX (64U*1024U*1024U)

static WebCacheItem* web_cache_item_free(WebCacheItem *i) {
        if (!i)
                return NULL;

        free(i->url);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WebCacheItem*, web_cache_item_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(web_cache_hash_ops, char, string_hash_func, string_compare_func, WebCacheItem, web_cache_item_free);

int web_cache_add_item(
                Hashmap **web_cache,
                const char *url,
                bool verified,
                const void *data,
                size_t size) {

        _cleanup_(web_cache_item_freep) WebCacheItem *item = NULL;
        _cleanup_free_ char *u = NULL;
        int r;

        assert(web_cache);
        assert(url);
        assert(data || size == 0);

        if (size > WEB_CACHE_ITEM_SIZE_MAX)
                return -E2BIG;

        item = web_cache_get_item(*web_cache, url, verified);
        if (item && memcmp_nn(item->data, item->size, data, size) == 0)
                return 0;

        if (hashmap_size(*web_cache) >= (size_t) (WEB_CACHE_ENTRIES_MAX + !!hashmap_get(*web_cache, url)))
                return -ENOSPC;

        r = hashmap_ensure_allocated(web_cache, &web_cache_hash_ops);
        if (r < 0)
                return r;

        u = strdup(url);
        if (!u)
                return -ENOMEM;

        item = malloc(offsetof(WebCacheItem, data) + size + 1);
        if (!item)
                return -ENOMEM;

        *item = (WebCacheItem) {
                .url = TAKE_PTR(u),
                .size = size,
                .verified = verified,
        };

        /* Just to be extra paranoid, let's NUL terminate the downloaded buffer */
        *(uint8_t*) mempcpy(item->data, data, size) = 0;

        web_cache_item_free(hashmap_remove(*web_cache, url));

        r = hashmap_put(*web_cache, item->url, item);
        if (r < 0)
                return r;

        TAKE_PTR(item);
        return 1;
}

WebCacheItem* web_cache_get_item(Hashmap *web_cache, const char *url, bool verified) {
        WebCacheItem *i;

        i = hashmap_get(web_cache, url);
        if (!i)
                return NULL;

        if (i->verified != verified)
                return NULL;

        return i;
}

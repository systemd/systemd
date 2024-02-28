/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sd-id128.h"

#include "hashmap.h"
#include "image-policy.h"
#include "json.h"
#include "lock-util.h"
#include "macro.h"
#include "os-util.h"
#include "path-util.h"
#include "string-util.h"
#include "time-util.h"

typedef enum ImageType {
        IMAGE_DIRECTORY,
        IMAGE_SUBVOLUME,
        IMAGE_RAW,
        IMAGE_BLOCK,
        _IMAGE_TYPE_MAX,
        _IMAGE_TYPE_INVALID = -EINVAL,
} ImageType;

typedef struct Image {
        unsigned n_ref;

        ImageType type;
        ImageClass class;
        char *name;
        char *path;
        bool read_only;

        usec_t crtime;
        usec_t mtime;

        uint64_t usage;
        uint64_t usage_exclusive;
        uint64_t limit;
        uint64_t limit_exclusive;

        char *hostname;
        sd_id128_t machine_id;
        char **machine_info;
        char **os_release;
        char **sysext_release;
        char **confext_release;

        bool metadata_valid:1;
        bool discoverable:1;  /* true if we know for sure that image_find() would find the image given just the short name */

        void *userdata;
} Image;

Image *image_unref(Image *i);
Image *image_ref(Image *i);

DEFINE_TRIVIAL_CLEANUP_FUNC(Image*, image_unref);

int image_find(ImageClass class, const char *root, const char *name, Image **ret);
int image_from_path(const char *path, Image **ret);
int image_find_harder(ImageClass class, const char *root, const char *name_or_path, Image **ret);
int image_discover(ImageClass class, const char *root, Hashmap *map);

int image_remove(Image *i);
int image_rename(Image *i, const char *new_name);
int image_clone(Image *i, const char *new_name, bool read_only);
int image_read_only(Image *i, bool b);

const char* image_type_to_string(ImageType t) _const_;
ImageType image_type_from_string(const char *s) _pure_;

int image_path_lock(const char *path, int operation, LockFile *global, LockFile *local);
int image_name_lock(const char *name, int operation, LockFile *ret);

int image_set_limit(Image *i, uint64_t referenced_max);

int image_read_metadata(Image *i, const ImagePolicy *image_policy);

bool image_in_search_path(ImageClass class, const char *root, const char *image);

static inline char **image_extension_release(Image *image, ImageClass class) {
        assert(image);

        if (class == IMAGE_SYSEXT)
                return image->sysext_release;
        if (class == IMAGE_CONFEXT)
                return image->confext_release;

        return NULL;
}

static inline bool IMAGE_IS_HIDDEN(const struct Image *i) {
        assert(i);

        return i->name && i->name[0] == '.';
}

static inline bool IMAGE_IS_VENDOR(const struct Image *i) {
        assert(i);

        return i->path && path_startswith(i->path, "/usr");
}

static inline bool IMAGE_IS_HOST(const struct Image *i) {
        assert(i);

        if (i->name && streq(i->name, ".host"))
                return true;

        if (i->path && path_equal(i->path, "/"))
                return true;

        return false;
}

int image_to_json(const struct Image *i, JsonVariant **ret);

extern const struct hash_ops image_hash_ops;

extern const char* const image_search_path[_IMAGE_CLASS_MAX];

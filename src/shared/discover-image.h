/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "shared-forward.h"
#include "os-util.h"

typedef enum ImageType {
        IMAGE_DIRECTORY,
        IMAGE_SUBVOLUME,
        IMAGE_RAW,
        IMAGE_BLOCK,
        IMAGE_MSTACK,
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

        struct file_handle *fh;
        uint64_t on_mount_id;
        uint64_t inode;

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

        bool metadata_valid:1;     /* true if the above 6 metadata fields have been read from the image */
        bool discoverable:1;       /* true if we know for sure that image_find() would find the image given just the short name */
        bool foreign_uid_owned:1;  /* true if this is of type IMAGE_DIRECTORY/IMAGE_SUBVOLUME and owned by foreign UID range */

        void *userdata;
} Image;

DECLARE_TRIVIAL_REF_UNREF_FUNC(Image, image);
DEFINE_TRIVIAL_CLEANUP_FUNC(Image*, image_unref);

int image_find(RuntimeScope scope, ImageClass class, const char *name, const char *root, Image **ret);
int image_from_path(const char *path, Image **ret);
int image_find_harder(RuntimeScope scope, ImageClass class, const char *name_or_path, const char *root, Image **ret);
int image_discover(RuntimeScope scope, ImageClass class, const char *root, Hashmap **images);

int image_remove(Image *i, RuntimeScope scope);
int image_rename(Image *i, const char *new_name, RuntimeScope scope);
int image_clone(Image *i, const char *new_name, bool read_only, RuntimeScope scope);
int image_read_only(Image *i, bool b, RuntimeScope scope);

DECLARE_STRING_TABLE_LOOKUP(image_type, ImageType);

int image_path_lock(RuntimeScope scope, const char *path, int operation, LockFile *global, LockFile *local);
int image_name_lock(RuntimeScope scope, const char *name, int operation, LockFile *ret);

int image_set_limit(Image *i, uint64_t referenced_max);
int image_set_pool_limit(RuntimeScope scope, ImageClass class, uint64_t referenced_max);
int image_get_pool_path(RuntimeScope scope, ImageClass class, char **ret);
int image_get_pool_usage(RuntimeScope scope, ImageClass class, uint64_t *ret);
int image_get_pool_limit(RuntimeScope scope, ImageClass class, uint64_t *ret);
int image_setup_pool(RuntimeScope scope, ImageClass class, bool use_btrfs_subvol, bool use_btrfs_quota);

int image_read_metadata(Image *i, const char *root, const ImagePolicy *image_policy, RuntimeScope scope);

bool image_in_search_path(RuntimeScope scope, ImageClass class, const char *root, const char *image);

static inline char** image_extension_release(Image *image, ImageClass class) {
        assert(image);

        if (class == IMAGE_SYSEXT)
                return image->sysext_release;
        if (class == IMAGE_CONFEXT)
                return image->confext_release;

        return NULL;
}

static inline bool image_is_hidden(const Image *i) {
        assert(i);

        return i->name && i->name[0] == '.';
}

static inline bool image_is_read_only(const Image *i) {
        assert(i);

        /* We enforce the rule that hidden images are always read-only too. If people want to change hidden
         * images they should make a copy first, and make that one mutable */

        if (image_is_hidden(i))
                return true;

        return i->read_only;
}
int bus_property_get_image_is_read_only(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error);

bool image_is_vendor(const Image *i);
bool image_is_host(const Image *i);

int image_to_json(const Image *i, sd_json_variant **ret);

int image_root_pick(RuntimeScope scope, ImageClass c, bool runtime, char **ret);

extern const struct hash_ops image_hash_ops;

extern const char* const image_search_path[_IMAGE_CLASS_MAX];

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/msdos_fs.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-gpt.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "conf-files.h"
#include "crypto-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "json-util.h"
#include "path-util.h"
#include "sha256.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "time-util.h"
#include "uapi16-manifest.h"
#include "utf8.h"
#include "voa-util.h"
#include "web-util.h"

#define CONTENTS_MAX 256U

void uapi16_contents_done(Uapi16Contents *c) {
        assert(c);

        c->file = mfree(c->file);
        c->url = mfree(c->url);
        c->http_headers = strv_free_erase(c->http_headers);
        iovec_done(&c->literal);
        iovec_done(&c->encoded_sha256);
        iovec_done(&c->original_sha256);
        c->encoding = mfree(c->encoding);
}

void uapi16_xattr_done(Uapi16Xattr *x) {
        assert(x);

        x->name = mfree(x->name);
        iovec_done(&x->value);
}

void uapi16_xattr_array_free(Uapi16Xattr *x, size_t n) {
        FOREACH_ARRAY(i, x, n)
                uapi16_xattr_done(i);

        free(x);
}

static void uapi16_object_xattrs_done(Uapi16Object *o) {
        assert(o);

        uapi16_xattr_array_free(o->user_xattrs, o->n_user_xattrs);
        o->user_xattrs = NULL;
        o->n_user_xattrs = 0;
        o->user_xattrs_set = false;
}

void uapi16_object_done(Uapi16Object *o) {
        assert(o);

        o->name = mfree(o->name);
        o->media_type = mfree(o->media_type);
        o->user_name = mfree(o->user_name);
        o->group_name = mfree(o->group_name);
        o->gpt_label = mfree(o->gpt_label);
        o->fs_label = mfree(o->fs_label);
        iovec_done(&o->sha256);

        FOREACH_ARRAY(c, o->contents, o->n_contents)
                uapi16_contents_done(c);
        o->contents = mfree(o->contents);
        o->n_contents = 0;

        uapi16_object_xattrs_done(o);
}

int uapi16_object_check_validity(Uapi16Object *o) {
        assert(o);

        if (o->valid_since_usec > 0 ||
            o->valid_until_usec < USEC_INFINITY) {
                usec_t n = now(CLOCK_REALTIME);

                if (n < o->valid_since_usec ||
                    n > o->valid_until_usec)
                        return -ESTALE;
        }

        if (o->validity >= 0 && o->validity == UAPI16_REVOKED)
                return -EHWPOISON;

        return 0;
}

bool uapi16_name_is_valid(const char *s) {
        /* The specification requires the "name" field to be a normalized, relative UTF-8 path without a
         * trailing slash and without control characters, of at most 4095 bytes, that does not clash with the
         * name of the manifest file itself. */

        if (isempty(s))
                return false;

        if (strlen(s) > UAPI16_NAME_MAX)
                return false;

        if (!utf8_is_valid(s))
                return false;

        if (path_is_absolute(s))
                return false;

        /* NB: path_is_normalized() limits the individual components to NAME_MAX, while the specification
         * does not limit them on their own. We are stricter here, since such names cannot be represented
         * on Linux file systems anyway. */
        if (!path_is_normalized(s))
                return false;

        /* path_is_normalized() accepts a trailing slash, the specification does not */
        if (endswith(s, "/"))
                return false;

        if (string_has_cc(s, /* ok= */ NULL))
                return false;

        if (uapi16_manifest_filename_is_reserved(s))
                return false;

        return true;
}

bool uapi16_xattr_name_is_valid(const char *s) {
        /* The specification requires extended attribute names to be non-empty UTF-8 strings without control
         * characters. */

        return !isempty(s) &&
                utf8_is_valid(s) &&
                !string_has_cc(s, /* ok= */ NULL);
}

bool uapi16_fs_label_is_valid(const char *s) {
        /* The specification requires the label to be valid UTF-8 without control characters. Any further
         * restrictions are file system-specific, and are enforced when the label is applied. */

        return s &&
                utf8_is_valid(s) &&
                !string_has_cc(s, /* ok= */ NULL);
}

int uapi16_fat_serial_from_string(const char *s, uint32_t *ret) {
        uint32_t v = 0;

        assert(s);

        /* Exactly two groups of four hex digits, separated by a hyphen, parsed case-insensitively. Nothing
         * else is permitted by the specification. */

        if (strlen(s) != UAPI16_FAT_SERIAL_STRING_MAX - 1 || s[4] != '-')
                return -EINVAL;

        for (size_t i = 0; i < UAPI16_FAT_SERIAL_STRING_MAX - 1; i++) {
                if (i == 4)
                        continue;

                int d = unhexchar(s[i]);
                if (d < 0)
                        return -EINVAL;

                v = (v << 4) | (uint32_t) d;
        }

        if (ret)
                *ret = v;

        return 0;
}

char* uapi16_fat_serial_to_string(uint32_t serial, char buf[static UAPI16_FAT_SERIAL_STRING_MAX]) {
        assert(buf);

        /* Formatted in uppercase, as the specification asks for */
        assert_se(snprintf_ok(buf, UAPI16_FAT_SERIAL_STRING_MAX, "%04" PRIX32 "-%04" PRIX32, serial >> 16, serial & 0xFFFFU));
        return buf;
}

assert_cc(UAPI16_FAT_ATTRS_ALL == (ATTR_RO|ATTR_HIDDEN|ATTR_SYS|ATTR_ARCH));

static const struct {
        unsigned flag;
        const char *field;
        size_t offset;
} inode_flag_table[] = {
        { FS_APPEND_FL,    "flagAppendOnly", offsetof(Uapi16Object, flag_append_only) },
        { FS_IMMUTABLE_FL, "flagImmutable",  offsetof(Uapi16Object, flag_immutable)   },
        { FS_NOATIME_FL,   "flagNoAtime",    offsetof(Uapi16Object, flag_no_atime)    },
        { FS_NOCOW_FL,     "flagNoCow",      offsetof(Uapi16Object, flag_no_cow)      },
        { FS_NODUMP_FL,    "flagNoDump",     offsetof(Uapi16Object, flag_no_dump)     },
};

static const struct {
        uint32_t attr;
        const char *field;
        size_t offset;
} fat_attr_table[] = {
        { ATTR_RO,     "readOnly",    offsetof(Uapi16Object, read_only)    }, /* the generic read-only marker */
        { ATTR_HIDDEN, "flagHidden",  offsetof(Uapi16Object, flag_hidden)  },
        { ATTR_SYS,    "flagSystem",  offsetof(Uapi16Object, flag_system)  },
        { ATTR_ARCH,   "flagArchive", offsetof(Uapi16Object, flag_archive) },
};

const char* uapi16_inode_flag_to_field(unsigned flag) {
        FOREACH_ELEMENT(i, inode_flag_table)
                if (i->flag == flag)
                        return i->field;

        return NULL;
}

const char* uapi16_fat_attr_to_field(uint32_t attr) {
        FOREACH_ELEMENT(i, fat_attr_table)
                if (i->attr == attr)
                        return i->field;

        return NULL;
}

void uapi16_object_inode_flags(const Uapi16Object *o, unsigned *ret_value, unsigned *ret_mask) {
        unsigned value = 0, mask = 0;

        assert(o);
        assert(ret_value || ret_mask);

        FOREACH_ELEMENT(i, inode_flag_table) {
                int b = *(const int*) ((const uint8_t*) o + i->offset);
                if (b < 0)
                        continue;

                mask |= i->flag;
                SET_FLAG(value, i->flag, b);
        }

        if (ret_value)
                *ret_value = value;
        if (ret_mask)
                *ret_mask = mask;
}

void uapi16_object_fat_attrs(const Uapi16Object *o, uint32_t *ret_value, uint32_t *ret_mask) {
        uint32_t value = 0, mask = 0;

        assert(o);
        assert(ret_value || ret_mask);

        FOREACH_ELEMENT(i, fat_attr_table) {
                int b = *(const int*) ((const uint8_t*) o + i->offset);
                if (b < 0)
                        continue;

                mask |= i->attr;
                SET_FLAG(value, i->attr, b);
        }

        if (ret_value)
                *ret_value = value;
        if (ret_mask)
                *ret_mask = mask;
}

int uapi16_inode_flags_merge_json(sd_json_variant **v, unsigned flags, unsigned mask) {
        int r;

        assert(v);

        FOREACH_ELEMENT(i, inode_flag_table) {
                if (!FLAGS_SET(mask, i->flag))
                        continue;

                r = sd_json_variant_set_field_boolean(v, i->field, FLAGS_SET(flags, i->flag));
                if (r < 0)
                        return r;
        }

        return 0;
}

int uapi16_fat_attrs_merge_json(sd_json_variant **v, uint32_t attrs, uint32_t mask) {
        int r;

        assert(v);

        FOREACH_ELEMENT(i, fat_attr_table) {
                if (!FLAGS_SET(mask, i->attr))
                        continue;

                r = sd_json_variant_set_field_boolean(v, i->field, FLAGS_SET(attrs, i->attr));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int json_dispatch_uapi16_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **n = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *n = mfree(*n);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        const char *s = sd_json_variant_string(variant);
        if (!uapi16_name_is_valid(s))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid file name.", strna(name));

        if (free_and_strdup(n, s) < 0)
                return json_log_oom(variant, flags);

        return 0;
}

int uapi16_features_build_json(ManifestField features, sd_json_variant **ret) {
        _cleanup_strv_free_ char **l = NULL;

        assert((features & ~_MANIFEST_FIELD_ALL) == 0);
        assert(ret);

        BIT_FOREACH(b, (unsigned) features)
                if (strv_extend(&l, ASSERT_PTR(manifest_field_to_uapi16_feature(1 << b))) < 0)
                        return -ENOMEM;

        /* The specification recommends sorting the values by their bytes */
        strv_sort(l);

        return sd_json_variant_new_array_strv(ret, l);
}

static int json_dispatch_features(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ManifestField *f = ASSERT_PTR(userdata);

        /* Unset is encoded as _MANIFEST_FIELD_INVALID, the caller then picks the default set */
        if (sd_json_variant_is_null(variant)) {
                *f = _MANIFEST_FIELD_INVALID;
                return 0;
        }

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        ManifestField mask = 0;
        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!sd_json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "Element of JSON field '%s' is not a string.", strna(name));

                const char *s = sd_json_variant_string(e);

                /* The specification requires ignoring unknown values, to allow future extensions */
                ManifestField k = manifest_field_from_uapi16_feature(s);
                if (k < 0) {
                        json_log(e, flags|SD_JSON_DEBUG, 0, "Ignoring unknown feature '%s'.", s);
                        continue;
                }

                if (FLAGS_SET(mask, k))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "Feature '%s' listed twice in JSON field '%s', refusing.", s, strna(name));

                mask |= k;
        }

        *f = mask;
        return 0;
}

static const char* const uapi16_order_table[_UAPI16_ORDER_MAX] = {
        [UAPI16_ORDER_CODEPOINT] = "codepoint",
};

DEFINE_STRING_TABLE_LOOKUP(uapi16_order, Uapi16Order);

static int json_dispatch_order(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Order *o = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *o = _UAPI16_ORDER_INVALID;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        /* The specification requires treating unknown values as if the field was not set, but keep them
         * apart from an absent field, so that the field can still be refused where it is not permitted */
        *o = uapi16_order_from_string(sd_json_variant_string(variant));
        if (*o < 0) {
                json_log(variant, flags|SD_JSON_DEBUG, 0, "Unknown order '%s', ignoring.", sd_json_variant_string(variant));
                *o = _UAPI16_ORDER_UNKNOWN;
        }

        return 0;
}

static int json_dispatch_inode_type(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        mode_t *t = ASSERT_PTR(userdata);

        /* Unset is encoded as 0, the caller then picks the default for the object */
        if (sd_json_variant_is_null(variant)) {
                *t = 0;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        mode_t m = inode_type_from_string(sd_json_variant_string(variant));
        if (m == MODE_INVALID)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid inode type.", strna(name));

        *t = m;
        return 0;
}

static int json_dispatch_gpt_label(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **n = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *n = mfree(*n);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        const char *label = sd_json_variant_string(variant);
        if (!gpt_label_is_valid(label))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid GPT partition label.", strna(name));

        if (free_and_strdup(n, label) < 0)
                return json_log_oom(variant, flags);

        return 0;
}

static int json_dispatch_gpt_uuid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->gpt_uuid_set = false;
                return 0;
        }

        r = sd_json_dispatch_id128(name, variant, flags, &o->gpt_uuid);
        if (r < 0)
                return r;

        o->gpt_uuid_set = true;
        return 0;
}

static int json_dispatch_gpt_type_uuid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->gpt_type_uuid_set = false;
                return 0;
        }

        r = sd_json_dispatch_id128(name, variant, flags, &o->gpt_type_uuid);
        if (r < 0)
                return r;

        o->gpt_type_uuid_set = true;
        return 0;
}

static int json_dispatch_gpt_disk_uuid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->gpt_disk_uuid_set = false;
                return 0;
        }

        r = sd_json_dispatch_id128(name, variant, flags, &o->gpt_disk_uuid);
        if (r < 0)
                return r;

        o->gpt_disk_uuid_set = true;
        return 0;
}

static int json_dispatch_gpt_flags(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->gpt_flags_set = false;
                return 0;
        }

        r = sd_json_dispatch_uint64(name, variant, flags, &o->gpt_flags);
        if (r < 0)
                return r;

        o->gpt_flags_set = true;
        return 0;
}

static int json_dispatch_fat_serial(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->fat_serial_set = false;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = uapi16_fat_serial_from_string(sd_json_variant_string(variant), &o->fat_serial);
        if (r < 0)
                return json_log(variant, flags, r, "JSON field '%s' is not a valid FAT volume serial number.", strna(name));

        o->fat_serial_set = true;
        return 0;
}

static int json_dispatch_fs_uuid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                o->fs_uuid_set = false;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        /* The specification requires RFC 9562 formatting, i.e. with hyphens, hence refuse the plain hex
         * formatting sd_id128_from_string() also accepts */
        const char *t = sd_json_variant_string(variant);
        if (strlen(t) != SD_ID128_UUID_STRING_MAX - 1)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a UUID in RFC 9562 formatting.", strna(name));

        r = sd_id128_from_string(t, &o->fs_uuid);
        if (r < 0)
                return json_log(variant, flags, r, "JSON field '%s' is not a valid UUID.", strna(name));

        o->fs_uuid_set = true;
        return 0;
}

static int json_dispatch_fs_label(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **n = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *n = mfree(*n);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        const char *label = sd_json_variant_string(variant);
        if (!uapi16_fs_label_is_valid(label))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid file system label.", strna(name));

        if (free_and_strdup(n, label) < 0)
                return json_log_oom(variant, flags);

        return 0;
}

static int json_dispatch_validity(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Validity *v = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *v = _UAPI16_VALIDITY_INVALID;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        /* The specification requires unknown values to be treated like "good", to allow future extensions */
        *v = uapi16_validity_from_string(sd_json_variant_string(variant));
        if (*v < 0) {
                json_log(variant, flags|SD_JSON_DEBUG, 0, "Unknown validity '%s', treating as 'good'.", sd_json_variant_string(variant));
                *v = UAPI16_GOOD;
        }

        return 0;
}

static int xattr_compare(const Uapi16Xattr *a, const Uapi16Xattr *b) {
        return strcmp(a->name, b->name);
}

int uapi16_xattr_array_sort(Uapi16Xattr *x, size_t n) {
        assert(x || n == 0);

        /* Sort by the byte values of the UTF-8 names, as the specification recommends */
        typesafe_qsort(x, n, xattr_compare);

        for (size_t i = 1; i < n; i++)
                if (streq(x[i-1].name, x[i].name))
                        return -ENOTUNIQ;

        return 0;
}

static int json_dispatch_xattr_value(sd_json_variant *variant, sd_json_dispatch_flags_t flags, const char *name, struct iovec *ret) {
        int r;

        assert(variant);
        assert(name);
        assert(ret);

        if (!sd_json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Value of extended attribute '%s' is not an object.", name);

        sd_json_variant *text = sd_json_variant_by_key(variant, "text"),
                *base64 = sd_json_variant_by_key(variant, "base64");
        if (text && sd_json_variant_is_null(text))
                text = NULL;
        if (base64 && sd_json_variant_is_null(base64))
                base64 = NULL;

        if (!!text == !!base64)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Exactly one of 'text' and 'base64' must be set for extended attribute '%s'.", name);

        if (text) {
                if (!sd_json_variant_is_string(text))
                        return json_log(text, flags, SYNTHETIC_ERRNO(EINVAL), "Field 'text' of extended attribute '%s' is not a string.", name);

                /* NB: sd-json refuses NUL bytes in strings, hence no need to check for them here */
                const char *t = sd_json_variant_string(text);
                if (!iovec_memdup(&IOVEC_MAKE_STRING(t), ret))
                        return json_log_oom(variant, flags);

                return 0;
        }

        if (!sd_json_variant_is_string(base64))
                return json_log(base64, flags, SYNTHETIC_ERRNO(EINVAL), "Field 'base64' of extended attribute '%s' is not a string.", name);

        _cleanup_free_ void *p = NULL;
        size_t l = 0;
        r = unbase64mem(sd_json_variant_string(base64), &p, &l);
        if (r < 0)
                return json_log(base64, flags, r, "Field 'base64' of extended attribute '%s' is not valid Base64.", name);

        *ret = IOVEC_MAKE(TAKE_PTR(p), l);
        return 0;
}

static int json_dispatch_extended_attributes(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        uapi16_object_xattrs_done(o);

        if (sd_json_variant_is_null(variant))
                return 0;

        if (!sd_json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        const char *ns;
        sd_json_variant *nv;
        JSON_VARIANT_OBJECT_FOREACH(ns, nv, variant) {
                if (!streq(ns, "user")) {
                        json_log(nv, flags|SD_JSON_DEBUG, 0, "Ignoring unknown extended attribute namespace '%s'.", ns);
                        continue;
                }

                /* A null namespace object is equivalent to an absent one, i.e. conveys no information */
                if (sd_json_variant_is_null(nv))
                        continue;

                if (!sd_json_variant_is_object(nv))
                        return json_log(nv, flags, SYNTHETIC_ERRNO(EINVAL), "Extended attribute namespace '%s' is not an object.", ns);

                /* The JSON parser accepts duplicate keys, refuse them here */
                if (o->user_xattrs_set)
                        return json_log(nv, flags, SYNTHETIC_ERRNO(EINVAL), "Duplicate extended attribute namespace '%s', refusing.", ns);

                Uapi16Xattr *x = NULL;
                size_t n = 0;
                CLEANUP_ARRAY(x, n, uapi16_xattr_array_free);

                const char *k;
                sd_json_variant *e;
                JSON_VARIANT_OBJECT_FOREACH(k, e, nv) {
                        if (!uapi16_xattr_name_is_valid(k))
                                return json_log(nv, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid extended attribute name '%s', refusing.", k);

                        _cleanup_(iovec_done) struct iovec value = {};
                        r = json_dispatch_xattr_value(e, flags, k, &value);
                        if (r < 0)
                                return r;

                        _cleanup_free_ char *kk = strdup(k);
                        if (!kk)
                                return json_log_oom(variant, flags);

                        if (!GREEDY_REALLOC(x, n+1))
                                return json_log_oom(variant, flags);

                        x[n++] = (Uapi16Xattr) {
                                .name = TAKE_PTR(kk),
                                .value = TAKE_STRUCT(value),
                        };
                }

                r = uapi16_xattr_array_sort(x, n);
                if (r == -ENOTUNIQ)
                        return json_log(nv, flags, SYNTHETIC_ERRNO(EINVAL), "Duplicate extended attribute name, refusing.");
                if (r < 0)
                        return json_log(nv, flags, r, "Failed to sort extended attributes: %m");

                o->user_xattrs = TAKE_PTR(x);
                o->n_user_xattrs = TAKE_GENERIC(n, size_t, 0);
                o->user_xattrs_set = true;
        }

        return 0;
}

int uapi16_xattrs_build_json(const Uapi16Xattr *x, size_t n, sd_json_variant **ret) {
        int r;

        assert(x || n == 0);
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ns = NULL;
        r = sd_json_variant_new_object(&ns, /* array= */ NULL, 0);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, x, n) {
                /* Use "text" if the value is valid UTF-8 without any NUL bytes, as the specification asks
                 * for, and Base64 otherwise. */
                bool text = !iovec_is_set(&i->value) ||
                        (!memchr(i->value.iov_base, 0, i->value.iov_len) &&
                         utf8_is_valid_n(i->value.iov_base, i->value.iov_len));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *e = NULL;
                if (text)
                        /* NB: pass "" explicitly for empty values, since sd_json_variant_new_stringn() turns
                         * NULL into a JSON null */
                        r = sd_json_variant_new_stringn(&v, iovec_is_set(&i->value) ? i->value.iov_base : "", i->value.iov_len);
                else
                        r = sd_json_variant_new_base64(&v, i->value.iov_base, i->value.iov_len);
                if (r < 0)
                        return r;

                r = sd_json_buildo(&e, SD_JSON_BUILD_PAIR_VARIANT(text ? "text" : "base64", v));
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&ns, i->name, e);
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR_VARIANT("user", ns));
}

static bool sha256_is_empty(const struct iovec *sha256) {
        /* Returns true if the specified hash is the hash of the empty string */
        return iovec_memcmp(sha256, &IOVEC_MAKE(SHA256_EMPTY, SHA256_DIGEST_SIZE)) == 0;
}

static int process_sha256_and_size(
                sd_json_variant *v,
                sd_json_dispatch_flags_t flags,
                const char *name,
                struct iovec *sha256,
                uint64_t *size) {

        assert(v);
        assert(sha256);
        assert(size);

        if (sha256_is_empty(sha256)) {
                if (*size == UINT64_MAX)
                        *size = 0;
                else if (*size != 0)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "Length of file with zero hash is non-zero: %s", strna(name));

                return 1;
        }

        if (*size == 0) {
                if (iovec_is_set(sha256))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "Zero length file does not have zero hash: %s", strna(name));

                if (!iovec_memdup(&IOVEC_MAKE(SHA256_EMPTY, SHA256_DIGEST_SIZE), sha256))
                        return json_log_oom(v, flags);

                return 1;
        }

        return 0;
}

static int json_dispatch_http_headers(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char ***headers = ASSERT_PTR(userdata);
        int r;

        /* Parses a JSON object whose keys are HTTP field names and whose values are the field values to
         * send, as used by the UAPI.16 "httpHeaders" field. Returns them as a strv of name/value pairs. */

        if (sd_json_variant_is_null(variant)) {
                *headers = strv_free_erase(*headers);
                return 0;
        }

        if (!sd_json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        if (sd_json_variant_elements(variant) / 2 > HTTP_HEADERS_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(E2BIG), "Too many HTTP header fields in JSON field '%s', refusing.", strna(name));

        _cleanup_strv_free_erase_ char **l = NULL;
        const char *k;
        sd_json_variant *e;
        JSON_VARIANT_OBJECT_FOREACH(k, e, variant) {
                if (!http_field_name_is_valid(k))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP field name in JSON field '%s': %s", strna(name), k);

                /* HTTP field names are case-insensitive, hence refuse duplicates regardless of case */
                STRV_FOREACH_PAIR(a, b, l)
                        if (strcaseeq(*a, k))
                                return json_log(variant, flags, SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate HTTP field name in JSON field '%s': %s", strna(name), k);

                if (!sd_json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "Value of HTTP field '%s' in JSON field '%s' is not a string.", k, strna(name));

                /* Don't log the value, it might carry credentials */
                const char *v = sd_json_variant_string(e);
                if (!http_field_value_is_valid(v))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid value of HTTP field '%s' in JSON field '%s'.", k, strna(name));

                r = strv_extend_many(&l, k, v);
                if (r < 0)
                        return json_log_oom(variant, flags);
        }

        free_and_replace_full(*headers, l, strv_free_erase);
        return 0;
}

static int json_dispatch_contents(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16Object *o = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                FOREACH_ARRAY(c, o->contents, o->n_contents)
                        uapi16_contents_done(c);

                o->contents = mfree(o->contents);
                o->n_contents = 0;
                return 0;
        }

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        sd_json_variant *s;
        JSON_VARIANT_ARRAY_FOREACH(s, variant) {
                /* The specification says null fields are equivalent to absent ones, hence SD_JSON_NULLABLE */
                static const sd_json_dispatch_field dispatch_table[] = {
                        { "file",           SD_JSON_VARIANT_STRING,        json_dispatch_uapi16_name,     offsetof(Uapi16Contents, file),            SD_JSON_NULLABLE },
                        { "url",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(Uapi16Contents, url),             SD_JSON_NULLABLE },
                        { "httpHeaders",    SD_JSON_VARIANT_OBJECT,        json_dispatch_http_headers,    offsetof(Uapi16Contents, http_headers),    SD_JSON_NULLABLE },
                        { "literal",        SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec,  offsetof(Uapi16Contents, literal),         SD_JSON_NULLABLE },
                        { "encoding",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(Uapi16Contents, encoding),        SD_JSON_NULLABLE },
                        { "encodedSize",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(Uapi16Contents, encoded_size),    0                },
                        { "encodedSha256",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec32,   offsetof(Uapi16Contents, encoded_sha256),  SD_JSON_NULLABLE },
                        { "originalSize",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(Uapi16Contents, original_size),   0                },
                        { "originalSha256", SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec32,   offsetof(Uapi16Contents, original_sha256), SD_JSON_NULLABLE },
                        { "offset",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(Uapi16Contents, offset),          0                },
                        {}
                };

                _cleanup_(uapi16_contents_done) Uapi16Contents c = UAPI16_CONTENTS_NULL;
                /* Inherit the logging/strictness behaviour from the caller, but not the flags specific to
                 * the "contents" field itself */
                r = sd_json_dispatch(s, dispatch_table, (flags & ~(SD_JSON_MANDATORY|SD_JSON_NULLABLE|SD_JSON_REFUSE_NULL)) | SD_JSON_ALLOW_EXTENSIONS, &c);
                if (r < 0)
                        return r;

                if (!!c.file + !!c.url + uapi16_contents_has_literal(&c) > 1)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Only one of 'file', 'url', 'literal' may be set for '%s'.", strna(name));

                if (!strv_isempty(c.http_headers) && !c.url)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Field 'httpHeaders' may only be set together with 'url' for '%s'.", strna(name));

                if (c.encoding) {
                        /* The encodings are the ones of HTTP's Content-Encoding:, which are case-insensitive,
                         * hence normalize. HTTP's "identity" is not permitted though: no encoding is expressed
                         * by leaving the field unset. */
                        if (isempty(c.encoding))
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Empty encoding of contents for '%s'.", strna(name));

                        ascii_strlower(c.encoding);
                        if (streq(c.encoding, "identity"))
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Encoding 'identity' of contents for '%s' is not permitted, leave the field unset instead.", strna(name));
                }

                r = process_sha256_and_size(s, flags, name, &c.encoded_sha256, &c.encoded_size);
                if (r < 0)
                        return r;
                r = process_sha256_and_size(s, flags, name, &c.original_sha256, &c.original_size);
                if (r < 0)
                        return r;

                if (!c.encoding) {
                        /* If there's no encoding then the original and the encoded size and hash are the
                         * same, hence let's fill in one from the other, or refuse if both are set and don't
                         * match. */
                        if (c.encoded_size == UINT64_MAX && c.original_size != UINT64_MAX)
                                c.encoded_size = c.original_size;
                        else if (c.encoded_size != UINT64_MAX && c.original_size == UINT64_MAX)
                                c.original_size = c.encoded_size;
                        else if (c.encoded_size != c.original_size)
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Encoded and original size of contents without encoding do not match for '%s'.", strna(name));

                        if (!iovec_is_set(&c.encoded_sha256) && iovec_is_set(&c.original_sha256)) {
                                if (iovec_done_and_memdup(&c.encoded_sha256, &c.original_sha256) < 0)
                                        return json_log_oom(variant, flags);
                        } else if (iovec_is_set(&c.encoded_sha256) && !iovec_is_set(&c.original_sha256)) {
                                if (iovec_done_and_memdup(&c.original_sha256, &c.encoded_sha256) < 0)
                                        return json_log_oom(variant, flags);
                        } else if (iovec_memcmp(&c.encoded_sha256, &c.original_sha256) != 0)
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Encoded and original hash of contents without encoding do not match for '%s'.", strna(name));
                }

                if (c.offset == UINT64_MAX)
                        c.offset = 0;
                else if (c.original_size != UINT64_MAX && c.offset > c.original_size)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Offset of contents entry is beyond file size for '%s'.", strna(name));

                if (o->n_contents >= CONTENTS_MAX)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(E2BIG), "Too many contents array entries, refusing.");

                if (!GREEDY_REALLOC(o->contents, o->n_contents+1))
                        return json_log_oom(variant, flags);

                o->contents[o->n_contents++] = TAKE_GENERIC(c, Uapi16Contents, UAPI16_CONTENTS_NULL);
        }

        return 0;
}

static int uapi16_object_validate(sd_json_variant *v, sd_json_dispatch_flags_t flags, const Uapi16Object *o, bool is_root) {
        assert(v);
        assert(o);

        /* Refuses fields that the specification does not permit on the object's inode type, and fields that
         * contradict each other. */

        const char *t = strna(inode_type_to_string(o->type));

        if (o->size != UINT64_MAX && !IN_SET(o->type, S_IFREG, S_IFLNK, S_IFDIR))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'size' is not permitted on inode type '%s', refusing.", t);

        if ((o->major != UINT64_MAX || o->minor != UINT64_MAX) && !IN_SET(o->type, S_IFBLK, S_IFCHR))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'major' and 'minor' are not permitted on inode type '%s', refusing.", t);

        if (o->mode != MODE_INVALID && o->type == S_IFLNK)
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'mode' is not permitted on symlinks, refusing.");

        if (!IN_SET(o->inode_token, 0, UINT64_MAX) && o->type == S_IFDIR)
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'inodeToken' is not permitted on directories, refusing.");

        if ((o->n_contents > 0 || iovec_is_set(&o->sha256)) && !IN_SET(o->type, S_IFREG, S_IFLNK, S_IFDIR))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'contents' and 'sha256' are not permitted on inode type '%s', refusing.", t);

        if ((o->gpt_label || o->gpt_uuid_set || o->gpt_type_uuid_set || o->gpt_flags_set || o->gpt_no_auto >= 0 || o->gpt_growfs >= 0) &&
            o->type != S_IFREG)
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "GPT partition fields are not permitted on inode type '%s', refusing.", t);

        if (o->gpt_disk_uuid_set && !is_root)
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'gptDiskUuid' is only permitted on the root object, refusing.");

        if (o->read_only >= 0 && o->mode != MODE_INVALID && (o->read_only == 0) != ((o->mode & 0222) != 0))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'readOnly' and 'mode' contradict each other, refusing.");

        /* NB: the generic "readOnly" field is not subject to these restrictions, even though it also encodes
         * the FAT read-only attribute */
        if (o->flag_hidden >= 0 || o->flag_system >= 0 || o->flag_archive >= 0) {
                /* The root directory of a FAT file system has no directory entry, hence no attributes */
                if (is_root)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "FAT attribute fields are not permitted on the root object, refusing.");
                if (!IN_SET(o->type, S_IFREG, S_IFDIR))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "FAT attribute fields are not permitted on inode type '%s', refusing.", t);
        }

        if ((o->fat_serial_set || o->fs_uuid_set || o->fs_label) && !is_root)
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'fatSerial', 'fsUUID' and 'fsLabel' are only permitted on the root object, refusing.");

        unsigned inode_mask;
        uapi16_object_inode_flags(o, /* ret_value= */ NULL, &inode_mask);
        if (inode_mask != 0 && !IN_SET(o->type, S_IFREG, S_IFDIR))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Inode flag fields are not permitted on inode type '%s', refusing.", t);

        return 0;
}

static const struct {
        ManifestField feature;
        size_t offset;
        bool fat_attr; /* The root directory of a FAT file system has no directory entry, hence no attributes */
} flag_feature_table[] = {
        { MANIFEST_FIELD_FLAG_APPEND_ONLY, offsetof(Uapi16Object, flag_append_only), false },
        { MANIFEST_FIELD_FLAG_IMMUTABLE,   offsetof(Uapi16Object, flag_immutable),   false },
        { MANIFEST_FIELD_FLAG_NO_ATIME,    offsetof(Uapi16Object, flag_no_atime),    false },
        { MANIFEST_FIELD_FLAG_NO_COW,      offsetof(Uapi16Object, flag_no_cow),      false },
        { MANIFEST_FIELD_FLAG_NO_DUMP,     offsetof(Uapi16Object, flag_no_dump),     false },
        { MANIFEST_FIELD_FLAG_HIDDEN,      offsetof(Uapi16Object, flag_hidden),      true  },
        { MANIFEST_FIELD_FLAG_SYSTEM,      offsetof(Uapi16Object, flag_system),      true  },
        { MANIFEST_FIELD_FLAG_ARCHIVE,     offsetof(Uapi16Object, flag_archive),     true  },
};

static int uapi16_object_apply_features(sd_json_variant *v, sd_json_dispatch_flags_t flags, Uapi16Object *o, bool is_root) {
        assert(v);
        assert(o);
        assert(o->features >= 0);

        /* Refuses fields of features the manifest does not list, and then initializes the fields whose
         * absence carries meaning if the manifest lists their feature. Must be called before any fields
         * are derived from others, as that would make them appear set. */

        ManifestField carried =
                (o->mode != MODE_INVALID ? MANIFEST_FIELD_MODE : 0) |
                (o->uid != UID_INVALID ? MANIFEST_FIELD_UID : 0) |
                (o->gid != GID_INVALID ? MANIFEST_FIELD_GID : 0) |
                (o->user_name ? MANIFEST_FIELD_USER_NAME : 0) |
                (o->group_name ? MANIFEST_FIELD_GROUP_NAME : 0) |
                (o->size != UINT64_MAX ? MANIFEST_FIELD_SIZE : 0) |
                (iovec_is_set(&o->sha256) ? MANIFEST_FIELD_HASH : 0) |
                (o->type == S_IFLNK && o->n_contents > 0 ? MANIFEST_FIELD_SYMLINK : 0) |
                (o->major != UINT64_MAX || o->minor != UINT64_MAX ? MANIFEST_FIELD_DEVICE : 0) |
                (o->inode_token != UINT64_MAX ? MANIFEST_FIELD_HARDLINK : 0) |
                (o->mtime_nsec != NSEC_INFINITY ? MANIFEST_FIELD_MTIME : 0) |
                (o->user_xattrs_set ? MANIFEST_FIELD_USER_XATTR : 0) |
                (o->read_only >= 0 ? MANIFEST_FIELD_READ_ONLY : 0) |
                (o->fs_uuid_set ? MANIFEST_FIELD_FS_UUID : 0) |
                (o->fs_label ? MANIFEST_FIELD_FS_LABEL : 0) |
                (o->fat_serial_set ? MANIFEST_FIELD_FAT_SERIAL : 0) |
                (o->gpt_label ? MANIFEST_FIELD_GPT_LABEL : 0) |
                (o->gpt_uuid_set ? MANIFEST_FIELD_GPT_UUID : 0) |
                (o->gpt_type_uuid_set ? MANIFEST_FIELD_GPT_TYPE_UUID : 0) |
                (o->gpt_disk_uuid_set ? MANIFEST_FIELD_GPT_DISK_UUID : 0) |
                (o->gpt_flags_set ? MANIFEST_FIELD_GPT_FLAGS : 0) |
                (o->gpt_no_auto >= 0 ? MANIFEST_FIELD_GPT_FLAG_NO_AUTO : 0) |
                (o->gpt_growfs >= 0 ? MANIFEST_FIELD_GPT_FLAG_GROWFS : 0);

        FOREACH_ELEMENT(i, flag_feature_table)
                if (*(const int*) ((const uint8_t*) o + i->offset) >= 0)
                        carried |= i->feature;

        BIT_FOREACH(b, (unsigned) (carried & ~o->features))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG),
                                "File object carries field of feature '%s', which the manifest does not list, refusing.",
                                manifest_field_to_uapi16_feature(1 << b));

        /* If the feature is listed, every symlink carries its target */
        if (FLAGS_SET(o->features, MANIFEST_FIELD_SYMLINK) && o->type == S_IFLNK) {
                bool found = false;

                FOREACH_ARRAY(c, o->contents, o->n_contents)
                        if (uapi16_contents_has_literal(c)) {
                                found = true;
                                break;
                        }

                if (!found)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG),
                                        "Symlink object does not carry its target, even though the manifest lists the 'symlink' feature, refusing.");
        }

        /* If the feature is listed, an absent "inodeToken" means the file is not subject to hardlinks */
        if (FLAGS_SET(o->features, MANIFEST_FIELD_HARDLINK) && o->inode_token == UINT64_MAX)
                o->inode_token = 0;

        /* If the feature is listed, an absent "user" namespace object means there are no such attributes */
        if (FLAGS_SET(o->features, MANIFEST_FIELD_USER_XATTR) && !o->user_xattrs_set) {
                assert(o->n_user_xattrs == 0);
                o->user_xattrs_set = true;
        }

        /* If the feature is listed, an absent flag field means the flag is cleared. But only where the
         * flag is defined at all, see uapi16_object_validate(). */
        if (IN_SET(o->type, S_IFREG, S_IFDIR))
                FOREACH_ELEMENT(i, flag_feature_table) {
                        int *b = (int*) ((uint8_t*) o + i->offset);

                        if (FLAGS_SET(o->features, i->feature) && *b < 0 && !(i->fat_attr && is_root))
                                *b = false;
                }

        /* If the feature is listed, an absent "readOnly" means the object is not read-only */
        if (FLAGS_SET(o->features, MANIFEST_FIELD_READ_ONLY) && o->read_only < 0)
                o->read_only = false;

        /* If the feature is listed, an absent "fsLabel" means the file system has no label */
        if (FLAGS_SET(o->features, MANIFEST_FIELD_FS_LABEL) && is_root && !o->fs_label) {
                o->fs_label = strdup("");
                if (!o->fs_label)
                        return json_log_oom(v, flags);
        }

        /* If the features are listed, absent partition attribute flag fields mean the flags are cleared. But
         * only where these fields are defined at all, see uapi16_object_validate(). */
        if (o->type == S_IFREG) {
                if (FLAGS_SET(o->features, MANIFEST_FIELD_GPT_FLAGS) && !o->gpt_flags_set) {
                        o->gpt_flags = 0;
                        o->gpt_flags_set = true;
                }
                if (FLAGS_SET(o->features, MANIFEST_FIELD_GPT_FLAG_NO_AUTO) && o->gpt_no_auto < 0)
                        o->gpt_no_auto = false;
                if (FLAGS_SET(o->features, MANIFEST_FIELD_GPT_FLAG_GROWFS) && o->gpt_growfs < 0)
                        o->gpt_growfs = false;
        }

        /* The individual partition attribute flag fields must be consistent with the raw flags. This is
         * checked only now, as absent fields count as cleared if their features are listed. */
        if (o->gpt_flags_set &&
            ((o->gpt_no_auto >= 0 && FLAGS_SET(o->gpt_flags, SD_GPT_FLAG_NO_AUTO) != o->gpt_no_auto) ||
             (o->gpt_growfs >= 0 && FLAGS_SET(o->gpt_flags, SD_GPT_FLAG_GROWFS) != o->gpt_growfs) ||
             (o->read_only >= 0 && FLAGS_SET(o->gpt_flags, SD_GPT_FLAG_READ_ONLY) != o->read_only)))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'gptFlags' and 'gptFlag*' or 'readOnly' contradict each other, refusing.");

        return 0;
}

int dispatch_uapi16_object(sd_json_variant *v, const Uapi16Object *root, sd_json_dispatch_flags_t flags, Uapi16Object *ret) {
        assert(ret);

        /* The specification says null fields are equivalent to absent ones, hence SD_JSON_NULLABLE */
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",                  SD_JSON_VARIANT_STRING,        json_dispatch_uapi16_name,         offsetof(Uapi16Object, name),             SD_JSON_NULLABLE },
                { "mediaType",             SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,           offsetof(Uapi16Object, media_type),       SD_JSON_NULLABLE },
                { "features",              SD_JSON_VARIANT_ARRAY,         json_dispatch_features,            offsetof(Uapi16Object, features),         SD_JSON_NULLABLE },
                { "order",                 SD_JSON_VARIANT_STRING,        json_dispatch_order,               offsetof(Uapi16Object, order),            SD_JSON_NULLABLE },
                { "type",                  SD_JSON_VARIANT_STRING,        json_dispatch_inode_type,          offsetof(Uapi16Object, type),             SD_JSON_NULLABLE },
                { "size",                  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, size),             0                },
                { "mode",                  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode,         offsetof(Uapi16Object, mode),             0                },
                { "uid",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,          offsetof(Uapi16Object, uid),              0                },
                { "gid",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,          offsetof(Uapi16Object, gid),              0                },
                /* The specification recommends accepting user/group names liberally, hence SD_JSON_RELAX */
                { "userName",              SD_JSON_VARIANT_STRING,        json_dispatch_user_group_name,     offsetof(Uapi16Object, user_name),        SD_JSON_NULLABLE|SD_JSON_RELAX },
                { "groupName",             SD_JSON_VARIANT_STRING,        json_dispatch_user_group_name,     offsetof(Uapi16Object, group_name),       SD_JSON_NULLABLE|SD_JSON_RELAX },
                { "major",                 _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, major),            0                },
                { "minor",                 _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, minor),            0                },
                { "mTimeNSec",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, mtime_nsec),       0                },
                { "inodeToken",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, inode_token),      0                },
                { "extendedAttributes",    SD_JSON_VARIANT_OBJECT,        json_dispatch_extended_attributes, 0,                                        SD_JSON_NULLABLE },
                { "gptLabel",              SD_JSON_VARIANT_STRING,        json_dispatch_gpt_label,           offsetof(Uapi16Object, gpt_label),        SD_JSON_NULLABLE },
                { "gptUuid",               SD_JSON_VARIANT_STRING,        json_dispatch_gpt_uuid,            0,                                        SD_JSON_NULLABLE },
                { "gptTypeUuid",           SD_JSON_VARIANT_STRING,        json_dispatch_gpt_type_uuid,       0,                                        SD_JSON_NULLABLE },
                { "gptDiskUuid",           SD_JSON_VARIANT_STRING,        json_dispatch_gpt_disk_uuid,       0,                                        SD_JSON_NULLABLE },
                { "gptFlags",              _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_gpt_flags,           0,                                        0                },
                { "gptFlagNoAuto",         SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, gpt_no_auto),      SD_JSON_NULLABLE },
                { "gptFlagGrowFileSystem", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, gpt_growfs),       SD_JSON_NULLABLE },
                { "readOnly",              SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, read_only),        SD_JSON_NULLABLE },
                { "flagHidden",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_hidden),      SD_JSON_NULLABLE },
                { "flagSystem",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_system),      SD_JSON_NULLABLE },
                { "flagArchive",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_archive),     SD_JSON_NULLABLE },
                { "fatSerial",             SD_JSON_VARIANT_STRING,        json_dispatch_fat_serial,          0,                                        SD_JSON_NULLABLE },
                { "fsUUID",                SD_JSON_VARIANT_STRING,        json_dispatch_fs_uuid,             0,                                        SD_JSON_NULLABLE },
                { "fsLabel",               SD_JSON_VARIANT_STRING,        json_dispatch_fs_label,            offsetof(Uapi16Object, fs_label),         SD_JSON_NULLABLE },
                { "flagAppendOnly",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_append_only), SD_JSON_NULLABLE },
                { "flagImmutable",         SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_immutable),   SD_JSON_NULLABLE },
                { "flagNoAtime",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_no_atime),    SD_JSON_NULLABLE },
                { "flagNoCow",             SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_no_cow),      SD_JSON_NULLABLE },
                { "flagNoDump",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,         offsetof(Uapi16Object, flag_no_dump),     SD_JSON_NULLABLE },
                { "contents",              SD_JSON_VARIANT_ARRAY,         json_dispatch_contents,            0,                                        SD_JSON_NULLABLE },
                { "sha256",                SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec32,       offsetof(Uapi16Object, sha256),           SD_JSON_NULLABLE },
                { "validSinceUSec",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, valid_since_usec), 0                },
                { "validUntilUSec",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,           offsetof(Uapi16Object, valid_until_usec), 0                },
                { "validity",              SD_JSON_VARIANT_STRING,        json_dispatch_validity,            offsetof(Uapi16Object, validity),         SD_JSON_NULLABLE },
                {}
        };

        int r;

        _cleanup_(uapi16_object_done) Uapi16Object object = UAPI16_OBJECT_NULL;
        r = sd_json_dispatch(v, dispatch_table, flags, &object);
        if (r < 0)
                return r;

        /* sd_json_dispatch_uint64() turns null into UINT64_MAX, but an unset start of the validity window
         * means 0 */
        if (object.valid_since_usec == USEC_INFINITY)
                object.valid_since_usec = 0;

        if (object.media_type && !streq(object.media_type, UAPI16_MANIFEST_MEDIA_TYPE))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Manifest object has unexpected media type '%s', refusing.", object.media_type);

        if (!root) {
                if (!object.media_type)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "First manifest object does not carry mediaType field, refusing.");

                if (object.name)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Initial manifest object has the name field set, refusing.");

                if (!IN_SET(object.type, 0, S_IFDIR))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Initial manifest object has unexpected inode type '%s', refusing.", strna(inode_type_to_string(object.type)));

                object.type = S_IFDIR;

                if (object.features < 0)
                        object.features = _MANIFEST_FIELD_DEFAULT;
        } else {
                if (!object.name)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Manifest object has no name field set, refusing.");

                if (object.type == 0)
                        object.type = S_IFREG;

                if (object.features >= 0)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'features' is only permitted on the root object, refusing.");

                if (object.order != _UAPI16_ORDER_INVALID)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Field 'order' is only permitted on the root object, refusing.");

                /* Inherit the manifest's features, so that users of the object know what it records */
                assert(root->features >= 0);
                object.features = root->features;
        }

        r = uapi16_object_validate(v, flags, &object, /* is_root= */ !root);
        if (r < 0)
                return r;

        r = uapi16_object_apply_features(v, flags, &object, /* is_root= */ !root);
        if (r < 0)
                return r;

        r = process_sha256_and_size(v, flags, /* name= */ NULL, &object.sha256, &object.size);
        if (r < 0)
                return r;

        /* Validate size/hash of object against contents */
        FOREACH_ARRAY(c, object.contents, object.n_contents) {
                assert(c->offset != UINT64_MAX);

                if (object.size != UINT64_MAX) {
                        /* Make sure offset + object size fit into the source size */

                        if (c->offset > UINT64_MAX - object.size ||
                            (c->original_size != UINT64_MAX && c->offset + object.size > c->original_size))
                                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Offset is beyond file size.");

                } else if (c->original_size != UINT64_MAX) {
                        /* Propagate contents size into object */

                        assert(c->offset <= c->original_size);
                        object.size = c->original_size - c->offset;
                }

                if (iovec_is_set(&object.sha256)) {
                        if (c->offset == 0 &&
                            object.size != UINT64_MAX &&
                            c->original_size == object.size) {
                                /* The object has the same size as the contents. In that case the SHA256 sums must match too */

                                if (iovec_is_set(&c->original_sha256)) {
                                        if (!iovec_equal(&object.sha256, &c->original_sha256))
                                                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Hash of object and contents does not match.");
                                } else {
                                        if (!iovec_memdup(&object.sha256, &c->original_sha256))
                                                return json_log_oom(v, flags);
                                }
                        }
                } else {
                        /* Propagate contents hash into object */

                        if (iovec_is_set(&c->original_sha256) &&
                            c->offset == 0 &&
                            object.size != UINT64_MAX &&
                            c->original_size == object.size)
                                if (!iovec_memdup(&c->original_sha256, &object.sha256))
                                        return json_log_oom(v, flags);
                }
        }

        *ret = TAKE_GENERIC(object, Uapi16Object, UAPI16_OBJECT_NULL);
        return 1;
}

static const char* const uapi16_validity_table[] = {
        [UAPI16_REVOKED] = "revoked",
        [UAPI16_GOOD]    = "good",
};

DEFINE_STRING_TABLE_LOOKUP(uapi16_validity, Uapi16Validity);

int uapi16_object_media_type(sd_json_variant *v, const char **ret) {
        assert(v);
        assert(ret);

        sd_json_variant *mt = sd_json_variant_by_key(v, "mediaType");
        if (!mt) {
                *ret = NULL;
                return 0;
        }

        if (!sd_json_variant_is_string(mt))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "JSON field 'mediaType' is not a string.");

        *ret = sd_json_variant_string(mt);
        return 1;
}

static const char* const uapi16_signature_mechanism_table[_UAPI16_SIGNATURE_MECHANISM_MAX] = {
        [UAPI16_SIGNATURE_PKCS7] = "pkcs7",
};

DEFINE_STRING_TABLE_LOOKUP(uapi16_signature_mechanism, Uapi16SignatureMechanism);

void uapi16_signature_done(Uapi16Signature *s) {
        assert(s);

        s->media_type = mfree(s->media_type);
        iovec_done(&s->key);
        iovec_done(&s->data);
}

static int json_dispatch_signature_mechanism(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Uapi16SignatureMechanism *m = ASSERT_PTR(userdata);

        if (sd_json_variant_is_null(variant)) {
                *m = _UAPI16_SIGNATURE_MECHANISM_INVALID;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        /* Unknown or unsupported mechanisms (such as "openpgp") are not an error: we just cannot verify with
         * them, hence store as invalid */
        *m = uapi16_signature_mechanism_from_string(sd_json_variant_string(variant));
        if (*m < 0)
                json_log(variant, flags|SD_JSON_DEBUG, 0, "Unsupported signature mechanism '%s', ignoring.", sd_json_variant_string(variant));

        return 0;
}

int dispatch_uapi16_signature_object(sd_json_variant *v, sd_json_dispatch_flags_t flags, Uapi16Signature *ret) {
        int r;

        assert(v);
        assert(ret);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "mediaType", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,           offsetof(Uapi16Signature, media_type), SD_JSON_MANDATORY },
                { "mechanism", SD_JSON_VARIANT_STRING, json_dispatch_signature_mechanism, offsetof(Uapi16Signature, mechanism),  SD_JSON_MANDATORY },
                { "key",       SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec,         offsetof(Uapi16Signature, key),        SD_JSON_NULLABLE  },
                /* Only the mechanism is mandatory as per spec, whether there's data depends on it */
                { "data",      SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec,      offsetof(Uapi16Signature, data),       SD_JSON_NULLABLE  },
                {}
        };

        _cleanup_(uapi16_signature_done) Uapi16Signature o = UAPI16_SIGNATURE_NULL;
        r = sd_json_dispatch(v, dispatch_table, flags, &o);
        if (r < 0)
                return r;

        if (!streq_ptr(o.media_type, UAPI16_SIGNATURE_MEDIA_TYPE))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Signature object has unexpected media type '%s', refusing.", strnull(o.media_type));

        *ret = TAKE_STRUCT(o);
        return 0;
}

#if HAVE_OPENSSL
struct Uapi16Signer {
        X509 *certificate; /* Not owned */
        CMS_ContentInfo *cms;
        BIO *bio;
};
#endif

Uapi16Signer* uapi16_signer_free(Uapi16Signer *s) {
#if HAVE_OPENSSL
        if (!s)
                return NULL;

        if (s->bio)
                sym_BIO_free_all(s->bio);
        if (s->cms)
                sym_CMS_ContentInfo_free(s->cms);

        return mfree(s);
#else
        assert(!s);
        return NULL;
#endif
}

int uapi16_signer_new(X509 *certificate, EVP_PKEY *private_key, Uapi16Signer **ret) {
#if HAVE_OPENSSL
        int r;

        assert(certificate);
        assert(private_key);
        assert(ret);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_(uapi16_signer_freep) Uapi16Signer *s = new(Uapi16Signer, 1);
        if (!s)
                return log_oom();

        *s = (Uapi16Signer) {
                .certificate = certificate,
        };

        /* PKCS#7 SignedData and CMS SignedData share their OID and wire format. We go through OpenSSL's
         * CMS API rather than its legacy PKCS7 API, since only the former knows how to sign with EdDSA
         * keys (RFC 8419).
         *
         * Without signed attributes the signature is made directly over the digest of the data, which
         * keeps the signature minimal, and makes the output deterministic where the algorithm is. This is
         * not possible with EdDSA though: a pure EdDSA signature is computed over the whole message in one
         * go, and hence cannot be applied to a stream. RFC 8419 addresses this by requiring signed
         * attributes, so that the signature is over a small attribute set which in turn carries the digest
         * of the content, and mandates SHA-512 as digest algorithm. (Ed448 is not supported: RFC 8419 wants
         * SHAKE256 with a 512 bit output there, which does not fit our digest BIO chain on the verifying
         * side, and OpenSSL's handling of that is hardly interoperable anyway.) */
        const EVP_MD *md = NULL;
        unsigned flags = CMS_DETACHED|CMS_BINARY|CMS_PARTIAL|CMS_NOATTR|CMS_NOSMIMECAP;

        switch (sym_EVP_PKEY_get_base_id(private_key)) {

        case EVP_PKEY_ED25519:
                /* OpenSSL < 3.2 refuses to combine EdDSA keys with an explicit digest, which CMS requires
                 * however. It only fails once the signature is finalized, i.e. after all data went through,
                 * hence check early. Check the version of the library we actually loaded, not the one we
                 * were built against. */
                if (sym_OpenSSL_version_num() < 0x30200000UL)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Signing with Ed25519 keys requires OpenSSL 3.2 or newer.");

                md = sym_EVP_sha512();
                flags &= ~CMS_NOATTR;
                break;

        case EVP_PKEY_ED448:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signing with Ed448 keys is not supported.");

        default:
                /* Let OpenSSL pick the default digest for the key type */
                break;
        }

        /* Set up a detached signature, but don't provide the data yet: we'll feed it incrementally via the
         * BIO CMS_dataInit() gives us, and finalize once everything went through. */
        s->cms = sym_CMS_sign(/* signcert= */ NULL, /* pkey= */ NULL, /* certs= */ NULL, /* data= */ NULL, flags);
        if (!s->cms)
                return log_openssl_errors(LOG_ERR, "Failed to set up PKCS#7 signature");

        if (!sym_CMS_add1_signer(s->cms, certificate, private_key, md, flags))
                return log_openssl_errors(LOG_ERR, "Failed to add signer to PKCS#7 signature");

        s->bio = sym_CMS_dataInit(s->cms, /* icont= */ NULL);
        if (!s->bio)
                return log_openssl_errors(LOG_ERR, "Failed to set up PKCS#7 data BIO");

        *ret = TAKE_PTR(s);
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signing not supported, OpenSSL support disabled.");
#endif
}

int uapi16_signer_feed(Uapi16Signer *s, const void *data, size_t size) {
#if HAVE_OPENSSL
        assert(s);
        assert(data || size == 0);

        if (size == 0)
                return 0;

        if (size > INT_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Record too large to sign.");

        if (sym_BIO_write(s->bio, data, size) != (int) size)
                return log_openssl_errors(LOG_ERR, "Failed to feed data into PKCS#7 signature");

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int uapi16_signer_finish(Uapi16Signer *s, sd_json_variant **ret) {
#if HAVE_OPENSSL
        int r;

        assert(s);
        assert(ret);

        if (sym_CMS_dataFinal(s->cms, s->bio) <= 0)
                return log_openssl_errors(LOG_ERR, "Failed to finalize PKCS#7 signature");

        _cleanup_(OPENSSL_freep) void *der = NULL;
        int der_size = sym_i2d_CMS_ContentInfo(s->cms, (unsigned char**) &der);
        if (der_size < 0)
                return log_openssl_errors(LOG_ERR, "Failed to convert PKCS#7 signature to DER");

        uint8_t fingerprint[X509_FINGERPRINT_SIZE];
        r = x509_fingerprint(s->certificate, fingerprint);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate certificate fingerprint: %m");

        r = sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("mediaType", UAPI16_SIGNATURE_MEDIA_TYPE),
                        SD_JSON_BUILD_PAIR_STRING("mechanism", uapi16_signature_mechanism_to_string(UAPI16_SIGNATURE_PKCS7)),
                        SD_JSON_BUILD_PAIR_HEX("key", fingerprint, sizeof(fingerprint)),
                        SD_JSON_BUILD_PAIR_BASE64("data", der, der_size));
        if (r < 0)
                return log_error_errno(r, "Failed to build signature object: %m");

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

typedef struct Uapi16SignatureVerifier Uapi16SignatureVerifier;

#if HAVE_OPENSSL
struct Uapi16SignatureVerifier {
        X509 *const *certificates;      /* Not owned */
        size_t n_certificates;
        uint8_t (*fingerprints)[X509_FINGERPRINT_SIZE];
        BIO *bio;
};
#endif

static Uapi16SignatureVerifier* uapi16_signature_verifier_free(Uapi16SignatureVerifier *v) {
#if HAVE_OPENSSL
        if (!v)
                return NULL;

        if (v->bio)
                sym_BIO_free_all(v->bio);

        free(v->fingerprints);
        return mfree(v);
#else
        assert(!v);
        return NULL;
#endif
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Uapi16SignatureVerifier*, uapi16_signature_verifier_free);

static int uapi16_signature_verifier_new(
                X509 *const *certificates,
                size_t n_certificates,
                Uapi16SignatureVerifier **ret) {

#if HAVE_OPENSSL
        int r;

        assert(certificates);
        assert(n_certificates > 0);
        assert(ret);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_(uapi16_signature_verifier_freep) Uapi16SignatureVerifier *v = new(Uapi16SignatureVerifier, 1);
        if (!v)
                return log_oom();

        *v = (Uapi16SignatureVerifier) {
                .certificates = certificates,
                .n_certificates = n_certificates,
        };

        v->fingerprints = malloc_multiply(n_certificates, sizeof(*v->fingerprints));
        if (!v->fingerprints)
                return log_oom();

        for (size_t i = 0; i < n_certificates; i++) {
                r = x509_fingerprint(certificates[i], v->fingerprints[i]);
                if (r < 0)
                        return log_error_errno(r, "Failed to calculate certificate fingerprint: %m");
        }

        /* We only learn which digest algorithm the signature uses once we reach the signature object at
         * the end of the stream. Hence run the data through a chain of digest BIOs for all algorithms we
         * might encounter, and pick the right one at the end. This is what CMS_verify() does internally,
         * except that we do not have to hold the data in memory. */
        v->bio = sym_BIO_new(sym_BIO_s_null());
        if (!v->bio)
                return log_oom();

        const EVP_MD *mds[] = {
                sym_EVP_sha256(),
                sym_EVP_sha384(),
                sym_EVP_sha512(),
        };

        FOREACH_ELEMENT(md, mds) {
                BIO *b = sym_BIO_new(sym_BIO_f_md());
                if (!b)
                        return log_oom();

                if (sym_BIO_set_md(b, *md) <= 0) {
                        sym_BIO_free(b);
                        return log_openssl_errors(LOG_ERR, "Failed to set digest of BIO");
                }

                v->bio = sym_BIO_push(b, v->bio);
        }

        *ret = TAKE_PTR(v);
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signature verification not supported, OpenSSL support disabled.");
#endif
}

static int uapi16_signature_verifier_feed(Uapi16SignatureVerifier *v, const void *data, size_t size) {
#if HAVE_OPENSSL
        assert(v);
        assert(data || size == 0);

        if (size == 0)
                return 0;

        if (size > INT_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Record too large to verify.");

        if (sym_BIO_write(v->bio, data, size) != (int) size)
                return log_openssl_errors(LOG_ERR, "Failed to feed data into digest");

        return 0;
#else
        assert_not_reached();
#endif
}

#if HAVE_OPENSSL
static bool uapi16_signature_verifier_certificate_applies(
                Uapi16SignatureVerifier *v,
                size_t i,
                const Uapi16Signature *sig) {

        assert(v);
        assert(i < v->n_certificates);
        assert(sig);

        /* A signature that does not name its key is checked against all certificates */
        return !iovec_is_set(&sig->key) ||
                iovec_equal(&sig->key, &IOVEC_MAKE(v->fingerprints[i], X509_FINGERPRINT_SIZE));
}
#endif

static int uapi16_signature_verifier_finish(Uapi16SignatureVerifier *v, const Uapi16Signature *sig) {
#if HAVE_OPENSSL
        bool tried = false;

        assert(v);
        assert(sig);

        /* Returns > 0 if the signature verified against one of our certificates, 0 if it was not applicable
         * (i.e. different mechanism, or a different key) or didn't verify. */

        if (sig->mechanism != UAPI16_SIGNATURE_PKCS7)
                return 0;

        bool applies = false;
        for (size_t j = 0; j < v->n_certificates && !applies; j++)
                applies = uapi16_signature_verifier_certificate_applies(v, j, sig);
        if (!applies) {
                log_debug("Signature made with a different key, skipping.");
                return 0;
        }

        if (!iovec_is_set(&sig->data)) {
                log_warning("Signature lacks data, skipping.");
                return 0;
        }

        const unsigned char *d = sig->data.iov_base;
        _cleanup_(CMS_ContentInfo_freep) CMS_ContentInfo *cms = sym_d2i_CMS_ContentInfo(NULL, &d, (long) sig->data.iov_len);
        if (!cms) {
                log_openssl_errors(LOG_WARNING, "Failed to parse PKCS#7 signature, skipping");
                return 0;
        }

        if (sym_OBJ_obj2nid(sym_CMS_get0_type(cms)) != NID_pkcs7_signed) {
                log_warning("PKCS#7 signature is not of 'signed' type, skipping.");
                return 0;
        }

        STACK_OF(CMS_SignerInfo) *sk = sym_CMS_get0_SignerInfos(cms);
        for (size_t j = 0; j < v->n_certificates; j++) {
                if (!uapi16_signature_verifier_certificate_applies(v, j, sig))
                        continue;

                for (int i = 0; i < sym_sk_CMS_SignerInfo_num(sk); i++) {
                        CMS_SignerInfo *si = sym_sk_CMS_SignerInfo_value(sk, i);

                        tried = true;

                        /* Always check against the certificates we were given, regardless of which
                         * certificates the signature itself might carry. */
                        sym_CMS_SignerInfo_set1_signer_cert(si, v->certificates[j]);

                        /* If there are signed attributes the signature covers those (and they in turn carry
                         * the digest of the data, which CMS_SignerInfo_verify_content() checks), otherwise
                         * the signature is directly over the digest of the data. Same logic as in
                         * CMS_verify(). */
                        if (sym_CMS_signed_get_attr_count(si) >= 0 &&
                            sym_CMS_SignerInfo_verify(si) <= 0) {
                                log_openssl_errors(LOG_DEBUG, "PKCS#7 signature verification failed");
                                continue;
                        }

                        if (sym_CMS_SignerInfo_verify_content(si, v->bio) > 0)
                                return 1;

                        log_openssl_errors(LOG_DEBUG, "PKCS#7 signature verification failed");
                }
        }

        /* Don't fail here, there might be another signature object following that verifies. If none does
         * the caller will refuse the manifest. */
        if (tried)
                log_debug("Manifest signature verification failed, skipping.");

        return 0;
#else
        assert_not_reached();
#endif
}

#define UAPI16_RECORD_SIZE_MAX (4U*1024U*1024U)
#define UAPI16_RECORD_READ_CHUNK (64U*1024U)

static int uapi16_manifest_next_record(
                FILE *f,
                struct iovec *buffer,
                sd_json_variant **ret,
                size_t *ret_bytes) {

        int r;

        assert(f);
        assert(buffer);
        assert(ret);
        assert(ret_bytes);

        /* Extracts the next record from the stream. The bytes read from the stream are collected in
         * 'buffer', and the size of the record (including its record separator) is returned in 'ret_bytes',
         * so that the caller can pass the record's raw bytes to the signature verifier before consuming
         * them from the buffer. */

        bool eof = false;

        for (;;) {
                if (iovec_is_set(buffer)) {
                        const char *p = buffer->iov_base;
                        size_t l = buffer->iov_len;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = json_seq_extract(&p, &l, SD_JSON_PARSE_MUST_BE_OBJECT, eof, &v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse JSON-SEQ record: %m");
                        if (r > 0) {
                                *ret = TAKE_PTR(v);
                                *ret_bytes = buffer->iov_len - l;
                                return 1;
                        }
                }

                if (eof) {
                        *ret = NULL;
                        *ret_bytes = 0;
                        return 0;
                }

                if (buffer->iov_len >= UAPI16_RECORD_SIZE_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "JSON-SEQ record too large, refusing.");

                if (!GREEDY_REALLOC(*(uint8_t**) &buffer->iov_base, buffer->iov_len + UAPI16_RECORD_READ_CHUNK))
                        return log_oom();

                errno = 0;
                size_t k = fread((uint8_t*) buffer->iov_base + buffer->iov_len, 1, UAPI16_RECORD_READ_CHUNK, f);
                if (k == 0) {
                        if (ferror(f))
                                return log_error_errno(errno_or_else(EIO), "Failed to read from manifest: %m");

                        eof = true;
                        continue;
                }

                buffer->iov_len += k;
        }
}

typedef struct Uapi16Placement {
        char **dirs;          /* The directories still open, i.e. whose entries may still follow */
        size_t n_dirs;
        char *previous_name;  /* Only tracked if the manifest declares an ordering */
} Uapi16Placement;

static void uapi16_placement_done(Uapi16Placement *p) {
        assert(p);

        p->dirs = strv_free(p->dirs);
        p->n_dirs = 0;
        p->previous_name = mfree(p->previous_name);
}

static int uapi16_placement_check(Uapi16Placement *p, const Uapi16Object *root, const Uapi16Object *o) {
        int r;

        assert(p);
        assert(root);
        assert(o);
        assert(o->name);

        /* The specification requires listing the file objects in tree order, i.e. every directory before
         * the file objects below it, and these immediately following it. Check that with a stack of the
         * directories that are still open. If the manifest declares the code point ordering, also check
         * that the names strictly increase, which also refuses names listed twice. As names are normalized,
         * path_compare() implements the code point ordering of the specification: it compares component by
         * component, byte by byte, and orders a component before others it is a prefix of. */

        if (root->order == UAPI16_ORDER_CODEPOINT) {
                if (p->previous_name && path_compare(p->previous_name, o->name) >= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Manifest declares code point ordering, but file object '%s' does not sort after '%s', refusing.",
                                               o->name, p->previous_name);

                r = free_and_strdup(&p->previous_name, o->name);
                if (r < 0)
                        return log_oom();
        }

        _cleanup_free_ char *parent = NULL;
        r = path_extract_directory(o->name, &parent);
        if (r < 0 && r != -EDESTADDRREQ) /* EDESTADDRREQ → in the root directory */
                return log_error_errno(r, "Failed to extract directory of '%s': %m", o->name);

        /* Close all directories the object is not located in */
        while (p->n_dirs > 0 && !streq_ptr(p->dirs[p->n_dirs - 1], parent)) {
                p->n_dirs--;
                p->dirs[p->n_dirs] = mfree(p->dirs[p->n_dirs]);
        }

        if (parent && p->n_dirs == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "File object '%s' is not listed right after the directory it is located in, refusing.",
                                       o->name);

        if (o->type == S_IFDIR && strv_extend_with_size(&p->dirs, &p->n_dirs, o->name) < 0)
                return log_oom();

        return 0;
}

int uapi16_manifest_read(
                FILE *f,
                X509 *const *certificates,
                size_t n_certificates,
                uapi16_object_handler_t handler,
                void *userdata) {

        int r;

        assert(f);
        assert(certificates || n_certificates == 0);
        assert(handler);

        _cleanup_(uapi16_signature_verifier_freep) Uapi16SignatureVerifier *verifier = NULL;
        if (n_certificates > 0) {
                r = uapi16_signature_verifier_new(certificates, n_certificates, &verifier);
                if (r < 0)
                        return r;
        }

        bool signature_seen = false, signature_supported_seen = false, signature_verified = false, trailer_seen = false;
        _cleanup_free_ char *unsupported_mechanism = NULL;
        _cleanup_(iovec_done) struct iovec buffer = {};
        _cleanup_(uapi16_object_done) Uapi16Object root = UAPI16_OBJECT_NULL;
        _cleanup_(uapi16_placement_done) Uapi16Placement placement = {};
        size_t n_objects = 0;
        for (;; n_objects++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                size_t bytes = 0;
                r = uapi16_manifest_next_record(f, &buffer, &v, &bytes);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (trailer_seen)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest contains data after trailer object, refusing.");

                const char *mt = NULL;
                r = uapi16_object_media_type(v, &mt);
                if (r < 0)
                        return log_error_errno(r, "Manifest object %zu has a 'mediaType' field that is not a string, refusing.", n_objects);

                if (n_objects == 0) {
                        /* First object must be of manifest media type */
                        if (!streq_ptr(mt, UAPI16_MANIFEST_MEDIA_TYPE))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "First object of manifest is not a file object of the manifest media type, refusing.");
                } else if (mt && !streq(mt, UAPI16_MANIFEST_MEDIA_TYPE)) {
                        /* File objects usually carry no media type at all. Signature objects end the list of
                         * file objects: file objects after them are not covered by the signature, and hence
                         * refused. The trailer object ends the manifest. Other objects of unknown media type
                         * are skipped, as the specification requires. */

                        if (streq(mt, UAPI16_TRAILER_MEDIA_TYPE))
                                trailer_seen = true;
                        else if (streq(mt, UAPI16_SIGNATURE_MEDIA_TYPE)) {
                                _cleanup_(uapi16_signature_done) Uapi16Signature sig = UAPI16_SIGNATURE_NULL;
                                r = dispatch_uapi16_signature_object(v, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &sig);
                                if (r < 0)
                                        return r;

                                signature_seen = true;

                                if (sig.mechanism < 0) {
                                        /* Signatures of mechanisms we do not support (e.g. "openpgp") are
                                         * skipped, as if they were not there. Remember the mechanism though,
                                         * so that we can explain the failure if there's no other signature. */
                                        const char *mechanism = sd_json_variant_string(sd_json_variant_by_key(v, "mechanism"));

                                        log_debug("Ignoring manifest signature of unsupported mechanism '%s'.", mechanism);

                                        if (!unsupported_mechanism) {
                                                unsupported_mechanism = strdup(mechanism);
                                                if (!unsupported_mechanism)
                                                        return log_oom();
                                        }
                                } else if (!verifier)
                                        log_debug("Manifest carries a signature, but no certificate specified, not verifying.");
                                else if (signature_verified)
                                        log_debug("Skipping additional signature, as we already found one that checked out.");
                                else {
                                        /* The signature covers everything up to the record separator of the
                                         * first signature object, hence never feed the signature object
                                         * itself. Multiple signature objects may follow each other, we accept
                                         * any one that verifies. */
                                        signature_supported_seen = true;

                                        r = uapi16_signature_verifier_finish(verifier, &sig);
                                        if (r < 0)
                                                return r;
                                        if (r > 0) {
                                                log_debug("Manifest signature verified successfully.");
                                                signature_verified = true;
                                        }
                                }
                        } else {
                                log_debug("Ignoring object of unknown media type '%s' in manifest.", mt);

                                if (!signature_seen && verifier) {
                                        r = uapi16_signature_verifier_feed(verifier, buffer.iov_base, bytes);
                                        if (r < 0)
                                                return r;
                                }
                        }

                        assert_se(iovec_consume(&buffer, bytes));
                        continue;
                }

                if (signature_seen)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest contains file object after signature object, refusing.");

                if (verifier) {
                        r = uapi16_signature_verifier_feed(verifier, buffer.iov_base, bytes);
                        if (r < 0)
                                return r;
                }

                assert_se(iovec_consume(&buffer, bytes));

                /* The root object is kept around for the whole manifest, as it declares manifest-wide
                 * properties that govern the other objects */
                _cleanup_(uapi16_object_done) Uapi16Object object = UAPI16_OBJECT_NULL;
                Uapi16Object *o = n_objects == 0 ? &root : &object;
                r = dispatch_uapi16_object(v, n_objects == 0 ? NULL : &root, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, o);
                if (r < 0)
                        return r;

                if (n_objects > 0) {
                        r = uapi16_placement_check(&placement, &root, o);
                        if (r < 0)
                                return r;
                }

                r = handler(o, n_objects, userdata);
                if (r < 0)
                        return r;
        }

        if (n_objects == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest contains no objects, refusing.");
        if (!trailer_seen)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest lacks trailer object, file is incomplete, refusing.");

        if (verifier && !signature_verified) {
                if (signature_supported_seen)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "No signature in manifest verified against the specified certificates, refusing.");
                if (unsupported_mechanism)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Manifest only carries signatures of unsupported mechanisms (e.g. '%s'), but PKCS#7 signature verification requested, refusing.",
                                               unsupported_mechanism);

                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Manifest carries no signature, but signature verification requested, refusing.");
        }

        return 0;
}

void uapi16_certificates_free(X509 **certificates, size_t n) {
#if HAVE_OPENSSL
        FOREACH_ARRAY(i, certificates, n)
                sym_X509_free(*i);
#else
        assert(n == 0);
#endif
        free(certificates);
}

#if HAVE_OPENSSL
static int uapi16_check_certificate_usage(X509 *cert, const char *path) {
        assert(cert);
        assert(path);

        /* Same checks as keyring-setup's check_usage() applies to artifact verifiers, so that both
         * consumers of the VOA hierarchy trust the same certificates. */

        uint32_t flags = sym_X509_get_extension_flags(cert);
        if (FLAGS_SET(flags, EXFLAG_INVALID))
                return log_warning_errno(SYNTHETIC_ERRNO(EKEYREJECTED),
                                         "Certificate '%s' carries an invalid X.509 extension, ignoring.", path);

        if (FLAGS_SET(flags, EXFLAG_XKUSAGE) &&
            (sym_X509_get_extended_key_usage(cert) & (XKU_CODE_SIGN|XKU_ANYEKU)) == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EKEYREJECTED),
                                         "Certificate '%s' is not a code signing certificate, ignoring.", path);

        if (FLAGS_SET(flags, EXFLAG_KUSAGE) &&
            !FLAGS_SET(sym_X509_get_key_usage(cert), KU_DIGITAL_SIGNATURE))
                return log_warning_errno(SYNTHETIC_ERRNO(EKEYREJECTED),
                                         "Certificate '%s' does not permit digital signatures, ignoring.", path);

        return 0;
}
#endif

int uapi16_load_voa_certificates(int root_fd, const char *context, X509 ***ret, size_t *ret_n) {
#if HAVE_OPENSSL
        int r;

        assert(wildcard_fd_is_valid(root_fd));
        assert(context);
        assert(ret);
        assert(ret_n);

        _cleanup_strv_free_ char **os = NULL;
        r = voa_os_identifiers(root_fd, &os);
        if (r < 0)
                return log_error_errno(r, "Failed to determine VOA OS identifiers: %m");

        ConfFile **files = NULL;
        size_t n_files = 0;
        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = voa_list_verifiers(
                        root_fd,
                        &(const VoaLookup) {
                                .os = os,
                                .role = UAPI16_VOA_ROLE,
                                .context = context,
                                .mode = VOA_MODE_ARTIFACT_VERIFIER,
                                .technology = VOA_TECHNOLOGY_X509,
                                .suffix = VOA_X509_CERTIFICATE_SUFFIX,
                        },
                        VOA_WARN,
                        &files,
                        &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate VOA verifiers for UAPI.16 manifests in context '%s': %m", context);

        X509 **certificates = NULL;
        size_t n_certificates = 0;
        CLEANUP_ARRAY(certificates, n_certificates, uapi16_certificates_free);

        FOREACH_ARRAY(i, files, n_files) {
                ConfFile *f = *i;

                /* Read the certificate through the pinned fd, so that the path is not resolved again */
                _cleanup_fclose_ FILE *file = NULL;
                r = fdopen_independent(f->fd, "re", &file);
                if (r < 0) {
                        log_warning_errno(r, "Failed to open certificate '%s', ignoring: %m", f->original_path);
                        continue;
                }

                _cleanup_free_ char *pem = NULL;
                size_t pem_size;
                r = read_full_stream_full(file, f->original_path, /* offset= */ UINT64_MAX, /* size= */ 64U * 1024U,
                                          READ_FULL_FILE_FAIL_WHEN_LARGER, &pem, &pem_size);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read certificate '%s', ignoring: %m", f->original_path);
                        continue;
                }

                _cleanup_(X509_freep) X509 *cert = NULL;
                bool more = false;
                r = openssl_load_x509_certificate_from_pem(&IOVEC_MAKE(pem, pem_size), &cert, &more);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse certificate '%s', ignoring: %m", f->original_path);
                        continue;
                }
                if (more) {
                        log_warning("Certificate file '%s' contains more than one certificate, ignoring.", f->original_path);
                        continue;
                }

                if (uapi16_check_certificate_usage(cert, f->original_path) < 0)
                        continue;

                if (!GREEDY_REALLOC(certificates, n_certificates + 1))
                        return log_oom();

                certificates[n_certificates++] = TAKE_PTR(cert);
                log_debug("Loaded UAPI.16 manifest certificate '%s'.", f->original_path);
        }

        *ret = TAKE_PTR(certificates);
        *ret_n = n_certificates;
        n_certificates = 0;
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signature verification not supported, OpenSSL support disabled.");
#endif
}

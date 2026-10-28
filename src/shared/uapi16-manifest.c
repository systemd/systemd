/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-gpt.h"

#include "alloc-util.h"
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
#include "string-table.h"
#include "strv.h"
#include "time-util.h"
#include "uapi16-manifest.h"
#include "utf8.h"
#include "voa-util.h"

#define CONTENTS_MAX 256U

void uapi16_contents_done(Uapi16Contents *c) {
        assert(c);

        c->file = mfree(c->file);
        c->url = mfree(c->url);
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
        o->gpt_label = mfree(o->gpt_label);
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
        /* The specification requires the "name" field to be a normalized, relative UTF-8 path without
         * control characters, that does not clash with the name of the manifest file itself. */

        if (isempty(s))
                return false;

        if (!utf8_is_valid(s))
                return false;

        if (path_is_absolute(s))
                return false;

        if (!path_is_normalized(s))
                return false;

        if (string_has_cc(s, NULL))
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
                !string_has_cc(s, NULL);
}

static int json_dispatch_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
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
        r = sd_json_variant_new_object(&ns, NULL, 0);
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
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "Length of file with zero hash is non-zero: %s", name);

                return 1;
        }

        if (*size == 0) {
                if (iovec_is_set(sha256))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "Zero length file does not have zero hash: %s", name);

                if (!iovec_memdup(&IOVEC_MAKE(SHA256_EMPTY, SHA256_DIGEST_SIZE), sha256))
                        return json_log_oom(v, flags);

                return 1;
        }

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
                        { "file",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(Uapi16Contents, file),            SD_JSON_NULLABLE },
                        { "url",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(Uapi16Contents, url),             SD_JSON_NULLABLE },
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
                r = sd_json_dispatch(s, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &c);
                if (r < 0)
                        return r;

                if (!!c.file + !!c.url + !!iovec_is_set(&c.literal) > 1)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Only one of 'file', 'url', 'literal' may be set for '%s'.", strna(name));

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
                                if (!iovec_done_and_memdup(&c.encoded_sha256, &c.original_sha256))
                                        return json_log_oom(variant, flags);
                        } else if (iovec_is_set(&c.encoded_sha256) && !iovec_is_set(&c.original_sha256)) {
                                if (!iovec_done_and_memdup(&c.original_sha256, &c.encoded_sha256))
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

        if (o->gpt_flags_set &&
            ((o->gpt_no_auto >= 0 && FLAGS_SET(o->gpt_flags, SD_GPT_FLAG_NO_AUTO) != o->gpt_no_auto) ||
             (o->gpt_growfs >= 0 && FLAGS_SET(o->gpt_flags, SD_GPT_FLAG_GROWFS) != o->gpt_growfs)))
                return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Fields 'gptFlags' and 'gptFlag*' contradict each other, refusing.");

        return 0;
}

int dispatch_uapi16_object(sd_json_variant *v, size_t n, sd_json_dispatch_flags_t flags, Uapi16Object *ret) {

        /* The specification says null fields are equivalent to absent ones, hence SD_JSON_NULLABLE */
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",                   SD_JSON_VARIANT_STRING,        json_dispatch_name,          offsetof(Uapi16Object, name),              SD_JSON_NULLABLE },
                { "mediaType",              SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,     offsetof(Uapi16Object, media_type),        SD_JSON_NULLABLE },
                { "type",                   SD_JSON_VARIANT_STRING,        json_dispatch_inode_type,    offsetof(Uapi16Object, type),              SD_JSON_NULLABLE },
                { "size",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, size),              0                },
                { "mode",                   _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode,   offsetof(Uapi16Object, mode),              0                },
                { "uid",                    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,    offsetof(Uapi16Object, uid),               0                },
                { "gid",                    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,    offsetof(Uapi16Object, gid),               0                },
                { "major",                  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, major),             0                },
                { "minor",                  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, minor),             0                },
                { "mTimeNSec",              _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, mtime_nsec),        0                },
                { "inodeToken",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, inode_token),       0                },
                { "extendedAttributes",     SD_JSON_VARIANT_OBJECT,        json_dispatch_extended_attributes, 0,                                   SD_JSON_NULLABLE },
                { "gptLabel",               SD_JSON_VARIANT_STRING,        json_dispatch_gpt_label,     offsetof(Uapi16Object, gpt_label),         SD_JSON_NULLABLE },
                { "gptUuid",                SD_JSON_VARIANT_STRING,        json_dispatch_gpt_uuid,      0,                                         SD_JSON_NULLABLE },
                { "gptTypeUuid",            SD_JSON_VARIANT_STRING,        json_dispatch_gpt_type_uuid, 0,                                         SD_JSON_NULLABLE },
                { "gptDiskUuid",            SD_JSON_VARIANT_STRING,        json_dispatch_gpt_disk_uuid, 0,                                         SD_JSON_NULLABLE },
                { "gptFlags",               _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_gpt_flags,     0,                                         0                },
                { "gptFlagNoAuto",          SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,   offsetof(Uapi16Object, gpt_no_auto),       SD_JSON_NULLABLE },
                { "gptFlagGrowFileSystem",  SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,   offsetof(Uapi16Object, gpt_growfs),        SD_JSON_NULLABLE },
                { "readOnly",               SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,   offsetof(Uapi16Object, read_only),         SD_JSON_NULLABLE },
                { "contents",               SD_JSON_VARIANT_ARRAY,         json_dispatch_contents,      0,                                         SD_JSON_NULLABLE },
                { "sha256",                 SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec32, offsetof(Uapi16Object, sha256),            SD_JSON_NULLABLE },
                { "validSinceUSec",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, valid_since_usec),  0                },
                { "validUntilUSec",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,     offsetof(Uapi16Object, valid_until_usec),  0                },
                { "validity",               SD_JSON_VARIANT_STRING,        json_dispatch_validity,      offsetof(Uapi16Object, validity),          SD_JSON_NULLABLE },
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

        if (n == 0) {
                if (!object.media_type)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "First manifest object does not carry mediaType field, refusing.");

                if (object.name)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Initial manifest object has the name field set, refusing.");

                if (!IN_SET(object.type, 0, S_IFDIR))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Initial manifest object has unexpected inode type '%s', refusing.", strna(inode_type_to_string(object.type)));

                object.type = S_IFDIR;
        } else {
                if (!object.name)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EBADMSG), "Manifest object has no name field set, refusing.");

                if (object.type == 0)
                        object.type = S_IFREG;
        }

        r = uapi16_object_validate(v, flags, &object, /* is_root= */ n == 0);
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
                            object.size != UINT64_MAX &&
                            c->original_size != UINT64_MAX &&
                            c->original_size - c->offset == object.size)
                                if (!iovec_memdup(&object.sha256, &c->original_sha256))
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
        assert_not_reached();
#endif
}

int uapi16_signer_finish(Uapi16Signer *s, sd_json_variant **ret) {
#if HAVE_OPENSSL
        int r;

        assert(s);
        assert(ret);

        if (sym_CMS_dataFinal(s->cms, s->bio) <= 0)
                return log_openssl_errors(LOG_ERR, "Failed to finalize PKCS#7 signature");

        _cleanup_free_ uint8_t *der = NULL;
        int der_size = sym_i2d_CMS_ContentInfo(s->cms, &der);
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
        assert_not_reached();
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
         * (i.e. different mechanism, or a different key), and -EBADMSG if the signature that should have
         * matched didn't verify. */

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

        if (tried)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest signature verification failed.");

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
                                return log_error_errno(errno_or_else(EIO), "Failed to read from manifest.");

                        eof = true;
                        continue;
                }

                buffer->iov_len += k;
        }
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

                _cleanup_(uapi16_object_done) Uapi16Object object = UAPI16_OBJECT_NULL;
                r = dispatch_uapi16_object(v, n_objects, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &object);
                if (r < 0)
                        return r;

                r = handler(&object, n_objects, userdata);
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

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "gpt.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "validatefs-util.h"
#include "xattr-util.h"

void validate_fields_done(ValidateFields *f) {
        assert(f);

        f->gpt_type_uuid = mfree(f->gpt_type_uuid);
        f->n_gpt_type_uuid = 0;
        f->gpt_label = strv_free(f->gpt_label);
        f->mount_point = strv_free(f->mount_point);
}

static char* validate_fields_gpt_type_uuid_as_string(const ValidateFields *f) {
        _cleanup_free_ char *joined = NULL;

        assert(f);

        FOREACH_ARRAY(u, f->gpt_type_uuid, f->n_gpt_type_uuid) {
                if (!strextend_with_separator(&joined, ", ", SD_ID128_TO_UUID_STRING(*u)))
                        return NULL;

                const char *id = gpt_partition_type_uuid_to_string(*u);
                if (id)
                        (void) strextend(&joined, " (", id, ")");
        }

        return TAKE_PTR(joined);
}

int validate_fields_read(int fd, int log_level, ValidateFields *ret) {
        _cleanup_(validate_fields_done) ValidateFields f = {};
        int r;

        /* Reads the user.validatefs.* xattrs from the specified inode. Returns > 0 if any constraints are
         * set, 0 if none are set. Returns -EINVAL if the xattrs are set but invalid. */

        assert(fd >= 0);
        assert(ret);

        _cleanup_strv_free_ char **l = NULL;
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.gpt_type_uuid", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_full_errno(log_level, r, "Failed to read 'user.validatefs.gpt_type_uuid' xattr: %m");
        } else {
                STRV_FOREACH(i, l) {
                        if (!GREEDY_REALLOC(f.gpt_type_uuid, f.n_gpt_type_uuid+1))
                                return log_oom_full(log_level);

                        r = sd_id128_from_string(*i, f.gpt_type_uuid + f.n_gpt_type_uuid);
                        if (r < 0)
                                return log_full_errno(log_level, r, "Failed to parse 'user.validatefs.gpt_type_uuid' xattr: %s", *i);

                        f.n_gpt_type_uuid++;
                }
        }

        l = strv_free(l);
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.gpt_label", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_full_errno(log_level, r, "Failed to read 'user.validatefs.gpt_label' xattr: %m");
        } else {
                STRV_FOREACH(i, l)
                        if (!gpt_label_is_valid(*i))
                                return log_full_errno(
                                                log_level,
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Extended attribute 'user.validatefs.gpt_label' contains invalid GPT label, refusing: %s", *i);

                f.gpt_label = TAKE_PTR(l);
        }

        l = strv_free(l);
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.mount_point", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_full_errno(log_level, r, "Failed to read 'user.validatefs.mount_point' xattr: %m");
        } else {
                STRV_FOREACH(i, l)
                        if (!utf8_is_valid(*i) ||
                            string_has_cc(*i, /* ok= */ NULL) ||
                            !path_is_absolute(*i) ||
                            !path_is_normalized(*i))
                                return log_full_errno(
                                                log_level,
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Path listed in extended attribute 'user.validatefs.mount_point' is not a valid, normalized, absolute path or contains invalid characters, refusing: %s", *i);

                f.mount_point = TAKE_PTR(l);
        }

        r = f.n_gpt_type_uuid > 0 || !strv_isempty(f.gpt_label) || !strv_isempty(f.mount_point);
        *ret = TAKE_STRUCT(f);
        return r;
}

bool validate_fields_need_gpt(const ValidateFields *f) {
        assert(f);

        /* Returns true if any of the constraints refer to GPT partition metadata, i.e. can only be fulfilled
         * if the file system is placed on a GPT partition */

        return f->n_gpt_type_uuid > 0 || !strv_isempty(f->gpt_label);
}

int validate_fields_check_mount_point(const ValidateFields *f, const char *root, const char *path, int log_level) {
        assert(f);
        assert(path);

        /* Checks whether the specified path (which is supposed to be prefixed by 'root', if specified) is
         * one of the listed mount points (which are relative to 'root'). */

        if (strv_isempty(f->mount_point))
                return 0;

        STRV_FOREACH(i, f->mount_point) {
                _cleanup_free_ char *jj = NULL;
                const char *j;

                if (root) {
                        jj = path_join(root, *i);
                        if (!jj)
                                return log_oom_full(log_level);

                        j = jj;
                } else
                        j = *i;

                if (path_equal(path, j))
                        return 0;
        }

        _cleanup_free_ char *joined = strv_join(f->mount_point, ", ");
        return log_full_errno(
                        log_level,
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be mounted on one of %s only, but is mounted on %s, refusing.",
                        strna(joined), path);
}

int validate_fields_check_gpt_label(const ValidateFields *f, const char *label, int log_level) {
        assert(f);

        if (strv_isempty(f->gpt_label))
                return 0;

        if (strv_contains(f->gpt_label, strempty(label)))
                return 0;

        _cleanup_free_ char *joined = strv_join(f->gpt_label, "', '");
        return log_full_errno(
                        log_level,
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be placed in a partition with labels '%s' only, but is placed in one labelled '%s', refusing.",
                        strna(joined), strempty(label));
}

int validate_fields_check_gpt_type(const ValidateFields *f, const sd_id128_t *type, int log_level) {
        assert(f);

        if (f->n_gpt_type_uuid == 0)
                return 0;

        if (!type) {
                _cleanup_free_ char *joined = validate_fields_gpt_type_uuid_as_string(f);
                return log_full_errno(
                                log_level,
                                SYNTHETIC_ERRNO(EPERM),
                                "File system is supposed to be placed in a partition of type UUIDs %s only, but has no type, refusing.",
                                strna(joined));
        }

        FOREACH_ARRAY(u, f->gpt_type_uuid, f->n_gpt_type_uuid)
                if (sd_id128_equal(*u, *type))
                        return 0;

        _cleanup_free_ char *joined = validate_fields_gpt_type_uuid_as_string(f);
        return log_full_errno(
                        log_level,
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be placed in a partition of type UUIDs %s only, but has type '%s', refusing.",
                        strna(joined), SD_ID128_TO_UUID_STRING(*type));
}

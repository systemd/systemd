/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "manifest-util.h"
#include "recurse-dir.h"
#include "sha256.h"
#include "string-table.h"
#include "string-util.h"
#include "uid-classification.h"
#include "user-util.h"

void manifest_context_done(ManifestContext *c) {
        assert(c);

        /* Nothing to release for now. */
}

static const char* const manifest_format_table[_MANIFEST_FORMAT_MAX] = {
        [MANIFEST_FORMAT_LIST]  = "list",
        [MANIFEST_FORMAT_MTREE] = "mtree",
};

DEFINE_STRING_TABLE_LOOKUP(manifest_format, ManifestFormat);

static const struct {
        ManifestField field;
        const char *name;
} manifest_field_table[] = {
        /* This is a bitfield, hence not a simple array indexed by the enum */
        { MANIFEST_FIELD_MODE,       "mode"       },
        { MANIFEST_FIELD_UID,        "uid"        },
        { MANIFEST_FIELD_GID,        "gid"        },
        { MANIFEST_FIELD_SIZE,       "size"       },
        { MANIFEST_FIELD_HASH,       "hash"       },
        { MANIFEST_FIELD_SYMLINK,    "symlink"    },
        { MANIFEST_FIELD_DEVICE,     "device"     },
        { MANIFEST_FIELD_HARDLINK,   "hardlink"   },
        { MANIFEST_FIELD_MTIME,      "mtime"      },
        { MANIFEST_FIELD_USER_XATTR, "user-xattr" },
};

const char* manifest_field_to_string(ManifestField f) {
        FOREACH_ELEMENT(i, manifest_field_table)
                if (i->field == f)
                        return i->name;

        return NULL;
}

ManifestField manifest_field_from_string(const char *s) {
        if (!s)
                return _MANIFEST_FIELD_INVALID;

        FOREACH_ELEMENT(i, manifest_field_table)
                if (streq(i->name, s))
                        return i->field;

        return _MANIFEST_FIELD_INVALID;
}

int manifest_fields_from_string(const char *s, ManifestField *ret) {
        ManifestField fields;
        bool first = true;
        int r;

        assert(s);
        assert(ret);

        fields = *ret;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&s, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                const char *n = word;
                bool add = true, relative = false;
                if (n[0] == '+') {
                        n++;
                        relative = true;
                } else if (n[0] == '-') {
                        n++;
                        add = false;
                        relative = true;
                }

                /* The first non-relative item resets the mask, subsequent items add to it. */
                if (first && !relative)
                        fields = 0;
                first = false;

                ManifestField f;
                if (streq(n, "all"))
                        f = _MANIFEST_FIELD_ALL;
                else if (streq(n, "default"))
                        f = _MANIFEST_FIELD_DEFAULT;
                else if (streq(n, "none"))
                        f = 0;
                else {
                        f = manifest_field_from_string(n);
                        if (f < 0)
                                return -EINVAL;
                }

                if (add)
                        fields |= f;
                else
                        fields &= ~f;
        }

        *ret = fields;
        return 0;
}

int manifest_fields_to_string(ManifestField f, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert(ret);

        FOREACH_ELEMENT(i, manifest_field_table) {
                if (!FLAGS_SET(f, i->field))
                        continue;

                if (!strextend_with_separator(&s, ",", i->name))
                        return -ENOMEM;
        }

        if (!s) {
                s = strdup("none");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int manifest_context_hash_fd(ManifestContext *c, int inode_fd, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(inode_fd >= 0);
        assert(ret);

        /* Calculating the hash might be slow, hence let's flush the output first, to give users an idea
         * where we are slow. */
        if (c->output)
                (void) fflush(c->output);

        /* Convert O_PATH fd into a regular one */
        _cleanup_close_ int fd = fd_reopen(inode_fd, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        return sha256_fd(fd, /* max_size= */ UINT64_MAX, ret);
}

static int manifest_list_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ManifestContext *c = ASSERT_PTR(userdata);

        assert(path);

        if (event == RECURSE_DIR_ENTER)
                fprintf(c->output, "%s%s/%s\n",
                        path,
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "");
        else if (event == RECURSE_DIR_ENTRY)
                fprintf(c->output, "%s\n", path);

        return RECURSE_DIR_CONTINUE;
}

static const char *pick_color_for_uid_gid(ManifestContext *c, uid_t uid) {
        assert(c);

        if (!c->color)
                return "";
        if (uid == UID_NOBODY)
                return ansi_highlight_yellow4(); /* files should never be owned by 'nobody' (but might happen due to userns mapping) */
        if (uid_is_system(uid))
                return ansi_normal();            /* files in disk images are typically owned by root and other system users, no issue there */
        if (uid_is_dynamic(uid) || uid_is_greeter(uid))
                return ansi_highlight_red();     /* files should never be owned persistently by dynamic users, and there are just no excuses */
        if (uid_is_container(uid) || uid_is_foreign(uid))
                return ansi_highlight_cyan();

        return ansi_highlight();
}

static unsigned manifest_mtree_fields_to_statx(ManifestField fields) {
        unsigned mask = STATX_TYPE; /* The inode type is always included */

        /* Returns the statx() mask needed to generate an mtree manifest with the specified fields. Only
         * covers the fields the mtree format can express, i.e. hardlink information is ignored. Symlink
         * targets and device numbers only need the inode type. */

        if (FLAGS_SET(fields, MANIFEST_FIELD_MODE))
                mask |= STATX_MODE;
        if (FLAGS_SET(fields, MANIFEST_FIELD_UID))
                mask |= STATX_UID;
        if (FLAGS_SET(fields, MANIFEST_FIELD_GID))
                mask |= STATX_GID;
        if (fields & (MANIFEST_FIELD_SIZE|MANIFEST_FIELD_HASH))
                mask |= STATX_SIZE;
        if (FLAGS_SET(fields, MANIFEST_FIELD_MTIME))
                mask |= STATX_MTIME;

        return mask;
}

static int manifest_mtree_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ManifestContext *c = ASSERT_PTR(userdata);
        FILE *f = ASSERT_PTR(c->output);
        _cleanup_free_ char *escaped = NULL;
        int r;

        assert(path);

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        assert(sx);

        if (isempty(path))
                path = ".";
        else {
                /* BSD mtree uses either C or octal escaping, and covers whitespace, comments and glob characters. We use C style escaping and follow suit */
                path = escaped = xescape(path, WHITESPACE COMMENTS GLOB_CHARS);
                if (!escaped)
                        return log_oom();
        }

        fprintf(f, "%s", isempty(path) ? "." : path);

        if (FLAGS_SET(sx->stx_mask, STATX_TYPE)) {
                if (S_ISDIR(sx->stx_mode))
                        fprintf(f, "%s/%s", c->color ? ansi_grey() : "", c->color ? ansi_normal() : "");

                fprintf(f, " %stype=%s%s%s%s",
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "",
                        c->color ? (S_ISDIR(sx->stx_mode) ? ansi_highlight_blue() :
                                    S_ISLNK(sx->stx_mode) ? ansi_highlight_cyan() :
                                    (S_ISFIFO(sx->stx_mode) || S_ISCHR(sx->stx_mode) || S_ISBLK(sx->stx_mode)) ? ansi_highlight_yellow4() :
                                    S_ISSOCK(sx->stx_mode) ? ansi_highlight_magenta() : "") : "",
                        ASSERT_PTR(S_ISDIR(sx->stx_mode) ? "dir" :
                                   S_ISREG(sx->stx_mode) ? "file" :
                                   S_ISLNK(sx->stx_mode) ? "link" :
                                   S_ISFIFO(sx->stx_mode) ? "fifo" :
                                   S_ISBLK(sx->stx_mode) ? "block" :
                                   S_ISCHR(sx->stx_mode) ? "char" :
                                   S_ISSOCK(sx->stx_mode) ? "socket" : NULL),
                        c->color ? ansi_normal() : "");
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_MODE) && FLAGS_SET(sx->stx_mask, STATX_MODE) && (!FLAGS_SET(sx->stx_mask, STATX_TYPE) || !S_ISLNK(sx->stx_mode)))
                fprintf(f, " %smode=%s%04o",
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "",
                        (unsigned) (sx->stx_mode & 0777));

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_UID) && FLAGS_SET(sx->stx_mask, STATX_UID))
                fprintf(f, " %suid=%s" UID_FMT "%s",
                        c->color ? ansi_grey() : "",
                        pick_color_for_uid_gid(c, sx->stx_uid),
                        sx->stx_uid,
                        c->color ? ansi_normal() : "");

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_GID) && FLAGS_SET(sx->stx_mask, STATX_GID))
                fprintf(f, " %sgid=%s" GID_FMT "%s",
                        c->color ? ansi_grey() : "",
                        pick_color_for_uid_gid(c, sx->stx_gid),
                        sx->stx_gid,
                        c->color ?  ansi_normal() : "");

        if (FLAGS_SET(sx->stx_mask, STATX_TYPE|STATX_SIZE) && S_ISREG(sx->stx_mode)) {
                if (FLAGS_SET(c->fields, MANIFEST_FIELD_SIZE))
                        fprintf(f, " %ssize=%s%" PRIu64,
                                c->color ?  ansi_grey() : "",
                                c->color ?  ansi_normal() : "",
                                (uint64_t) sx->stx_size);

                if (FLAGS_SET(c->fields, MANIFEST_FIELD_HASH) && inode_fd >= 0 && sx->stx_size > 0) {
                        uint8_t hash[SHA256_DIGEST_SIZE];

                        r = manifest_context_hash_fd(c, inode_fd, hash);
                        if (r < 0)
                                log_warning_errno(r, "Failed to calculate file SHA256 sum for '%s', ignoring: %m", path);
                        else {
                                _cleanup_free_ char *h = NULL;

                                h = hexmem(hash, SHA256_DIGEST_SIZE);
                                if (!h)
                                        return log_oom();

                                fprintf(f, " %ssha256sum=%s%s",
                                        c->color ? ansi_grey() : "",
                                        c->color ? ansi_normal() : "",
                                        h);
                        }
                }
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_SYMLINK) && FLAGS_SET(sx->stx_mask, STATX_TYPE) && S_ISLNK(sx->stx_mode) && inode_fd >= 0) {
                _cleanup_free_ char *target = NULL;

                r = readlinkat_malloc(inode_fd, "", &target);
                if (r < 0)
                        log_warning_errno(r, "Failed to read symlink '%s', ignoring: %m", path);
                else {
                        _cleanup_free_ char *target_escaped = NULL;

                        target_escaped = xescape(target, WHITESPACE COMMENTS GLOB_CHARS);
                        if (!target_escaped)
                                return log_oom();

                        fprintf(f, " %slink=%s%s",
                                c->color ? ansi_grey() : "",
                                c->color ? ansi_normal() : "",
                                target_escaped);
                }
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_DEVICE) && FLAGS_SET(sx->stx_mask, STATX_TYPE) && (S_ISBLK(sx->stx_mode) || S_ISCHR(sx->stx_mode)))
                fprintf(f, " %sdevice=%slinux,%" PRIu64 ",%" PRIu64,
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "",
                        (uint64_t) sx->stx_rdev_major,
                        (uint64_t) sx->stx_rdev_minor);

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_MTIME) && FLAGS_SET(sx->stx_mask, STATX_MTIME) && sx->stx_mtime.tv_sec >= 0)
                fprintf(f, " %stime=%s%" PRIu64 ".%09" PRIu32,
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "",
                        (uint64_t) sx->stx_mtime.tv_sec,
                       sx->stx_mtime.tv_nsec);

        fprintf(f, "\n");

        return RECURSE_DIR_CONTINUE;
}

int manifest_make(ManifestContext *c, int dir_fd) {
        int r;

        assert(c);
        assert(dir_fd >= 0);

        if (!c->output)
                c->output = stdout;

        int (*item_callback)(
                        RecurseDirEvent event,
                        const char *path,
                        int dir_fd,
                        int inode_fd,
                        const struct dirent *de,
                        const struct statx *sx,
                        void *userdata) = NULL;
        unsigned statx_mask = 0;
        const char *path = NULL;
        RecurseDirFlags flags = RECURSE_DIR_SORT;

        switch (c->format) {

        case MANIFEST_FORMAT_LIST:
                item_callback = manifest_list_item;
                break;

        case MANIFEST_FORMAT_MTREE:
                path = ".";
                statx_mask |= manifest_mtree_fields_to_statx(c->fields);
                flags |= RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL;
                item_callback = manifest_mtree_item;
                break;

        default:
                assert_not_reached();
        }

        r = recurse_dir(dir_fd, path, statx_mask, /* n_depth_max= */ UINT_MAX, flags, item_callback, c);
        if (r < 0)
                return r;

        r = fflush_and_check(c->output);
        if (r < 0)
                return log_error_errno(r, "Failed to write manifest: %m");

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "chase.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "manifest-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sha256.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"
#include "uid-classification.h"
#include "user-util.h"
#include "utf8.h"
#include "xattr-util.h"

void manifest_context_done(ManifestContext *c) {
        assert(c);

        if (c->db_fd >= 0)
                (void) rm_rf_children(TAKE_FD(c->db_fd), REMOVE_PHYSICAL|REMOVE_REWIND, /* root_dev= */ NULL);

        c->db_path = rmdir_and_free(c->db_path);
}

static const char* const manifest_format_table[_MANIFEST_FORMAT_MAX] = {
        [MANIFEST_FORMAT_LIST]       = "list",
        [MANIFEST_FORMAT_MTREE]      = "mtree",
        [MANIFEST_FORMAT_SHA256SUMS] = "sha256sums",
        [MANIFEST_FORMAT_UAPI16]     = "uapi16",
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

static bool manifest_handle_skip_event(ManifestContext *c, RecurseDirEvent event, const char *path) {
        const char *what;
        int error;

        assert(c);

        /* recurse_dir() reports inodes it could not open or stat via special events. We cannot serialize
         * them, hence count them as skipped. Returns true if the event was one of these. */

        if (event >= RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE && event <= RECURSE_DIR_SKIP_OPEN_DIR_ERROR_MAX) {
                error = event - RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE;
                what = "open directory";
        } else if (event >= RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE && event <= RECURSE_DIR_SKIP_OPEN_INODE_ERROR_MAX) {
                error = event - RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE;
                what = "open inode";
        } else if (event >= RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE && event <= RECURSE_DIR_SKIP_STAT_INODE_ERROR_MAX) {
                error = event - RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE;
                what = "stat inode";
        } else
                return false;

        log_warning_errno(error, "Failed to %s '%s', skipping: %m", what, strna(path));
        c->n_skipped++;
        return true;
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

        if (manifest_handle_skip_event(c, event, path))
                return RECURSE_DIR_CONTINUE;

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

        if (manifest_handle_skip_event(c, event, path))
                return RECURSE_DIR_CONTINUE;

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
                        if (r < 0) {
                                log_warning_errno(r, "Failed to calculate file SHA256 sum for '%s', ignoring: %m", path);
                                c->n_metadata_omitted++;
                        } else {
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
                if (r < 0) {
                        log_warning_errno(r, "Failed to read symlink '%s', ignoring: %m", path);
                        c->n_metadata_omitted++;
                } else {
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

        if (!de) /* Only the top-level inode comes without directory entry */
                c->top_level_covered = true;

        return RECURSE_DIR_CONTINUE;
}

static unsigned manifest_uapi16_fields_to_statx(ManifestField fields) {
        unsigned mask = STATX_TYPE; /* The inode type is always included */

        /* Returns the statx() mask needed to generate an uapi16 manifest with the specified fields. */

        if (FLAGS_SET(fields, MANIFEST_FIELD_MODE))
                mask |= STATX_MODE;
        if (FLAGS_SET(fields, MANIFEST_FIELD_UID))
                mask |= STATX_UID;
        if (FLAGS_SET(fields, MANIFEST_FIELD_GID))
                mask |= STATX_GID;
        if (fields & (MANIFEST_FIELD_SIZE|MANIFEST_FIELD_HASH))
                mask |= STATX_SIZE;
        if (FLAGS_SET(fields, MANIFEST_FIELD_HARDLINK))
                mask |= STATX_NLINK;
        if (FLAGS_SET(fields, MANIFEST_FIELD_MTIME))
                mask |= STATX_MTIME;

        return mask;
}

static int inode_fid_hex(int inode_fd, char **ret) {
        _cleanup_free_ struct file_handle *handle = NULL;
        int r;

        assert(inode_fd >= 0);
        assert(ret);

        /* Generate a unique identifier for this inode via the kernel's FID logic. Returns 0 if the file
         * system does not support FIDs, in which case we cannot identify hardlinks. */
        uint64_t unique_mnt_id = 0;
        int mnt_id = 0;
        r = name_to_handle_at_try_fid(inode_fd, /* path= */ NULL, &handle, &mnt_id, &unique_mnt_id, AT_EMPTY_PATH);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_debug_errno(r, "File system does not support FIDs, not checking for hardlinks: %m");
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire FID of path: %m");

        struct sha256_ctx ctx;
        sha256_init_ctx(&ctx);
        sha256_process_bytes(&handle->handle_bytes, sizeof(handle->handle_bytes), &ctx);
        sha256_process_bytes(&handle->handle_type, sizeof(handle->handle_type), &ctx);
        sha256_process_bytes(&handle->f_handle, handle->handle_bytes, &ctx);
        sha256_process_bytes(&mnt_id, sizeof(mnt_id), &ctx);
        sha256_process_bytes(&unique_mnt_id, sizeof(unique_mnt_id), &ctx);

        uint8_t fid_hash[SHA256_DIGEST_SIZE];
        sha256_finish_ctx(&ctx, fid_hash);

        char *fhs = hexmem(fid_hash, sizeof(fid_hash));
        if (!fhs)
                return log_oom();

        *ret = fhs;
        return 1;
}

static int hardlink_db_acquire(ManifestContext *c) {
        int r;

        assert(c);

        /* Returns 1 if the database was created just now and hence is empty, 0 if it existed already */

        if (c->db_fd >= 0)
                return 0;

        assert(!c->db_path);

        /* Let's use a temporary directory on disk as hardlink database, so that we can
         * process very large images without allocating ridiculous amounts of memory. */

        const char *vtd = NULL;
        r = var_tmp_dir(&vtd);
        if (r < 0)
                return log_error_errno(r, "Failed to determine /var/tmp/ directory: %m");

        _cleanup_free_ char *template = path_join(vtd, "dissect-hardlink-db-XXXXXX");
        if (!template)
                return log_oom();

        c->db_fd = mkdtemp_open(template, /* flags= */ 0, &c->db_path);
        if (c->db_fd < 0)
                return log_error_errno(c->db_fd, "Failed to create temporary directory: %m");

        return 1;
}

static int hardlink_data_lookup(
                ManifestContext *c,
                const char *path,
                int inode_fd,
                const struct statx *sx,
                uint64_t *ret_hardlink_counter,
                uint8_t ret_hash[static SHA256_DIGEST_SIZE],
                bool *ret_hash_valid) {

        _cleanup_free_ char *slt = NULL, *fhs = NULL;
        int r;

        assert(c);
        assert(sx);
        assert(ret_hardlink_counter);
        assert(ret_hash);
        assert(ret_hash_valid);

        if (!FLAGS_SET(c->fields, MANIFEST_FIELD_HARDLINK))
                goto nope;

        if (!FLAGS_SET(sx->stx_mask, STATX_NLINK|STATX_TYPE))
                goto nope;

        if (S_ISDIR(sx->stx_mode) || sx->stx_nlink <= 1)
                goto nope;

        if (inode_fd < 0)
                goto nope;

        /* This is a hardlinked inode, apparently. Let's figure out its inode token */

        r = inode_fid_hex(inode_fd, &fhs);
        if (r < 0)
                return r;
        if (r == 0)
                goto nope;

        r = hardlink_db_acquire(c);
        if (r < 0)
                return r;
        bool is_empty = r > 0;

        uint64_t hardlink_counter;
        uint8_t hash[SHA256_DIGEST_SIZE];
        bool hash_valid = false;

        r = is_empty ? -ENOENT : readlinkat_malloc(c->db_fd, fhs, &slt);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to read hardlink database symlink '%s': %m", fhs);

                if (c->counter >= UINT64_MAX) /* Paranoia */
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Hardlink overflow.");

                hardlink_counter = ++c->counter;

                slt = asprintf_safe("%" PRIu64, hardlink_counter);
                if (!slt)
                        return log_oom();

                if (S_ISREG(sx->stx_mode)) {
                        r = manifest_context_hash_fd(c, inode_fd, hash);
                        if (r < 0)
                                log_warning_errno(r, "Failed to calculate file SHA256 sum for '%s', ignoring: %m", empty_to_root(path));
                        else {
                                _cleanup_free_ char *hs = hexmem(hash, SHA256_DIGEST_SIZE);
                                if (!hs)
                                        return log_oom();

                                if (!strextend(&slt, ":", hs))
                                        return log_oom();

                                hash_valid = true;
                        }
                }

                if (symlinkat(slt, c->db_fd, fhs) < 0)
                        return log_error_errno(errno, "Failed to create hardlink database symlink '%s': %m", fhs);
        } else {
                char *colon = strchr(slt, ':');

                if (colon) {
                        _cleanup_free_ void *unhexxed = NULL;
                        size_t unhexxed_size = 0;
                        r = unhexmem(colon + 1, &unhexxed, &unhexxed_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to unhex file hash: %m");
                        if (unhexxed_size != SHA256_DIGEST_SIZE)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed hash entry: %m");

                        memcpy(hash, unhexxed, unhexxed_size);
                        hash_valid = true;
                        *colon = 0;
                }

                r = safe_atou64(slt, &hardlink_counter);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode hardlink counter: %m");
        }

        *ret_hardlink_counter = hardlink_counter;
        if (hash_valid)
                memcpy_safe(ret_hash, hash, SHA256_DIGEST_SIZE);
        *ret_hash_valid = hash_valid;
        return 1;

nope:
        *ret_hardlink_counter = 0;
        *ret_hash_valid = false;
        return 0;
}

static int manifest_read_user_xattrs(int inode_fd, Uapi16Xattr **ret, size_t *ret_n) {
        int r;

        assert(inode_fd >= 0);
        assert(ret);
        assert(ret_n);

        /* Reads all extended attributes in the "user." namespace of the specified inode (which may be an
         * O_PATH fd), sorted by name. Returns -EUCLEAN if there's an attribute whose name cannot be
         * represented in a UAPI.16 manifest. */

        _cleanup_free_ char *list = NULL;
        r = flistxattr_malloc(inode_fd, &list);
        if (ERRNO_IS_NEG_XATTR_ABSENT(r)) {
                /* If the file system doesn't support xattrs, the inode has none */
                *ret = NULL;
                *ret_n = 0;
                return 0;
        }
        if (r < 0)
                return r;

        Uapi16Xattr *x = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(x, n, uapi16_xattr_array_free);

        NULSTR_FOREACH(i, list) {
                const char *k = startswith(i, "user.");
                if (!k)
                        continue;

                if (!uapi16_xattr_name_is_valid(k))
                        return -EUCLEAN;

                _cleanup_free_ char *v = NULL;
                size_t l = 0;
                r = fgetxattr_malloc(inode_fd, i, &v, &l);
                if (ERRNO_IS_NEG_XATTR_ABSENT(r)) /* Removed in the meantime */
                        continue;
                if (r < 0)
                        return r;

                _cleanup_free_ char *kk = strdup(k);
                if (!kk)
                        return -ENOMEM;

                if (!GREEDY_REALLOC(x, n+1))
                        return -ENOMEM;

                x[n++] = (Uapi16Xattr) {
                        .name = TAKE_PTR(kk),
                        .value = IOVEC_MAKE(TAKE_PTR(v), l),
                };
        }

        r = uapi16_xattr_array_sort(x, n);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(x);
        *ret_n = TAKE_GENERIC(n, size_t, 0);
        return 0;
}

static int manifest_uapi16_xattrs(ManifestContext *c, const char *path, int inode_fd, sd_json_variant **ret) {
        int r;

        assert(c);
        assert(inode_fd >= 0);
        assert(ret);

        Uapi16Xattr *x = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(x, n, uapi16_xattr_array_free);

        r = manifest_read_user_xattrs(inode_fd, &x, &n);
        if (r == -EUCLEAN) {
                /* A namespace object must list all attributes of the namespace, hence omit it entirely if
                 * we cannot */
                log_warning("Inode '%s' carries an extended attribute whose name cannot be represented in a UAPI.16 manifest, omitting extended attributes.", empty_to_root(path));
                c->n_metadata_omitted++;
                *ret = NULL;
                return 0;
        }
        if (r < 0) {
                log_warning_errno(r, "Failed to read extended attributes of '%s', ignoring: %m", empty_to_root(path));
                c->n_metadata_omitted++;
                *ret = NULL;
                return 0;
        }

        r = uapi16_xattrs_build_json(x, n, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object for extended attributes: %m");

        return 1;
}

static int manifest_uapi16_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ManifestContext *c = ASSERT_PTR(userdata);
        int r;

        /* Generates a UAPI.16 Manifest of the directory tree */

        /* We ignore this to avoid input-as-output cycles (only on top-level though!) */
        if (path && uapi16_manifest_filename_is_reserved(path)) {
                log_debug("Skipping directory entry '%s' to avoid recursive manifest generation.", path);
                return RECURSE_DIR_CONTINUE;
        }

        if (manifest_handle_skip_event(c, event, path))
                return RECURSE_DIR_CONTINUE;

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        bool is_root = isempty(path);

        _cleanup_free_ char *data = NULL;
        uint8_t hash[SHA256_DIGEST_SIZE];
        uint64_t size = UINT64_MAX;
        bool have_size = false, hash_valid = false;
        const char *type = NULL;
        uint64_t hardlink_counter = 0;

        r = hardlink_data_lookup(c, path, inode_fd, sx, &hardlink_counter, hash, &hash_valid);
        if (r < 0)
                return r;

        if (FLAGS_SET(sx->stx_mask, STATX_TYPE)) {
                switch (sx->stx_mode & S_IFMT) {

                case S_IFREG:
                        if (FLAGS_SET(sx->stx_mask, STATX_SIZE)) {
                                size = sx->stx_size;
                                have_size = true;
                        }

                        if (!hash_valid && FLAGS_SET(c->fields, MANIFEST_FIELD_HASH) && inode_fd >= 0) {
                                r = manifest_context_hash_fd(c, inode_fd, hash);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to calculate file SHA256 sum for '%s', ignoring: %m", empty_to_root(path));
                                        c->n_metadata_omitted++;
                                } else
                                        hash_valid = true;
                        }

                        break;

                case S_IFLNK:
                        if (FLAGS_SET(c->fields, MANIFEST_FIELD_SYMLINK) && inode_fd >= 0) {
                                r = readlinkat_malloc(inode_fd, "", &data);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to read symlink '%s', ignoring: %m", empty_to_root(path));
                                        c->n_metadata_omitted++;
                                } else {
                                        size = strlen(data);
                                        have_size = true;
                                }
                        }

                        break;
                }

                /* Suppress the type on the top-level entry and on regular files. */
                type = !is_root && !S_ISREG(sx->stx_mode) ? inode_type_to_string(sx->stx_mode) : NULL;
        }

        if (!is_root && !uapi16_name_is_valid(path)) {
                _cleanup_free_ char *e = cescape(path);
                if (!e)
                        return log_oom();

                /* This is not a path we can express in a UAPI.16 manifest (e.g. because it is not valid
                 * UTF-8 or contains control characters). Let's continue, but count it and report the failure
                 * in the end */
                log_warning("Encountered path '%s' which cannot be represented in a UAPI.16 manifest, skipping.", e);
                c->n_skipped++;
                return RECURSE_DIR_CONTINUE;
        }

        /* Symlinks cannot carry extended attributes in the "user." namespace, everything else might (Linux
         * traditionally only allowed them on regular files and directories, but recently added support for
         * sockets, and might extend this further), hence try. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jx = NULL;
        if (FLAGS_SET(c->fields, MANIFEST_FIELD_USER_XATTR) &&
            FLAGS_SET(sx->stx_mask, STATX_TYPE) &&
            !S_ISLNK(sx->stx_mode) &&
            inode_fd >= 0) {
                r = manifest_uapi16_xattrs(c, path, inode_fd, &jx);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_buildo(
                        &j,
                        SD_JSON_BUILD_PAIR_CONDITION(is_root, "mediaType", JSON_BUILD_CONST_STRING(UAPI16_MANIFEST_MEDIA_TYPE)),
                        SD_JSON_BUILD_PAIR_CONDITION(!is_root, "name", SD_JSON_BUILD_STRING(path)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!type, "type", SD_JSON_BUILD_STRING(type)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_SIZE) && have_size, "size", SD_JSON_BUILD_UNSIGNED(size)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "contents", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("literal", SD_JSON_BUILD_BASE64(data, size))))),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_HASH) && hash_valid, "sha256", SD_JSON_BUILD_HEX(hash, SHA256_DIGEST_SIZE)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_DEVICE) && FLAGS_SET(sx->stx_mask, STATX_TYPE) && (S_ISBLK(sx->stx_mode) || S_ISCHR(sx->stx_mode)), "major", SD_JSON_BUILD_UNSIGNED(sx->stx_rdev_major)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_DEVICE) && FLAGS_SET(sx->stx_mask, STATX_TYPE) && (S_ISBLK(sx->stx_mode) || S_ISCHR(sx->stx_mode)), "minor", SD_JSON_BUILD_UNSIGNED(sx->stx_rdev_minor)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_MODE) && FLAGS_SET(sx->stx_mask, STATX_TYPE|STATX_MODE) && !S_ISLNK(sx->stx_mode), "mode", SD_JSON_BUILD_UNSIGNED(sx->stx_mode & 07777)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_UID) && FLAGS_SET(sx->stx_mask, STATX_UID), "uid", SD_JSON_BUILD_UNSIGNED(sx->stx_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_GID) && FLAGS_SET(sx->stx_mask, STATX_GID), "gid", SD_JSON_BUILD_UNSIGNED(sx->stx_gid)),
                        SD_JSON_BUILD_PAIR_CONDITION(hardlink_counter > 0, "inodeToken", SD_JSON_BUILD_UNSIGNED(hardlink_counter)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!jx, "extendedAttributes", SD_JSON_BUILD_VARIANT(jx)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(c->fields, MANIFEST_FIELD_MTIME) && FLAGS_SET(sx->stx_mask, STATX_MTIME), "mTimeNSec", SD_JSON_BUILD_UNSIGNED(statx_timestamp_load_nsec(&sx->stx_mtime))));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        /* The specification recommends sorting fields alphabetically, recursively */
        r = sd_json_variant_normalize(&j);
        if (r < 0)
                return log_error_errno(r, "Failed to sort JSON object: %m");

        r = sd_json_variant_dump(j, c->json_format_flags | SD_JSON_FORMAT_SEQ | SD_JSON_FORMAT_FLUSH, c->output, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to write JSON output: %m");

        if (is_root)
                c->top_level_covered = true;

        return RECURSE_DIR_CONTINUE;
}

static int sums_escape(const char *s, char **ret) {
        assert(s);

        if (!strpbrk(s, "\n\r\\")) {
                /* No escaping required */
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *buf = new(char, strlen(s) * 2 + 1);
        if (!buf)
                return -ENOMEM;

        size_t n = 0;

        for (const char *p = s; *p; p++)
                switch (*p) {
                case '\n':
                        buf[n++] = '\\';
                        buf[n++] = 'n';
                        break;
                case '\r':
                        buf[n++] = '\\';
                        buf[n++] = 'r';
                        break;
                case '\\':
                        buf[n++] = '\\';
                        buf[n++] = '\\';
                        break;
                default:
                        buf[n++] = *p;
                }

        buf[n] = 0;
        *ret = TAKE_PTR(buf);
        return 1;
}

static int manifest_sha256sums_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ManifestContext *c = ASSERT_PTR(userdata);
        int r;

        /* Generates output compatible with sha256sum(1), i.e. what "sha256sum -c" (and systemd-sysupdate)
         * consume. Only regular files are listed, like sha256sum would do it. */

        assert(path);

        if (manifest_handle_skip_event(c, event, path))
                return RECURSE_DIR_CONTINUE;

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        assert(sx);

        if (!FLAGS_SET(sx->stx_mask, STATX_TYPE) || !S_ISREG(sx->stx_mode)) {
                log_warning("Skipping non-regular file '%s' because not representable in manifest format.", path);
                c->n_skipped++;
                return RECURSE_DIR_CONTINUE;
        }

        /* We ignore this to avoid input-as-output cycles (only on top-level though!) */
        if (streq(path, "SHA256SUMS") || (startswith(path, "SHA256SUMS.") && !strchr(path, '/'))) {
                log_debug("Skipping directory entry '%s' to avoid recursive manifest generation.", path);
                return RECURSE_DIR_CONTINUE;
        }

        assert(inode_fd >= 0);

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = manifest_context_hash_fd(c, inode_fd, hash);
        if (r < 0) {
                log_warning_errno(r, "Failed to calculate hash of file '%s', ignoring: %m", path);
                c->n_skipped++;
                return RECURSE_DIR_CONTINUE;
        }

        _cleanup_free_ char *h = hexmem(hash, SHA256_DIGEST_SIZE);
        if (!h)
                return log_oom();

        _cleanup_free_ char *escaped = NULL;
        r = sums_escape(path, &escaped);
        if (r < 0)
                return log_error_errno(r, "Failed to escape string for manifest: %m");

        fprintf(c->output,
                "%s%s  %s\n",
                escaped ? "\\" : "",
                h,
                escaped ?: path);

        return RECURSE_DIR_CONTINUE;
}

int manifest_make(ManifestContext *c, int dir_fd) {
        int r;

        assert(c);
        assert(dir_fd >= 0);

        if (!c->output)
                c->output = stdout;

        if (!c->color)
                c->json_format_flags &= ~(SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_COLOR_AUTO);

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

        case MANIFEST_FORMAT_SHA256SUMS:
                if (!FLAGS_SET(c->fields, MANIFEST_FIELD_HASH))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot generate SHA256SUMS manifest without hash field.");

                statx_mask = STATX_TYPE|STATX_SIZE;
                flags |= RECURSE_DIR_INODE_FD;
                item_callback = manifest_sha256sums_item;
                break;

        case MANIFEST_FORMAT_UAPI16:
                statx_mask |= manifest_uapi16_fields_to_statx(c->fields);
                flags |= RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL;
                item_callback = manifest_uapi16_item;
                break;

        default:
                assert_not_reached();
        }

        r = recurse_dir(dir_fd, path, statx_mask, /* n_depth_max= */ UINT_MAX, flags, item_callback, c);
        if (r < 0)
                return r;

        /* These formats do not list the top-level inode itself, hence enumerating it is all we can do */
        if (IN_SET(c->format, MANIFEST_FORMAT_LIST, MANIFEST_FORMAT_SHA256SUMS))
                c->top_level_covered = true;

        if (c->format == MANIFEST_FORMAT_UAPI16) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
                r = sd_json_buildo(
                                &j,
                                SD_JSON_BUILD_PAIR("mediaType", JSON_BUILD_CONST_STRING(UAPI16_TRAILER_MEDIA_TYPE)));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON object: %m");

                r = sd_json_variant_dump(j, c->json_format_flags | SD_JSON_FORMAT_SEQ, c->output, /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to write JSON output: %m");
        }

        r = fflush_and_check(c->output);
        if (r < 0)
                return log_error_errno(r, "Failed to write manifest: %m");

        return 0;
}

static int sums_unescape(const char *s, char **ret) {
        _cleanup_free_ char *buf = NULL;
        size_t n = 0;

        assert(s);
        assert(ret);

        /* Reverses sums_escape() */

        buf = new(char, strlen(s) + 1);
        if (!buf)
                return -ENOMEM;

        for (const char *p = s; *p; p++) {
                if (*p != '\\') {
                        buf[n++] = *p;
                        continue;
                }

                p++;
                switch (*p) {
                case 'n':
                        buf[n++] = '\n';
                        break;
                case 'r':
                        buf[n++] = '\r';
                        break;
                case '\\':
                        buf[n++] = '\\';
                        break;
                default:
                        return -EINVAL;
                }
        }

        buf[n] = 0;
        *ret = TAKE_PTR(buf);
        return 0;
}

int manifest_parse_sums(
                FILE *f,
                size_t *line_nr,
                char **ret_filename,
                struct iovec *ret_digest) {

        int r;

        assert(f);
        assert(line_nr);
        assert(ret_filename);
        assert(ret_digest);

        size_t hash_len = SHA256_DIGEST_SIZE * 2;

        _cleanup_free_ char *line = NULL;
        r = read_line(f, LONG_LINE_MAX, &line);
        if (r < 0)
                return log_error_errno(r, "Failed to read manifest line %zu: %m", *line_nr + 1);
        if (r == 0) {
                *ret_filename = NULL;
                *ret_digest = (struct iovec) {};
                return 0;
        }

        size_t n = ++(*line_nr);

        if (!utf8_is_valid(line))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest line %zu is not valid UTF-8, refusing.", n);

        const char *p = line;

        /* coreutils prefixes lines whose file names contain characters that need escaping with a
         * backslash. */
        bool escaped = p[0] == '\\';
        if (escaped)
                p++;

        /* hash + separator + filename */
        if (strlen(p) < hash_len + 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Corrupt manifest at line %zu, refusing.", n);

        _cleanup_(iovec_done) struct iovec digest = {};
        r = unhexmem_full(p, hash_len, /* secure= */ false, &digest.iov_base, &digest.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to parse digest at manifest line %zu, refusing.", n);
        /* unhexmem_full() skips whitespace, hence the result might be shorter than expected */
        if (digest.iov_len != SHA256_DIGEST_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Manifest hash at line %zu decoded to %zu bytes, refusing.",
                                       n, digest.iov_len);
        p += hash_len;

        if (*p != ' ')
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing space separator at manifest line %zu, refusing.", n);
        p++;

        if (!IN_SET(*p, '*', ' '))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing binary/text input marker at manifest line %zu, refusing.", n);
        p++;

        if (isempty(p))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty filename specified at manifest line %zu, refusing.", n);

        _cleanup_free_ char *fn = NULL;
        if (escaped) {
                r = sums_unescape(p, &fn);
                if (r < 0)
                        return log_error_errno(r, "Invalid escaping in filename at manifest line %zu, refusing.", n);
        } else {
                fn = strdup(p);
                if (!fn)
                        return log_oom();
        }

        /* Accept either a plain filename or a relative subpath like "subdir/file" but reject
         * absolute paths and any paths containing "." or ".." */
        if (path_is_absolute(fn) || !path_is_normalized(fn))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid filename specified at manifest line %zu, refusing.", n);

        *ret_filename = TAKE_PTR(fn);
        *ret_digest = TAKE_STRUCT(digest);
        return 1;
}

void manifest_verify_error(ManifestContext *c, const char *path, const char *format, ...) {
        int r;

        assert(c);
        assert(format);

        /* Reports a mismatch. We count them, and continue with the next entry, so that users get a full
         * picture. */

        va_list ap;
        va_start(ap, format);
        _cleanup_free_ char *m = NULL;
        r = vasprintf(&m, format, ap);
        va_end(ap);
        if (r < 0)
                (void) log_oom();
        else
                log_error("%s: %s", path ?: ".", m);

        c->n_errors++;
}

int manifest_verify_hash(
                ManifestContext *c,
                const char *path,
                int inode_fd,
                const struct iovec *expected) {

        uint8_t hash[SHA256_DIGEST_SIZE];
        int r;

        assert(c);
        assert(path);
        assert(inode_fd >= 0);
        assert(iovec_is_set(expected));

        if (expected->iov_len != SHA256_DIGEST_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected hash size for '%s'.", path);

        r = manifest_context_hash_fd(c, inode_fd, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate hash of '%s': %m", path);

        if (memcmp_nn(hash, SHA256_DIGEST_SIZE, expected->iov_base, expected->iov_len) != 0) {
                manifest_verify_error(c, path, "Hash mismatch.");
                return -ENXIO;
        }

        return 0;
}

static int manifest_stat_file(
                ManifestContext *c,
                int dir_fd,
                const char *path,
                unsigned statx_mask,
                struct statx *ret_sx,
                struct iovec *ret_hash,
                int *ret_fd) {

        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(c);
        assert(dir_fd >= 0);

        /* Opens the specified relative path below the specified directory fd as O_PATH fd, without ever
         * following symlinks, mirroring how recurse_dir() enumerates the tree. */

        if (path) {
                assert(!path_is_absolute(path));
                assert(path_is_normalized(path));
        } else
                path = ".";

        r = chaseat(dir_fd, dir_fd, path, CHASE_NOFOLLOW|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, &fd);
        if (IN_SET(r, -ENOENT, -ENOTDIR)) {
                manifest_verify_error(c, path, "Listed in manifest, but missing in tree.");
                return 0;
        }
        if (IN_SET(r, -EREMCHG, -ELOOP)) { /* chase() reports prohibited symlinks as EREMCHG, openat2() as ELOOP */
                manifest_verify_error(c, path, "Listed in manifest, but a symlink is in the way.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s': %m", path);

        struct statx sx;
        if (ret_sx || ret_hash) {
                r = xstatx(fd, "", AT_EMPTY_PATH, (ret_sx ? statx_mask : 0) | (ret_hash ? STATX_TYPE : 0), &sx);
                if (r < 0)
                        return log_error_errno(r, "Failed to stat '%s': %m", path);
        }

        if (ret_hash) {
                if (S_ISREG(sx.stx_mode)) {
                        _cleanup_free_ uint8_t *h = new(uint8_t, SHA256_DIGEST_SIZE);
                        if (!h)
                                return -ENOMEM;

                        r = manifest_context_hash_fd(c, fd, h);
                        if (r < 0)
                                return r;

                        *ret_hash = IOVEC_MAKE(TAKE_PTR(h), SHA256_DIGEST_SIZE);
                } else
                        *ret_hash = (struct iovec) {};
        }

        if (ret_sx)
                *ret_sx = sx;

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 1;
}

static int verify_list(ManifestContext *c, int dir_fd, FILE *f) {
        int r;

        assert(c);
        assert(dir_fd >= 0);
        assert(f);

        for (size_t line_nr = 1;; line_nr++) {
                _cleanup_free_ char *line = NULL;
                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read manifest line %zu: %m", line_nr);
                if (r == 0)
                        break;

                if (isempty(line))
                        continue;

                char *is_dir = endswith(line, "/");
                if (is_dir)
                        *is_dir = 0;

                if (isempty(line) || path_is_absolute(line) || !path_is_normalized(line))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path specified at manifest line %zu, refusing.", line_nr);

                struct statx sx;
                r = manifest_stat_file(
                                c,
                                dir_fd,
                                line,
                                STATX_TYPE,
                                &sx,
                                /* ret_hash= */ NULL,
                                /* ret_fd= */ NULL);
                if (r < 0)
                        return r;
                if (r == 0) /* check already failed */
                        continue;

                if (is_dir) {
                        if (!S_ISDIR(sx.stx_mode))
                                manifest_verify_error(c, line, "Expected directory, but found non-directory.");
                        else
                                log_debug("'%s' exists and is a directory as expected.", line);
                } else {
                        /* Directories are always listed with a trailing slash, hence an entry without one
                         * refers to a non-directory */
                        if (S_ISDIR(sx.stx_mode))
                                manifest_verify_error(c, line, "Expected non-directory, but found directory.");
                        else
                                log_debug("'%s' exists.", line);
                }
        }

        return 0;
}

static int verify_sha256sums_line(
                ManifestContext *c,
                int dir_fd,
                const char *filename,
                const struct iovec *digest) {

        int r;

        assert(c);
        assert(dir_fd >= 0);
        assert(filename);

        struct statx sx;
        _cleanup_(iovec_done) struct iovec hash = {};
        r = manifest_stat_file(
                        c,
                        dir_fd,
                        filename,
                        STATX_TYPE,
                        &sx,
                        FLAGS_SET(c->fields, MANIFEST_FIELD_HASH) ? &hash : NULL,
                        /* ret_fd= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) /* check already failed */
                return 0;

        if (!S_ISREG(sx.stx_mode)) {
                manifest_verify_error(c, filename, "Expected regular file, but found %s.", strna(inode_type_to_string(sx.stx_mode)));
                return 0;
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_HASH)) {
                if (!iovec_equal(digest, &hash))
                        manifest_verify_error(c, filename, "Hash of '%s' does not match.", filename);
                else
                        log_debug("'%s' exists and matches manifest.", filename);
        } else
                log_debug("'%s' exists.", filename);

        return 0;
}

static int verify_sha256sums(ManifestContext *c, int dir_fd, FILE *f) {
        int r;

        assert(c);
        assert(dir_fd >= 0);
        assert(f);

        for (size_t line_nr = 0;;) {
                _cleanup_free_ char *fn = NULL;
                _cleanup_(iovec_done) struct iovec digest = {};
                r = manifest_parse_sums(f, &line_nr, &fn, &digest);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                r = verify_sha256sums_line(c, dir_fd, fn, &digest);
                if (r < 0)
                        return r;
        }
}

static int hardlink_db_verify(
                ManifestContext *c,
                const char *path,
                int inode_fd,
                uint64_t token) {

        _cleanup_free_ char *fhs = NULL, *ts = NULL, *stored = NULL;
        int r;

        assert(c);
        assert(inode_fd >= 0);
        assert(!IN_SET(token, 0, UINT64_MAX));

        /* Checks that all names carrying the same inode token refer to the same inode, and that no two
         * distinct inodes share a token. We store two symlinks per hardlinked inode in the database: one
         * named after the FID pointing to the token, and one named after the token pointing to the FID. */

        r = inode_fid_hex(inode_fd, &fhs);
        if (r <= 0)
                return r;

        r = hardlink_db_acquire(c);
        if (r < 0)
                return r;

        ts = asprintf_safe("token-%" PRIu64, token);
        if (!ts)
                return log_oom();

        r = readlinkat_malloc(c->db_fd, fhs, &stored);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read hardlink database symlink '%s': %m", fhs);
        if (r >= 0) {
                if (!streq(stored, ts))
                        manifest_verify_error(c, path, "Inode token %" PRIu64 " in manifest, but inode already seen with a different token.", token);
                return 0;
        }

        stored = mfree(stored);
        r = readlinkat_malloc(c->db_fd, ts, &stored);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read hardlink database symlink '%s': %m", ts);
        if (r >= 0) {
                /* We haven't seen this inode before, but the token: hence two different inodes share a token */
                manifest_verify_error(c, path, "Inode token %" PRIu64 " in manifest already used by a different inode, not a hardlink.", token);
                return 0;
        }

        if (symlinkat(ts, c->db_fd, fhs) < 0)
                return log_error_errno(errno, "Failed to create hardlink database symlink '%s': %m", fhs);
        if (symlinkat(fhs, c->db_fd, ts) < 0)
                return log_error_errno(errno, "Failed to create hardlink database symlink '%s': %m", ts);

        return 0;
}

static int verify_user_xattrs(ManifestContext *c, const Uapi16Object *o, int fd) {
        int r;

        assert(c);
        assert(o);
        assert(o->user_xattrs_set);
        assert(fd >= 0);

        Uapi16Xattr *x = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(x, n, uapi16_xattr_array_free);

        r = manifest_read_user_xattrs(fd, &x, &n);
        if (r == -EUCLEAN) {
                manifest_verify_error(c, o->name, "Inode carries an extended attribute whose name cannot be represented in a manifest.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read extended attributes of '%s': %m", o->name ?: ".");

        /* Both lists are sorted by name, hence compare them in one pass */
        size_t i = 0, j = 0;
        while (i < o->n_user_xattrs || j < n) {
                int d = i >= o->n_user_xattrs ? 1 :
                        j >= n ? -1 :
                        strcmp(o->user_xattrs[i].name, x[j].name);

                if (d < 0) {
                        manifest_verify_error(c, o->name, "Extended attribute 'user.%s' is missing.", o->user_xattrs[i].name);
                        i++;
                } else if (d > 0) {
                        manifest_verify_error(c, o->name, "Unexpected extended attribute 'user.%s'.", x[j].name);
                        j++;
                } else {
                        if (iovec_memcmp(&o->user_xattrs[i].value, &x[j].value) != 0)
                                manifest_verify_error(c, o->name, "Value of extended attribute 'user.%s' does not match.", x[j].name);
                        i++;
                        j++;
                }
        }

        return 0;
}

static int verify_object(ManifestContext *c, int dir_fd, const Uapi16Object *o) {
        int r;

        assert(c);
        assert(dir_fd >= 0);
        assert(o);

        uint64_t saved_errors = c->n_errors;

        struct statx sx;
        _cleanup_close_ int fd = -EBADF;
        r = manifest_stat_file(
                        c,
                        dir_fd,
                        o->name,
                        STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID|STATX_SIZE|STATX_MTIME,
                        &sx,
                        /* ret_hash= */ NULL,
                        &fd);
        if (r <= 0)
                return r;

        if ((sx.stx_mode & S_IFMT) != o->type) {
                manifest_verify_error(c, o->name, "Expected inode type '%s', but found '%s'.",
                                      strna(inode_type_to_string(o->type)),
                                      strna(inode_type_to_string(sx.stx_mode)));
                return 0; /* No point in checking anything else */
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_MODE) && o->mode != MODE_INVALID && (sx.stx_mode & 07777) != o->mode)
                manifest_verify_error(c, o->name, "Expected access mode 0%04o, but found 0%04o.", (unsigned) o->mode, (unsigned) (sx.stx_mode & 07777));

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_UID) && uid_is_valid(o->uid) && sx.stx_uid != o->uid)
                manifest_verify_error(c, o->name, "Expected UID " UID_FMT ", but found " UID_FMT ".", o->uid, sx.stx_uid);

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_GID) && gid_is_valid(o->gid) && sx.stx_gid != o->gid)
                manifest_verify_error(c, o->name, "Expected GID " GID_FMT ", but found " GID_FMT ".", o->gid, sx.stx_gid);

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_MTIME) && o->mtime_nsec != NSEC_INFINITY && statx_timestamp_load_nsec(&sx.stx_mtime) != o->mtime_nsec)
                manifest_verify_error(c, o->name, "Modification time mismatch.");

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_USER_XATTR) && o->user_xattrs_set) {
                r = verify_user_xattrs(c, o, fd);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(c->fields, MANIFEST_FIELD_DEVICE) && (S_ISBLK(o->type) || S_ISCHR(o->type))) {
                if (o->major != UINT64_MAX && sx.stx_rdev_major != o->major)
                        manifest_verify_error(c, o->name, "Expected device major %" PRIu64 ", but found %" PRIu32 ".", o->major, sx.stx_rdev_major);
                if (o->minor != UINT64_MAX && sx.stx_rdev_minor != o->minor)
                        manifest_verify_error(c, o->name, "Expected device minor %" PRIu64 ", but found %" PRIu32 ".", o->minor, sx.stx_rdev_minor);
        }

        /* Inode tokens are only assigned to non-directory inodes, the dispatcher refuses them otherwise */
        if (FLAGS_SET(c->fields, MANIFEST_FIELD_HARDLINK) && !IN_SET(o->inode_token, 0, UINT64_MAX)) {
                r = hardlink_db_verify(c, o->name, fd, o->inode_token);
                if (r < 0)
                        return r;
        }

        if (S_ISREG(o->type)) {
                if (FLAGS_SET(c->fields, MANIFEST_FIELD_SIZE) && o->size != UINT64_MAX && sx.stx_size != o->size)
                        manifest_verify_error(c, o->name, "Expected size %" PRIu64 ", but found %" PRIu64 ".", o->size, (uint64_t) sx.stx_size);
                else if (FLAGS_SET(c->fields, MANIFEST_FIELD_HASH) && iovec_is_set(&o->sha256))
                        (void) manifest_verify_hash(c, o->name, fd, &o->sha256);
        }

        if (S_ISLNK(o->type) && FLAGS_SET(c->fields, MANIFEST_FIELD_SYMLINK)) {
                /* We generate the symlink target as first "contents" entry with a literal */
                const Uapi16Contents *literal = NULL;
                FOREACH_ARRAY(i, o->contents, o->n_contents)
                        if (iovec_is_set(&i->literal)) {
                                literal = i;
                                break;
                        }

                if (literal) {
                        _cleanup_free_ char *target = NULL;
                        r = readlinkat_malloc(fd, "", &target);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read symlink '%s': %m", o->name ?: ".");

                        if (iovec_memcmp(&IOVEC_MAKE_STRING(target), &literal->literal) != 0)
                                manifest_verify_error(c, o->name, "Symlink target mismatch.");
                }
        }

        log_debug(c->n_errors == saved_errors ?
                  "'%s' exists and matches manifest." :
                  "'%s' exists but does not fully match manifest.", o->name ?: ".");

        return 0;
}

typedef struct VerifyObjectContext {
        ManifestContext *context;
        int dir_fd;
} VerifyObjectContext;

static int verify_object_handler(Uapi16Object *o, size_t index, void *userdata) {
        VerifyObjectContext *vc = ASSERT_PTR(userdata);
        int r;

        assert(o);

        r = uapi16_object_check_validity(o);
        if (r == -ESTALE)
                log_warning_errno(r, "File object not within its validity time window, processing anyway.");
        else if (r == -EHWPOISON)
                log_warning_errno(r, "File object has been revoked, processing anyway.");
        else if (r < 0)
                return log_error_errno(r, "Failed to check file object validity: %m");

        return verify_object(vc->context, vc->dir_fd, o);
}

static int uapi16_manifest_verify(ManifestContext *c, int dir_fd, FILE *f) {
        assert(c);
        assert(dir_fd >= 0);
        assert(f);

        return uapi16_manifest_read(
                        f,
                        verify_object_handler,
                        &(VerifyObjectContext) {
                                .context = c,
                                .dir_fd = dir_fd,
                        });
}

int manifest_verify(ManifestContext *c, int dir_fd, FILE *f) {
        int r;

        assert(c);
        assert(dir_fd >= 0);
        assert(f);

        switch (c->format) {

        case MANIFEST_FORMAT_LIST:
                r = verify_list(c, dir_fd, f);
                break;

        case MANIFEST_FORMAT_SHA256SUMS:
                r = verify_sha256sums(c, dir_fd, f);
                break;

        case MANIFEST_FORMAT_MTREE:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Verification of mtree manifests is not supported.");

        case MANIFEST_FORMAT_UAPI16:
                r = uapi16_manifest_verify(c, dir_fd, f);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        if (c->n_errors > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Found %" PRIu64 " mismatches between manifest and directory tree.", c->n_errors);

        log_info("Directory tree matches manifest.");
        return 0;
}

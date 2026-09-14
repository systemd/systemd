/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
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

static int hardlink_data_lookup(
                ManifestContext *c,
                const char *path,
                int inode_fd,
                const struct statx *sx,
                uint64_t *ret_hardlink_counter,
                uint8_t ret_hash[static SHA256_DIGEST_SIZE],
                bool *ret_hash_valid) {

        _cleanup_free_ struct file_handle *handle = NULL;
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

        /* Generate a unique identifier for this inode via the kernel's FID logic. */
        uint64_t unique_mnt_id = 0;
        int mnt_id = 0;
        r = name_to_handle_at_try_fid(inode_fd, /* path= */ NULL, &handle, &mnt_id, &unique_mnt_id, AT_EMPTY_PATH);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_debug_errno(r, "File system does not support FIDs, not checking for hardlinks: %m");
                goto nope;
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

        fhs = hexmem(fid_hash, sizeof(fid_hash));
        if (!fhs)
                return log_oom();

        bool is_empty = false;
        if (c->db_fd < 0) {
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

                is_empty = true;
        }

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

static int manifest_uapi16_xattrs(const char *path, int inode_fd, sd_json_variant **ret) {
        int r;

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
                *ret = NULL;
                return 0;
        }
        if (r < 0) {
                log_warning_errno(r, "Failed to read extended attributes of '%s', ignoring: %m", empty_to_root(path));
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

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        /* We ignore this to avoid input-as-output cycles (only on top-level though!) */
        if (path && uapi16_manifest_filename_is_reserved(path)) {
                log_debug("Skipping directory entry '%s' to avoid recursive manifest generation.", path);
                return RECURSE_DIR_CONTINUE;
        }

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
                                if (r < 0)
                                        log_warning_errno(r, "Failed to calculate file SHA256 sum for '%s', ignoring: %m", empty_to_root(path));
                                else
                                        hash_valid = true;
                        }

                        break;

                case S_IFLNK:
                        if (FLAGS_SET(c->fields, MANIFEST_FIELD_SYMLINK) && inode_fd >= 0) {
                                r = readlinkat_malloc(inode_fd, "", &data);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to read symlink '%s', ignoring: %m", empty_to_root(path));
                                else {
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
                r = manifest_uapi16_xattrs(path, inode_fd, &jx);
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

        return RECURSE_DIR_CONTINUE;
}

static int sums_escape(const char *s, char **ret) {
        assert(s);
        assert(ret);

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

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        assert(sx);

        if (!FLAGS_SET(sx->stx_mask, STATX_TYPE)) {
                log_warning("Skipping '%s' because its inode type is unknown.", path);
                c->n_skipped++;
                return RECURSE_DIR_CONTINUE;
        }

        /* The format only lists regular files by design, hence skipping anything else is expected */
        if (!S_ISREG(sx->stx_mode)) {
                log_info("Skipping non-regular file '%s' because not representable in SHA256SUMS format.", path);
                c->n_skipped++;
                c->n_skipped_expected++;
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

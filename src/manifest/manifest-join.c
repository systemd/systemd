/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "json-util.h"
#include "log.h"
#include "manifest-join.h"
#include "manifest-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sha256.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"

/* To join manifests of arbitrary size without holding them in memory, the objects are collected in a
 * temporary directory below /var/tmp/, with the following layout:
 *
 *     objects/<sha256(name)>   The object, normalized and without its inode token, wrapped in an object that
 *                              also records the index of the input it was taken from
 *     tokens/<sha256(name)>    Symlink to the hardlink group of the object, if it has one
 *     tree/<name>/             An empty directory for each object, mirroring its path, so that walking this
 *                              tree sorted yields the objects in the very same order "make" generates them
 *     inputs/<input>-<token>   Symlink to the hardlink group an inode token of an input belongs to
 *     groups/<group>           Symlink to the parent group, for groups that have been merged into another
 *     out/<group>              Symlink to the inode token assigned in the output to a (root) group
 *
 * The leading object of a manifest (i.e. the one describing the top-level inode) is stored under the hash of
 * the empty string, and corresponds to tree/ itself.
 *
 * Hardlink groups are tracked as union-find structure: whenever two inputs tie the same object to a token
 * belonging to different groups, the groups are merged. Hence if one input says X and Y are hardlinked, and
 * another says Y and Z are, then X, Y and Z end up in the same group. A group is always merged into the one
 * with the lower number, which means parent pointers always point to lower numbers, and lookups terminate. */

typedef struct JoinContext {
        int db_fd;
        char *db_path;

        int objects_fd;
        int tokens_fd;
        int tree_fd;
        int inputs_fd;
        int groups_fd;
        int out_fd;

        char * const *inputs;
        size_t n_inputs;
        size_t current_input;

        uint64_t n_groups;          /* Number of hardlink groups allocated so far */
        uint64_t n_tokens;          /* Number of inode tokens assigned in the output so far */
        uint64_t n_objects;         /* Number of distinct objects */
        uint64_t n_conflicts;       /* Number of conflicting objects */

        ManifestContext *manifest;  /* Not owned. The output */
} JoinContext;

#define JOIN_CONTEXT_NULL                       \
        (JoinContext) {                         \
                .db_fd = -EBADF,                \
                .objects_fd = -EBADF,           \
                .tokens_fd = -EBADF,            \
                .tree_fd = -EBADF,              \
                .inputs_fd = -EBADF,            \
                .groups_fd = -EBADF,            \
                .out_fd = -EBADF,               \
        }

static void join_context_done(JoinContext *j) {
        assert(j);

        j->objects_fd = safe_close(j->objects_fd);
        j->tokens_fd = safe_close(j->tokens_fd);
        j->tree_fd = safe_close(j->tree_fd);
        j->inputs_fd = safe_close(j->inputs_fd);
        j->groups_fd = safe_close(j->groups_fd);
        j->out_fd = safe_close(j->out_fd);

        if (j->db_fd >= 0)
                (void) rm_rf_children(TAKE_FD(j->db_fd), REMOVE_PHYSICAL|REMOVE_REWIND, /* root_dev= */ NULL);

        j->db_path = rmdir_and_free(j->db_path);
}

static int join_context_setup(JoinContext *j) {
        int r;

        assert(j);
        assert(j->db_fd < 0);

        /* Let's use a temporary directory on disk, like the hardlink database of manifest_make(), so that
         * we can process very large manifests without allocating ridiculous amounts of memory. */

        const char *vtd = NULL;
        r = var_tmp_dir(&vtd);
        if (r < 0)
                return log_error_errno(r, "Failed to determine /var/tmp/ directory: %m");

        _cleanup_free_ char *template = path_join(vtd, "manifest-join-XXXXXX");
        if (!template)
                return log_oom();

        j->db_fd = mkdtemp_open(template, /* flags= */ 0, &j->db_path);
        if (j->db_fd < 0)
                return log_error_errno(j->db_fd, "Failed to create temporary directory: %m");

        struct {
                const char *name;
                int *fd;
        } table[] = {
                { "objects", &j->objects_fd },
                { "tokens",  &j->tokens_fd  },
                { "tree",    &j->tree_fd    },
                { "inputs",  &j->inputs_fd  },
                { "groups",  &j->groups_fd  },
                { "out",     &j->out_fd     },
        };

        FOREACH_ELEMENT(i, table) {
                *i->fd = open_mkdir_at(j->db_fd, i->name, O_EXCL, 0700);
                if (*i->fd < 0)
                        return log_error_errno(*i->fd, "Failed to create directory '%s' in '%s': %m", i->name, j->db_path);
        }

        return 0;
}

static int join_object_key(const char *name, char **ret) {
        assert(name);
        assert(ret);

        /* The objects are keyed by the SHA256 hash of their name, so that the file names in the database are
         * of fixed length, whatever the name looks like */

        char *k = hexmem(SHA256_DIRECT(name, strlen(name)), SHA256_DIGEST_SIZE);
        if (!k)
                return log_oom();

        *ret = k;
        return 0;
}

static int read_number_link(int dir_fd, const char *name, uint64_t *ret) {
        int r;

        assert(dir_fd >= 0);
        assert(name);
        assert(ret);

        /* Reads a symlink in the database pointing to a positive number. Returns 0 and sets *ret to zero if
         * the symlink doesn't exist. */

        _cleanup_free_ char *s = NULL;
        r = readlinkat_malloc(dir_fd, name, &s);
        if (r == -ENOENT) {
                *ret = 0;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read symlink '%s' in join database: %m", name);

        uint64_t n;
        r = safe_atou64(s, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse symlink '%s' in join database: %m", name);
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Symlink '%s' in join database points to zero, refusing.", name);

        *ret = n;
        return 1;
}

static int write_number_link(int dir_fd, const char *name, uint64_t n) {
        assert(dir_fd >= 0);
        assert(name);
        assert(n > 0);

        char t[DECIMAL_STR_MAX(uint64_t)];
        xsprintf(t, "%" PRIu64, n);

        if (symlinkat(t, dir_fd, name) < 0)
                return log_error_errno(errno, "Failed to create symlink '%s' in join database: %m", name);

        return 0;
}

static int join_group_find(JoinContext *j, uint64_t group, uint64_t *ret) {
        int r;

        assert(j);
        assert(group > 0);
        assert(ret);

        /* Returns the root of the group, i.e. the group all groups merged with it are represented by */

        uint64_t root = group;
        for (;;) {
                char k[DECIMAL_STR_MAX(uint64_t)];
                xsprintf(k, "%" PRIu64, root);

                uint64_t parent;
                r = read_number_link(j->groups_fd, k, &parent);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Groups are always merged into the one with the lower number, this guarantees we terminate */
                if (parent >= root)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Group %" PRIu64 " in join database has invalid parent group %" PRIu64 ", refusing.", root, parent);

                root = parent;
        }

        *ret = root;
        return 0;
}

static int join_group_merge(JoinContext *j, uint64_t a, uint64_t b, uint64_t *ret) {
        int r;

        assert(j);
        assert(a > 0);
        assert(b > 0);
        assert(ret);

        r = join_group_find(j, a, &a);
        if (r < 0)
                return r;

        r = join_group_find(j, b, &b);
        if (r < 0)
                return r;

        if (a != b) {
                uint64_t lower = MIN(a, b), higher = MAX(a, b);

                log_debug("Merging hardlink group %" PRIu64 " into %" PRIu64 ".", higher, lower);

                char k[DECIMAL_STR_MAX(uint64_t)];
                xsprintf(k, "%" PRIu64, higher);

                r = write_number_link(j->groups_fd, k, lower);
                if (r < 0)
                        return r;

                a = lower;
        }

        *ret = a;
        return 0;
}

static int join_record_token(JoinContext *j, const char *key, uint64_t token) {
        int r;

        assert(j);
        assert(key);
        assert(!IN_SET(token, 0, UINT64_MAX));

        /* Ties the object with the specified key to the hardlink group the inode token of the current input
         * maps to. If the object already belongs to a group, and so does the token, but they are different,
         * the two groups are merged. */

        char ik[DECIMAL_STR_MAX(size_t) + 1 + DECIMAL_STR_MAX(uint64_t)];
        xsprintf(ik, "%zu-%" PRIu64, j->current_input, token);

        uint64_t group_input;
        r = read_number_link(j->inputs_fd, ik, &group_input);
        if (r < 0)
                return r;

        uint64_t group_object;
        r = read_number_link(j->tokens_fd, key, &group_object);
        if (r < 0)
                return r;

        uint64_t group;
        if (group_input == 0 && group_object == 0) {
                if (j->n_groups >= UINT64_MAX - 1) /* Paranoia */
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Too many hardlink groups.");

                group = ++j->n_groups;
        } else if (group_input == 0)
                group = group_object;
        else if (group_object == 0)
                group = group_input;
        else {
                r = join_group_merge(j, group_input, group_object, &group);
                if (r < 0)
                        return r;
        }

        if (group_input == 0) {
                r = write_number_link(j->inputs_fd, ik, group);
                if (r < 0)
                        return r;
        }

        if (group_object == 0) {
                r = write_number_link(j->tokens_fd, key, group);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const char* join_object_display_name(const char *name) {
        return isempty(name) ? "top-level inode" : name;
}

/* An object as stored in the database, along with the index of the input it was taken from */
typedef struct JoinStoredObject {
        uint64_t input;
        sd_json_variant *object;
} JoinStoredObject;

static void join_stored_object_done(JoinStoredObject *s) {
        assert(s);

        s->object = sd_json_variant_unref(s->object);
}

static int join_load_object(JoinContext *j, const char *key, JoinStoredObject *ret) {
        int r;

        assert(j);
        assert(key);
        assert(ret);

        /* Loads the object with the specified key from the database. Returns 0 if there's no such object. */

        _cleanup_fclose_ FILE *f = NULL;
        r = xfopenat(j->objects_fd, key, "re", /* open_flags= */ 0, &f);
        if (r == -ENOENT) {
                *ret = (JoinStoredObject) {};
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open object '%s' in join database: %m", key);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        r = sd_json_parse_file_at(f, j->objects_fd, key, /* flags= */ 0, &w, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse object '%s' in join database: %m", key);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "input",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,  offsetof(JoinStoredObject, input),  SD_JSON_MANDATORY },
                { "object", SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant, offsetof(JoinStoredObject, object), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(join_stored_object_done) JoinStoredObject s = {};
        r = sd_json_dispatch(w, dispatch_table, SD_JSON_LOG, &s);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(s);
        return 1;
}

static int join_log_conflict(JoinContext *j, const char *name, const JoinStoredObject *stored, sd_json_variant *v) {
        int r;

        assert(j);
        assert(name);
        assert(stored);
        assert(v);

        sd_json_variant *a = stored->object;

        /* Figure out which fields differ, to make the log message useful */
        _cleanup_strv_free_ char **fields = NULL;
        const char *k;
        sd_json_variant *e;
        JSON_VARIANT_OBJECT_FOREACH(k, e, a) {
                sd_json_variant *other = sd_json_variant_by_key(v, k);
                if (other && sd_json_variant_equal(e, other))
                        continue;

                r = strv_extend(&fields, k);
                if (r < 0)
                        return log_oom();
        }
        JSON_VARIANT_OBJECT_FOREACH(k, e, v) {
                if (sd_json_variant_by_key(a, k))
                        continue;

                r = strv_extend(&fields, k);
                if (r < 0)
                        return log_oom();
        }

        _cleanup_free_ char *l = strv_join(fields, ", ");
        if (!l)
                return log_oom();

        log_error("Definition of %s%s%s in '%s' conflicts with the one in '%s' (differing fields: %s).",
                  isempty(name) ? "" : "'",
                  join_object_display_name(name),
                  isempty(name) ? "" : "'",
                  j->inputs[j->current_input],
                  stored->input < j->n_inputs ? j->inputs[stored->input] : "n/a",
                  l);

        return 0;
}

static int join_store_object(JoinContext *j, const char *key, sd_json_variant *v, bool replace) {
        int r;

        assert(j);
        assert(key);
        assert(v);

        /* Store the object along with the index of the input it came from, for log messages */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        r = sd_json_buildo(
                        &w,
                        SD_JSON_BUILD_PAIR_UNSIGNED("input", j->current_input),
                        SD_JSON_BUILD_PAIR_VARIANT("object", v));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        r = json_variant_write_file_at(
                        j->objects_fd,
                        key,
                        w,
                        /* format_flags= */ 0,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MODE_0600|(replace ? WRITE_STRING_FILE_TRUNCATE : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to write object '%s' to join database: %m", key);

        return 0;
}

static int dispatch_mtime(sd_json_variant *v, uint64_t *ret) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "mTimeNSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, 0, 0 },
                {}
        };

        int r;

        assert(v);
        assert(ret);

        /* Extracts the modification time of an object, NSEC_INFINITY if it has none */

        uint64_t mtime = NSEC_INFINITY;
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &mtime);
        if (r < 0)
                return r;

        *ret = mtime;
        return 0;
}

static int join_resolve_mtime(JoinContext *j, const char *key, const JoinStoredObject *stored, sd_json_variant *v) {
        int r;

        assert(j);
        assert(key);
        assert(stored);
        assert(v);

        /* If two definitions of the same object differ in their modification time only, the newest one
         * wins. A definition without modification time conveys no information about it, hence any other is
         * considered newer. Returns > 0 if the definitions could be reconciled that way, 0 if they differ in
         * anything else. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a_filtered = sd_json_variant_ref(stored->object), *v_filtered = sd_json_variant_ref(v);
        r = sd_json_variant_filter(&a_filtered, STRV_MAKE("mTimeNSec"));
        if (r < 0)
                return log_error_errno(r, "Failed to remove modification time from object: %m");

        r = sd_json_variant_filter(&v_filtered, STRV_MAKE("mTimeNSec"));
        if (r < 0)
                return log_error_errno(r, "Failed to remove modification time from object: %m");

        if (!sd_json_variant_equal(a_filtered, v_filtered))
                return 0;

        uint64_t a_mtime, v_mtime;
        r = dispatch_mtime(stored->object, &a_mtime);
        if (r < 0)
                return r;

        r = dispatch_mtime(v, &v_mtime);
        if (r < 0)
                return r;

        if (v_mtime == NSEC_INFINITY ||
            (a_mtime != NSEC_INFINITY && a_mtime >= v_mtime))
                return 1; /* The stored definition is the newest, keep it */

        r = join_store_object(j, key, v, /* replace= */ true);
        if (r < 0)
                return r;

        return 1;
}

static int join_object_handler(Uapi16Object *o, size_t index, void *userdata) {
        JoinContext *j = ASSERT_PTR(userdata);
        int r;

        assert(o);
        assert(o->json);

        /* The leading object describing the top-level inode carries no name, use the empty string for it */
        const char *name = index == 0 ? "" : o->name;
        assert(name);

        /* Inode tokens are local to each manifest, hence compare everything but them */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = sd_json_variant_ref(o->json);
        r = sd_json_variant_filter(&v, STRV_MAKE("inodeToken"));
        if (r < 0)
                return log_error_errno(r, "Failed to remove inode token from object: %m");

        r = sd_json_variant_normalize(&v);
        if (r < 0)
                return log_error_errno(r, "Failed to normalize object: %m");

        _cleanup_free_ char *key = NULL;
        r = join_object_key(name, &key);
        if (r < 0)
                return r;

        _cleanup_(join_stored_object_done) JoinStoredObject stored = {};
        r = join_load_object(j, key, &stored);
        if (r < 0)
                return r;
        if (r == 0) {
                r = join_store_object(j, key, v, /* replace= */ false);
                if (r < 0)
                        return r;

                /* Create the directory for the object in the tree, along with its parents, as the inputs
                 * might list children before their parents, or not list the parents at all */
                if (!isempty(name)) {
                        r = mkdirat_p(j->tree_fd, name, 0700);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create directory '%s' in join database: %m", name);
                }

                j->n_objects++;
        } else if (!sd_json_variant_equal(stored.object, v)) {
                r = join_resolve_mtime(j, key, &stored, v);
                if (r < 0)
                        return r;
                if (r == 0) {
                        r = join_log_conflict(j, name, &stored, v);
                        if (r < 0)
                                return r;

                        j->n_conflicts++;
                }
        }

        if (!IN_SET(o->inode_token, 0, UINT64_MAX)) {
                r = join_record_token(j, key, o->inode_token);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int join_write_object(JoinContext *j, const char *name) {
        int r;

        assert(j);
        assert(name);

        /* Writes the object of the specified name to the output, with the inode token rewritten. Returns 0
         * if there's no such object, i.e. for parent directories that no input listed */

        _cleanup_free_ char *key = NULL;
        r = join_object_key(name, &key);
        if (r < 0)
                return r;

        _cleanup_(join_stored_object_done) JoinStoredObject stored = {};
        r = join_load_object(j, key, &stored);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("No object for '%s' in any input, skipping.", join_object_display_name(name));
                return 0;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(stored.object);

        uint64_t group;
        r = read_number_link(j->tokens_fd, key, &group);
        if (r < 0)
                return r;
        if (r > 0) {
                r = join_group_find(j, group, &group);
                if (r < 0)
                        return r;

                /* Assign the output tokens in order of first appearance, so that the result is the same as
                 * what "make" would generate for the joined tree */
                char k[DECIMAL_STR_MAX(uint64_t)];
                xsprintf(k, "%" PRIu64, group);

                uint64_t token;
                r = read_number_link(j->out_fd, k, &token);
                if (r < 0)
                        return r;
                if (r == 0) {
                        token = ++j->n_tokens;

                        r = write_number_link(j->out_fd, k, token);
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_set_field_unsigned(&v, "inodeToken", token);
                if (r < 0)
                        return log_error_errno(r, "Failed to set inode token of object: %m");
        }

        r = manifest_uapi16_write_object(j->manifest, v);
        if (r < 0)
                return r;

        return 1;
}

static int join_write_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        JoinContext *j = ASSERT_PTR(userdata);
        int r;

        /* The tree only contains directories, we created it ourselves, hence any failure to enumerate it is
         * fatal, as is any entry of a different type */

        if (event == RECURSE_DIR_SKIP_DEPTH)
                return log_error_errno(SYNTHETIC_ERRNO(ELOOP), "Maximum directory depth reached at '%s', refusing.", strna(path));
        if (event >= RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE && event <= RECURSE_DIR_SKIP_OPEN_DIR_ERROR_MAX)
                return log_error_errno(event - RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE, "Failed to open directory '%s' in join database: %m", strna(path));
        if (event == RECURSE_DIR_ENTRY)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected non-directory '%s' in join database, refusing.", strna(path));
        if (event != RECURSE_DIR_ENTER)
                return RECURSE_DIR_CONTINUE;

        r = join_write_object(j, path);
        if (r < 0)
                return r;

        return RECURSE_DIR_CONTINUE;
}

int manifest_join(ManifestContext *c, char * const *inputs) {
        int r;

        assert(c);
        assert(c->format == MANIFEST_FORMAT_UAPI16);
        assert(!strv_isempty(inputs));

        _cleanup_(join_context_done) JoinContext j = JOIN_CONTEXT_NULL;
        j.inputs = inputs;
        j.n_inputs = strv_length(inputs);
        j.manifest = c;

        r = join_context_setup(&j);
        if (r < 0)
                return r;

        for (j.current_input = 0; j.current_input < j.n_inputs; j.current_input++) {
                const char *p = inputs[j.current_input];

                _cleanup_fclose_ FILE *f = fopen(p, "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open manifest file '%s': %m", p);

                /* We do not verify signatures here: joining is not verifying, use "verify" for that */
                r = uapi16_manifest_read(
                                f,
                                /* certificates= */ NULL,
                                /* n_certificates= */ 0,
                                join_object_handler,
                                &j);
                if (r < 0)
                        return log_error_errno(r, "Failed to read manifest '%s': %m", p);
        }

        if (j.n_conflicts > 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "Found %" PRIu64 " conflicting objects, refusing to join manifests.",
                                       j.n_conflicts);

        r = manifest_uapi16_begin(c);
        if (r < 0)
                return r;

        /* The leading object first, then everything else in tree order */
        r = join_write_object(&j, "");
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "No input carries a leading object, refusing.");

        /* Note that we opened the directory while it was still empty, and some file systems (btrfs) only
         * return entries that existed when the directory was opened, until it is rewound, hence ask for
         * that. */
        r = recurse_dir(j.tree_fd,
                        /* path= */ NULL,
                        /* statx_mask= */ 0,
                        /* n_depth_max= */ UINT_MAX,
                        RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SEEK0,
                        join_write_item,
                        &j);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate join database: %m");

        r = manifest_uapi16_end(c);
        if (r < 0)
                return r;

        log_debug("Joined %zu manifests into one with %" PRIu64 " objects and %" PRIu64 " hardlink groups.",
                  j.n_inputs, j.n_objects, j.n_tokens);

        return 0;
}

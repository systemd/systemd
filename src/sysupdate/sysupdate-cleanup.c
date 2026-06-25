/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sha256.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate.h"
#include "sysupdate-cleanup.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"
#include "sysupdate-transfer.h"
#include "sysupdate-util.h"

/* This implements the "installdb", which is a simple database of directories + patterns that we ever
 * installed something into, i.e. for any resource we ever considered "owned" by a transfer file. This is
 * useful to automatically clean up "orphaned" files that used to be owned by a transfer file, but might no
 * longer be in newer versions of those transfer files, or where the transfer files/components got
 * removed/disabled altogether.
 *
 * This is ultimately just a per-component content-addressable database implemented via a special directory
 * in /var/lib/systemd/sysupdate/ that carries symlinks to store the data. Whenever we drop a file into the
 * system we create an entry in it. An entry symlink's filename is a SHA256 hash of the symlink's target. The
 * target encodes the directory of the transfer file used, suffixed by the pattern used by the transfer
 * file. If a transfer file lists multiple patterns, multiple entries are generated, one for each pattern.
 *
 * The on-disk layout hence looks roughly like this (for a component "foo" with a transfer file that has
 * Path=/var/lib/machines/ and two patterns "image_@v.raw" and "image_@v.efi"):
 *
 *     /var/lib/systemd/sysupdate/
 *     └── installdb.foo/
 *         ├── 8cbee6aa38b98811598118ebbc0eb4c1b7e479e7bfa4312c0b36edc765d1733b → /var/lib/machines/./image_@v.raw
 *         └── 042266dec8deae09c1e75f3d015734513b75a1daa38b4173c907b5345cf4ed41 → /var/lib/machines/./image_@v.efi
 *
 * (For the component-less case the directory is just called "installdb", without the ".foo" suffix.) The
 * symlink names are the SHA256 hashes (in hex) of their respective targets, and the "/./" separates the
 * directory part from the pattern part of the target.
 *
 * With this in place we have an always updated database of any file and pattern ever owned by any transfer
 * file we operated on. When doing a clean-up run, we now iterate through all installdb directories (i.e
 * every component ever installed), and all entries in them. We look for all files the entries match. We then
 * check if the current set of transfer files also owns these files. If yes, we keep both those files and the
 * installdb entry. If however no current transfer files own these files anymore, we first delete the files,
 * and then the installdb entry, since it no longer matches any files. */

static int context_installdb_acquire_fd(Context *c, bool make) {
        assert(c);

        if (c->installdb_fd >= 0)
                return 0;

        _cleanup_free_ char *j = NULL;
        const char *p;
        if (c->component) {
                j = strjoin("/var/lib/systemd/sysupdate/installdb.", c->component);
                if (!j)
                        return log_oom();

                p = j;
        } else
                p = "/var/lib/systemd/sysupdate/installdb";

        ChaseFlags flags = CHASE_MUST_BE_DIRECTORY|CHASE_PREFIX_ROOT;

        if (make)
                flags |= CHASE_MKDIR_0755;

        c->installdb_fd = chase_and_open(
                        p,
                        arg_root,
                        flags,
                        O_DIRECTORY|O_CLOEXEC|(make ? O_CREAT : 0),
                        /* ret_path= */ NULL);
        if (c->installdb_fd == -ENOENT && !make)
                return 0;
        if (c->installdb_fd < 0)
                return log_error_errno(c->installdb_fd, "Failed to open install database '%s%s': %m", empty_or_root(arg_root) ? "" : arg_root, p);

        return 1;
}

static int installdb_make_names(const char *path, const char *pattern, char **ret_key, char **ret_value) {
        assert(path);
        assert(pattern);

        /* We'll generate a string from the location and the pattern that looks a lot like a path, but
         * actually isn't, it's a path concatenated with a pattern. We separate both parts with /./. */
        _cleanup_free_ char *s = strjoin(path, "/./", pattern);
        if (!s)
                return log_oom();

        _cleanup_free_ char *h = sha256_direct_hex(s, SIZE_MAX);
        if (!h)
                return log_oom();

        if (ret_key)
                *ret_key = TAKE_PTR(h);

        if (ret_value)
                *ret_value = TAKE_PTR(s);

        return 0;
}

int context_installdb_record(
                Context *c,
                const char *path,
                char **patterns) {

        int r;

        assert(c);
        assert(path);

        /* Creates installdb entries for the specified pairs of directory and pattern. This is called
         * whenever we install a new file. */

        if (strv_isempty(patterns))
                return 0;

        /* The provided path comes with arg_root prefixed. Strip it here again */
        const char *p = arg_root ? ASSERT_PTR(path_startswith(path, arg_root)) : path;

        r = context_installdb_acquire_fd(c, /* make= */ true);
        if (r < 0)
                return r;

        int ret = 0;
        STRV_FOREACH(i, patterns) {
                _cleanup_free_ char *key = NULL, *value = NULL;
                r = installdb_make_names(p, *i, &key, &value);
                if (r < 0)
                        return r;

                r = symlinkat_idempotent(value, c->installdb_fd, key, /* make_relative= */ false);
                if (r < 0)
                        RET_GATHER(ret, log_warning_errno(r, "Failed to add '%s' in '%s' entry to install database: %m", *i, path));
        }

        return ret;
}

static int context_is_path_currently_owned(
                Context *c,
                const char *path,
                const char *relpath) {

        int r;

        assert(c);
        assert(path);
        assert(relpath);

        /* Checks if the there's a transfer file for the directoy 'path', and then if any of its patterns
         * match 'relpath' */

        FOREACH_ARRAY(_t, c->transfers, c->n_transfers) {
                Transfer *t = *_t;

                if (!RESOURCE_IS_FILESYSTEM(t->target.type))
                        continue;

                if (!path_equal(t->target.path, path))
                        continue;

                /* OK, so we found a transfer that covers this directory. Now let's see if any of its patterns match */

                r = pattern_match_many(t->target.patterns, relpath, /* ret= */ NULL);
                if (r < 0) {
                        _cleanup_free_ char *cl = strv_join(t->target.patterns, "', '");
                        if (!cl)
                                return log_oom();

                        return log_error_errno(r, "Failed to match patterns '%s' against '%s': %m", cl, relpath);
                }

                if (IN_SET(r, PATTERN_MATCH_YES, PATTERN_MATCH_RETRY)) /* Yay, this path is pinned by this transfer file */
                        return true;

                assert(r == PATTERN_MATCH_NO);
        }

        return false; /* We found nothing! The path seems to be unowned. */
}

static int context_installdb_process_directory(
                Context *c,
                const char *path,            /* The configured Path= in the original transfer file */
                const char *relpath,         /* For recursive path matches the path we encountered so far */
                int dir_fd,
                DirectoryEntries *de,
                const char *pattern) {

        int r;

        assert(c);
        assert(path);
        assert(dir_fd >= 0);
        assert(de);
        assert(pattern);

        int ret = 0;
        bool keep_installdb = false;
        FOREACH_ARRAY(_d, de->entries, de->n_entries) {
                const struct dirent *d = *_d;

                assert(IN_SET(d->d_type, DT_REG, DT_DIR)); /* caller must have filtered via readdir_all() RECURSE_DIR_MUST_BE_xyz flags already */

                _cleanup_free_ char *j = NULL;
                const char *p;
                if (relpath) {
                        j = path_join(relpath, d->d_name);
                        if (!j)
                                return log_oom();

                        p = j;
                } else
                        p = d->d_name;

                /* Let's see if this entry matches the pattern we recorded in the installdb? */
                r = pattern_match(pattern, p, /* ret= */ NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to match pattern '%s' against '%s', ignoring: %m", pattern, p);
                        /* Can't match, do not clean up */
                        continue;
                }
                if (r == PATTERN_MATCH_NO) /* No match, do not clean up */
                        continue;
                if (r == PATTERN_MATCH_RETRY) {
                        /* Might match in a subdirectory */

                        if (d->d_type != DT_DIR)
                                continue;

                        _cleanup_close_ int subdir_fd = RET_NERRNO(openat(dir_fd, d->d_name, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
                        if (subdir_fd == -ENOENT)
                                continue;
                        if (subdir_fd < 0) {
                                RET_GATHER(ret, log_warning_errno(subdir_fd, "Failed to open directory '%s', skipping: %m", p));
                                continue;
                        }

                        _cleanup_free_ DirectoryEntries *subde = NULL;
                        r = readdir_all(subdir_fd, RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_MUST_BE_DIRECTORY|RECURSE_DIR_MUST_BE_REGULAR, &subde);
                        if (r < 0) {
                                RET_GATHER(ret, log_error_errno(r, "Failed to enumerate resource path '%s': %m", p));
                                continue;
                        }

                        r = context_installdb_process_directory(c, path, p, subdir_fd, subde, pattern);
                        if (r < 0)
                                RET_GATHER(ret, r);
                        else
                                keep_installdb = keep_installdb || r;
                        continue;
                }

                assert(r == PATTERN_MATCH_YES);

                /* Ah, we have a match, this is a candidate for cleanup. Let's see if any of the currently defined transfer files want to own it */

                r = context_is_path_currently_owned(c, path, p);
                if (r < 0)
                        return r;
                if (r > 0) {
                        log_debug("Path '%s' is owned by current transfer files, keeping.", p);

                        keep_installdb = true; /* We are keeping the file, let's also keep the installdb entry for it hence */
                        continue;
                }

                /* OK, we found an orphaned inode that was owned by a previous invocation, but is no longer
                 * owned by any of the current transfer files. Delete it. */

                r = rm_rf_child(dir_fd, d->d_name, REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD);
                if (r < 0) {
                        if (r != -ENOENT)
                                RET_GATHER(ret, log_warning_errno(r, "Failed to remove '%s' which is no longer owned by any transfer files: %m", p));

                        continue;
                }

                log_info("Successfully removed '%s' which is no longer owned by any transfer files.", p);
        }

        /* Report back if there's a reason to keep the installdb entry for this directory */
        return ret < 0 ? ret : keep_installdb;
}

static int context_installdb_process_entry(
                Context *c,
                const char *key,
                const char *value) {

        int r;

        assert(c);
        assert(key);
        assert(value);

        _cleanup_free_ char *h = sha256_direct_hex(value, SIZE_MAX);
        if (!h)
                return log_oom();

        if (!streq(key, h)) {
                log_notice("Invalid hash of install database entry '%s' → '%s', expunging.", key, value);
                return 0;
        }

        const char *s = strstr(value, "/./");
        if (!s) {
                log_notice("Malformed install database entry '%s' → '%s', expunging.", key, value);
                return 0;
        }

        _cleanup_free_ char *path = strndup(value, s - value);
        if (!path)
                return log_oom();

        if (!path_is_absolute(path) || !path_is_normalized(path)) {
                log_notice("Install database path '%s' of entry '%s' → '%s' is invalid, expunging database entry.", path, key, value);
                return 0;
        }

        const char *pattern = s + 3;

        /* NB: We set CHASE_PROHIBIT_SYMLINKS because the path was normalized by the writer of the entry
         * already, and if it isn't anymore, then something is fishy. */
        _cleanup_close_ int dir_fd = chase_and_open(path, arg_root, CHASE_MUST_BE_DIRECTORY|CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, O_DIRECTORY|O_CLOEXEC, /* ret_path= */ NULL);
        if (dir_fd == -ENOENT) {
                log_debug("Install database path '%s' does not exist, expunging database entry.", path);
                return 0;
        }
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open resource path '%s': %m", path);

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dir_fd, RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_MUST_BE_DIRECTORY|RECURSE_DIR_MUST_BE_REGULAR, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate resource path '%s': %m", path);

        return context_installdb_process_directory(c, path, /* relpath= */ NULL, dir_fd, de, pattern);
}

int installdb_cleanup_component(const char *node, const char *component) {
        int r;

        _cleanup_(context_freep) Context* context = NULL;
        r = context_make_offline(
                        &context,
                        node,
                        component,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        r = context_installdb_acquire_fd(context, /* make= */ false);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("Not cleaning up component '%s', install database is empty.", strna(component));
                return 0;
        }

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(context->installdb_fd, RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_MUST_BE_SYMLINK, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate install database for component '%s': %m", strna(component));

        int ret = 0;
        FOREACH_ARRAY(_d, de->entries, de->n_entries) {
                const struct dirent *d = *_d;

                _cleanup_free_ char *v = NULL;
                r = readlinkat_malloc(context->installdb_fd, d->d_name, &v);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read symlink '%s', ignoring: %m", d->d_name);
                        continue;
                }

                r = context_installdb_process_entry(context, d->d_name, v);
                if (r < 0)  {
                        RET_GATHER(ret, r);
                        continue;
                }
                if (r > 0) /* Still good, keep installdb entry */
                        continue;

                r = RET_NERRNO(unlinkat(context->installdb_fd, d->d_name, /* flags= */ 0));
                if (r < 0 && r != -ENOENT)
                        RET_GATHER(ret, log_warning_errno(r, "Failed to remove install database entry '%s': %m", d->d_name));
        }

        return ret;
}

int installdb_list_components(char ***ret) {
        int r;

        assert(ret);

        _cleanup_close_ int dir_fd = chase_and_open(
                        "/var/lib/systemd/sysupdate",
                        arg_root,
                        CHASE_MUST_BE_DIRECTORY|CHASE_PREFIX_ROOT,
                        O_DIRECTORY|O_CLOEXEC,
                        /* ret_path= */ NULL);
        if (dir_fd == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open '/var/lib/systemd/sysupdate/': %m");

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dir_fd, RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_MUST_BE_DIRECTORY, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate installdb directory '/var/lib/systemd/sysupdate/': %m");

        _cleanup_strv_free_ char **l = NULL;
        FOREACH_ARRAY(_d, de->entries, de->n_entries) {
                const struct dirent *d = *_d;

                const char *e = startswith(d->d_name, "installdb.");
                if (!e)
                        continue;

                if (!component_name_valid(e))
                        continue;

                if (strv_extend(&l, e) < 0)
                        return log_oom();
        }

        strv_sort_uniq(l);
        *ret = TAKE_PTR(l);
        return 0;
}

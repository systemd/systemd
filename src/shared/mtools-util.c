/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "escape.h"
#include "install-file.h"
#include "log.h"
#include "mtools-util.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static int mtools_exec(char *const *argv, ForkFlags extra_fork_flags) {
        int r;

        assert(argv);
        assert(argv[0]);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = quote_command_line(argv, SHELL_ESCAPE_EMPTY);
                log_debug("Invoking mtools command: %s", strna(j));
        }

        _cleanup_free_ char *seconds = NULL, *source_date_epoch = NULL;
        r = source_date_epoch_seconds(&seconds);
        if (r < 0)
                return log_oom();
        if (seconds) {
                source_date_epoch = strjoin("SOURCE_DATE_EPOCH=", seconds);
                if (!source_date_epoch)
                        return log_oom();
        }

        r = pidref_safe_fork(
                        "(mtools)",
                        FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS|extra_fork_flags,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Avoid failures caused by mismatch in expectations between mkfs.vfat and mtools by
                 * disabling the stricter checks using MTOOLS_SKIP_CHECK. Force TZ=UTC and forward
                 * SOURCE_DATE_EPOCH so that mtools produces deterministic FAT timestamps. */
                execve(argv[0], argv,
                       STRV_MAKE("MTOOLS_SKIP_CHECK=1",
                                 "TZ=UTC",
                                 source_date_epoch));

                log_full_errno(FLAGS_SET(extra_fork_flags, FORK_LOG) ? LOG_ERR : LOG_DEBUG, errno, "Failed to execute %s: %m", argv[0]);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static int find_mtool(const char *name, char **ret) {
        int r;

        assert(name);
        assert(ret);

        r = find_executable(name, ret);
        if (r == -ENOENT)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Could not find %s binary.", name);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether %s binary exists: %m", name);

        return 0;
}

static int mmd_one(const char *mmd_bin, const char *node, const char *dest_rel) {
        int r;

        assert(mmd_bin);
        assert(node);
        assert(dest_rel);

        _cleanup_free_ char *dst = strjoin("::", dest_rel);
        if (!dst)
                return log_oom();

        /* Note: mmd accepts only -D and -i; there is no -Q quiet flag like mcopy has. */
        _cleanup_strv_free_ char **argv = strv_new(mmd_bin, "-Ds", "-DS", "-i", node, dst);
        if (!argv)
                return log_oom();

        /* If a directory already exists mmd will skip the entry (because we pass -Ds/-DS above), but it
         * ultimately still fails. That sucks, and there's no way we can turn this off. Let's ignore the
         * return value here (i.e. we do not pass FORK_LOG here, and eat up the error), under the assumption
         * that any serious failure is noticed later either way, once we populate the directory, and it
         * turns out to be missing. */
        r = mtools_exec(argv, /* extra_fork_flags= */ 0);
        if (r < 0)
                log_debug_errno(r, "mtools mmd operation failed, assuming because directory already existed, ignoring: %m");

        return 0;
}

static int mcopy_flush_files(
                const char *mcopy_bin,
                const char *node,
                const char *dest_rel,
                char ***file_batch) {

        assert(mcopy_bin);
        assert(node);
        assert(dest_rel);
        assert(file_batch);

        _cleanup_strv_free_ char **argv = NULL, **batch = TAKE_PTR(*file_batch);
        _cleanup_free_ char *dest = NULL;

        if (strv_isempty(batch))
                return 0;

        /* mcopy treats ::dir/ as the destination directory. The trailing slash makes it copy the
         * source files into it rather than renaming a single source to that path. */
        dest = strjoin("::", dest_rel, "/");
        if (!dest)
                return log_oom();

        argv = strv_new(mcopy_bin, "-p", "-Q", "-m", "-i", node);
        if (!argv)
                return log_oom();

        STRV_FOREACH(p, batch)
                if (strv_extend(&argv, *p) < 0)
                        return log_oom();

        if (strv_extend(&argv, dest) < 0)
                return log_oom();

        return mtools_exec(argv, FORK_LOG);
}

static int mcopy_recurse(
                const char *mcopy_bin,
                const char *mmd_bin,
                const char *node,
                const char *src_root,
                const char *dest_rel) {

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_strv_free_ char **file_batch = NULL;
        int r;

        assert(mcopy_bin);
        assert(mmd_bin);
        assert(node);
        assert(src_root);
        assert(dest_rel);

        /* Walk the source in deterministic (alphabetical) order so the FAT directory entries are
         * inserted in a host-independent sequence. We can't rely on `mcopy -s` to do this, as mtools
         * recurses via the platform's readdir() so the order is FS dependent. Instead we drive the
         * recursion here and issue per-item mmd/mcopy invocations interleaved per parent
         * directory, batching consecutive sibling files so the fork cost stays bounded. */
        r = readdir_all_at(AT_FDCWD, src_root, RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s' contents: %m", src_root);

        for (size_t i = 0; i < de->n_entries; i++) {
                struct dirent *ent = de->entries[i];
                _cleanup_free_ char *src = NULL;

                if (!IN_SET(ent->d_type, DT_REG, DT_DIR)) {
                        log_debug("%s/%s is not a file/directory which are the only file types supported by vfat, ignoring",
                                  src_root, ent->d_name);
                        continue;
                }

                src = path_join(src_root, ent->d_name);
                if (!src)
                        return log_oom();

                if (ent->d_type == DT_REG) {
                        if (strv_consume(&file_batch, TAKE_PTR(src)) < 0)
                                return log_oom();
                        continue;
                }

                /* Directory. Flush pending file siblings first so the parent FAT directory's entry
                 * order matches the sorted enumeration above, then create the subdir and recurse. */
                r = mcopy_flush_files(mcopy_bin, node, dest_rel, &file_batch);
                if (r < 0)
                        return r;

                _cleanup_free_ char *child_rel = strjoin(dest_rel, "/", ent->d_name);
                if (!child_rel)
                        return log_oom();

                r = mmd_one(mmd_bin, node, child_rel);
                if (r < 0)
                        return r;

                r = mcopy_recurse(mcopy_bin, mmd_bin, node, src, child_rel);
                if (r < 0)
                        return r;
        }

        return mcopy_flush_files(mcopy_bin, node, dest_rel, &file_batch);
}

int mtools_copy_tree(const char *node, const char *root) {
        _cleanup_free_ char *mcopy = NULL, *mmd = NULL;
        int r;

        assert(node);
        assert(root);

        /* Return early if there's nothing to copy. */
        if (dir_is_empty(root, /* ignore_hidden_or_backup= */ false))
                return 0;

        r = find_mtool("mcopy", &mcopy);
        if (r < 0)
                return r;

        r = find_mtool("mmd", &mmd);
        if (r < 0)
                return r;

        return mcopy_recurse(mcopy, mmd, node, root, "");
}

int mtools_mkdir(const char *node, const char *path) {
        _cleanup_free_ char *mmd = NULL;
        int r;

        assert(node);
        assert(path);

        r = find_mtool("mmd", &mmd);
        if (r < 0)
                return r;

        /* Create each component in turn, mmd does not do that for us */
        _cleanup_free_ char *current = NULL;
        for (const char *p = path;;) {
                const char *e;

                r = path_find_first_component(&p, /* accept_dot_dot= */ false, &e);
                if (r < 0)
                        return log_error_errno(r, "Invalid path '%s': %m", path);
                if (r == 0)
                        break;

                /* path_find_first_component() returns a pointer into 'path', not a NUL terminated copy */
                _cleanup_free_ char *component = strndup(e, r);
                if (!component)
                        return log_oom();

                if (!path_extend(&current, component))
                        return log_oom();

                r = mmd_one(mmd, node, current);
                if (r < 0)
                        return r;
        }

        return 0;
}

int mtools_copy_file(const char *node, const char *source, const char *dest) {
        _cleanup_free_ char *mcopy = NULL;
        int r;

        assert(node);
        assert(source);
        assert(dest);

        r = find_mtool("mcopy", &mcopy);
        if (r < 0)
                return r;

        _cleanup_free_ char *dst = strjoin("::", dest);
        if (!dst)
                return log_oom();

        /* -o overwrites an existing file of the same name without asking */
        _cleanup_strv_free_ char **argv = strv_new(mcopy, "-o", "-Q", "-m", "-i", node, source, dst);
        if (!argv)
                return log_oom();

        return mtools_exec(argv, FORK_LOG);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include "log.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

int mkfs_exists(const char *fstype) {
        const char *mkfs;
        int r;

        assert(fstype);

        if (STR_IN_SET(fstype, "auto", "swap")) /* these aren't real file system types, refuse early */
                return -EINVAL;

        mkfs = strjoina("mkfs.", fstype);
        if (!filename_is_valid(mkfs)) /* refuse file system types with slashes and similar */
                return -EINVAL;

        r = find_executable(mkfs, NULL);
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return r;

        return true;
}

int mkfs_supports_root_option(const char *fstype) {
        return fstype_is_ro(fstype) || STR_IN_SET(fstype, "ext2", "ext3", "ext4", "btrfs", "vfat", "xfs");
}

static int mangle_linux_fs_label(const char *s, size_t max_len, char **ret) {
        /* Not more than max_len bytes (12 or 16) */

        assert(s);
        assert(max_len > 0);
        assert(ret);

        const char *q;
        char *ans;

        for (q = s; *q;) {
                int l;

                l = utf8_encoded_valid_unichar(q, SIZE_MAX);
                if (l < 0)
                        return l;

                if ((size_t) (q - s + l) > max_len)
                        break;
                q += l;
        }

        ans = memdup_suffix0(s, q - s);
        if (!ans)
                return -ENOMEM;

        *ret = ans;
        return 0;
}

static int mangle_fat_label(const char *s, char **ret) {
        _cleanup_free_ char *q = NULL;
        int r;

        assert(s);
        assert(ret);

        r = utf8_to_ascii(s, '_', &q);
        if (r < 0)
                return r;

        /* Classic FAT only allows 11 character uppercase labels */
        strshorten(q, 11);
        ascii_strupper(q);

        /* mkfs.vfat: Labels with characters *?.,;:/\|+=<>[]" are not allowed.
         * Let's also replace any control chars. */
        for (char *p = q; *p; p++)
                if (strchr("*?.,;:/\\|+=<>[]\"", *p) || char_is_cc(*p))
                        *p = '_';

        *ret = TAKE_PTR(q);
        return 0;
}

static int mtools_exec(char *const *argv) {
        int r;

        assert(argv);
        assert(argv[0]);

        r = pidref_safe_fork(
                        "(mtools)",
                        FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
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
                                 strv_find_prefix(environ, "SOURCE_DATE_EPOCH=")));

                log_error_errno(errno, "Failed to execute %s: %m", argv[0]);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static int mcopy_flush_files(
                const char *mcopy_bin,
                const char *node,
                const char *dest_rel,
                char ***file_batch) {

        _cleanup_strv_free_ char **argv = NULL, **batch = TAKE_PTR(*file_batch);
        _cleanup_free_ char *dest = NULL;

        assert(mcopy_bin);
        assert(node);
        assert(dest_rel);
        assert(file_batch);

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

        return mtools_exec(argv);
}

static int do_mcopy_recurse(
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

                _cleanup_free_ char *dst = strjoin("::", dest_rel, "/", ent->d_name);
                if (!dst)
                        return log_oom();

                /* Note: mmd accepts only -D and -i; there is no -Q quiet flag like mcopy has. */
                _cleanup_strv_free_ char **argv = strv_new(mmd_bin, "-i", node, dst);
                if (!argv)
                        return log_oom();

                r = mtools_exec(argv);
                if (r < 0)
                        return r;

                _cleanup_free_ char *child_rel = strjoin(dest_rel, "/", ent->d_name);
                if (!child_rel)
                        return log_oom();

                r = do_mcopy_recurse(mcopy_bin, mmd_bin, node, src, child_rel);
                if (r < 0)
                        return r;
        }

        return mcopy_flush_files(mcopy_bin, node, dest_rel, &file_batch);
}

static int do_mcopy(const char *node, const char *root) {
        _cleanup_free_ char *mcopy = NULL, *mmd = NULL;
        int r;

        assert(node);
        assert(root);

        /* Return early if there's nothing to copy. */
        if (dir_is_empty(root, /* ignore_hidden_or_backup= */ false))
                return 0;

        r = find_executable("mcopy", &mcopy);
        if (r == -ENOENT)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Could not find mcopy binary.");
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether mcopy binary exists: %m");

        r = find_executable("mmd", &mmd);
        if (r == -ENOENT)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Could not find mmd binary.");
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether mmd binary exists: %m");

        return do_mcopy_recurse(mcopy, mmd, node, root, "");
}

int make_filesystem(
                const char *node,
                const char *fstype,
                const char *label,
                const char *root,
                sd_id128_t uuid,
                MakeFileSystemFlags flags,
                uint64_t sector_size,
                char *compression,
                char *compression_level,
                char * const *extra_mkfs_args) {

        _cleanup_free_ char *mkfs = NULL, *mangled_label = NULL;
        _cleanup_strv_free_ char **argv = NULL, **env = NULL;
        char vol_id[CONST_MAX(SD_ID128_UUID_STRING_MAX, 8U + 1U)] = {};
        int stdio_fds[3] = { -EBADF, STDERR_FILENO, STDERR_FILENO};
        ForkFlags fork_flags = FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|
                        FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO|FORK_REOPEN_LOG;
        int r;

        assert(node);
        assert(fstype);
        assert(label);

        if (fstype_is_ro(fstype) && !root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot generate read-only filesystem %s without a source tree.",
                                       fstype);

        if (streq(fstype, "swap")) {
                if (root)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "A swap filesystem can't be populated, refusing");
                r = find_executable("mkswap", &mkfs);
                if (r == -ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkswap binary not available.");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mkswap binary exists: %m");
        } else if (streq(fstype, "squashfs")) {
                r = find_executable("mksquashfs", &mkfs);
                if (r == -ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mksquashfs binary not available.");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mksquashfs binary exists: %m");

        } else if (streq(fstype, "erofs")) {
                r = find_executable("mkfs.erofs", &mkfs);
                if (r == -ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkfs.erofs binary not available.");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mkfs.erofs binary exists: %m");

        } else if (fstype_is_ro(fstype)) {
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Don't know how to create read-only file system '%s', refusing.",
                                                       fstype);
        } else {
                if (root && !mkfs_supports_root_option(fstype))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Populating with source tree is not supported for %s", fstype);
                r = mkfs_exists(fstype);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mkfs binary for %s exists: %m", fstype);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkfs binary for %s is not available.", fstype);

                mkfs = strjoin("mkfs.", fstype);
                if (!mkfs)
                        return log_oom();
        }

        if (STR_IN_SET(fstype, "ext2", "ext3", "ext4", "xfs", "swap")) {
                size_t max_len =
                        streq(fstype, "xfs") ? 12 :
                        streq(fstype, "swap") ? 15 :
                        16;

                r = mangle_linux_fs_label(label, max_len, &mangled_label);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine volume label from string \"%s\": %m", label);
                label = mangled_label;

        } else if (streq(fstype, "vfat")) {
                r = mangle_fat_label(label, &mangled_label);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine FAT label from string \"%s\": %m", label);
                label = mangled_label;

                xsprintf(vol_id, "%08" PRIx32,
                         ((uint32_t) uuid.bytes[0] << 24) |
                         ((uint32_t) uuid.bytes[1] << 16) |
                         ((uint32_t) uuid.bytes[2] << 8) |
                         ((uint32_t) uuid.bytes[3])); /* Take first 32 bytes of UUID */
        }

        if (isempty(vol_id))
                assert_se(sd_id128_to_uuid_string(uuid, vol_id));

        /* When changing this conditional, also adjust the log statement below. */
        if (STR_IN_SET(fstype, "ext2", "ext3", "ext4")) {
                const char *ext_e_opts;

                /* Set hash_seed to the same value as the filesystem UUID for reproducibility */
                ext_e_opts = strjoina(FLAGS_SET(flags, MKFS_DISCARD) ? "discard" : "nodiscard",
                                      ",lazy_itable_init=1,hash_seed=",
                                      vol_id);

                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                "-I", "256",
                                "-m", "0",
                                "-E", ext_e_opts,
                                "-b", "4096",
                                "-T", "default");
                if (!argv)
                        return log_oom();

                if (root && strv_extend_many(&argv, "-d", root) < 0)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_QUIET) && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_FS_VERITY) && strv_extend_many(&argv, "-O", "verity") < 0)
                        return log_oom();

                if (strv_extend(&argv, node) < 0)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&env, "MKE2FS_DEVICE_SECTSIZE") < 0)
                                return log_oom();

                        if (strv_extendf(&env, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                /* e2fsprogs supports $SOURCE_DATE_EPOCH since v1.47.1. For older versions, we need to set
                 * $E2FSPROGS_FAKE_TIME. See the following:
                 * https://github.com/tytso/e2fsprogs/commit/b6e2913061577ad981464e435026d71a48fd5caf
                 * Note, $E2FSPROGS_FAKE_TIME and $SOURCE_DATE_EPOCH are mostly equivalent, except for the
                 * 0 value handling, where $E2FSPROGS_FAKE_TIME=0 is ignored and the current time is used,
                 * but $SOURCE_DATE_EPOCH=0 sets 1970-01-01 as the timestamp. */
                if (!secure_getenv("E2FSPROGS_FAKE_TIME")) { /* honor $E2FSPROGS_FAKE_TIME if already set */
                        const char *e = secure_getenv("SOURCE_DATE_EPOCH");
                        if (e && strv_extend_strv(&env, STRV_MAKE("E2FSPROGS_FAKE_TIME", e), /* filter_duplicates= */ false) < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "btrfs")) {
                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id);
                if (!argv)
                        return log_oom();

                if (!FLAGS_SET(flags, MKFS_DISCARD) && strv_extend(&argv, "--nodiscard") < 0)
                        return log_oom();

                if (root && strv_extend_many(&argv, "-r", root) < 0)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_QUIET) && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (compression) {
                        if (!root)
                                log_warning("Btrfs compression setting ignored because no files are being copied. "
                                            "Compression= can only be applied when CopyFiles= is also specified.");
                        else {
                                _cleanup_free_ char *c = NULL;

                                c = strdup(compression);
                                if (!c)
                                        return log_oom();

                                if (compression_level && !strextend(&c, ":", compression_level))
                                        return log_oom();

                                if (strv_extend_many(&argv, "--compress", c) < 0)
                                        return log_oom();
                        }
                }

                /* mkfs.btrfs unconditionally warns about several settings changing from v5.15 onwards which
                 * isn't silenced by "-q", so let's redirect stdout to /dev/null as well. */
                if (FLAGS_SET(flags, MKFS_QUIET))
                        stdio_fds[1] = -EBADF;

                /* mkfs.btrfs expects a sector size of at least 4k bytes. */
                if (sector_size > 0 && strv_extendf(&argv, "--sectorsize=%"PRIu64, MAX(sector_size, 4 * U64_KB)) < 0)
                        return log_oom();

                if (strv_extend(&argv, node) < 0)
                        return log_oom();

        } else if (streq(fstype, "f2fs")) {
                argv = strv_new(mkfs,
                                "-g",  /* "default options" */
                                "-f",  /* force override, without this it doesn't seem to want to write to an empty partition */
                                "-l", label,
                                "-U", vol_id,
                                "-t", one_zero(FLAGS_SET(flags, MKFS_DISCARD)));
                if (!argv)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_QUIET) && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_FS_VERITY) && strv_extend_many(&argv, "-O", "verity") < 0)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-w") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                if (strv_extend(&argv, node) < 0)
                        return log_oom();

        } else if (streq(fstype, "xfs")) {
                const char *j;

                j = strjoina("uuid=", vol_id);

                argv = strv_new(mkfs,
                                "-L", label,
                                "-m", j,
                                "-m", "reflink=1");
                if (!argv)
                        return log_oom();

                if (!FLAGS_SET(flags, MKFS_DISCARD) && strv_extend(&argv, "-K") < 0)
                        return log_oom();

                if (root && strv_extend_many(&argv, "-p", root) < 0)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-s") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "size=%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                if (FLAGS_SET(flags, MKFS_QUIET) && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (strv_extend(&argv, node) < 0)
                        return log_oom();

        } else if (streq(fstype, "vfat")) {

                argv = strv_new(mkfs,
                                "-i", vol_id,
                                "-n", label,
                                "-F", "32");  /* yes, we force FAT32 here */
                if (!argv)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-S") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                if (strv_extend(&argv, node) < 0)
                        return log_oom();

                /* mkfs.vfat does not have a --quiet option so let's redirect stdout to /dev/null instead. */
                if (FLAGS_SET(flags, MKFS_QUIET))
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "swap")) {
                /* TODO: add --quiet once util-linux v2.38 is available everywhere. */

                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                node);
                if (!argv)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_QUIET))
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "squashfs")) {

                argv = strv_new(mkfs,
                                root, node, /* mksquashfs expects its arguments before the options. */
                                "-noappend");
                if (!argv)
                        return log_oom();

                if (compression) {
                        if (strv_extend_many(&argv, "-comp", compression) < 0)
                                return log_oom();

                        if (compression_level && strv_extend_many(&argv, "-Xcompression-level", compression_level) < 0)
                                return log_oom();
                }

                /* mksquashfs -quiet option is pretty new so let's redirect stdout to /dev/null instead. */
                if (FLAGS_SET(flags, MKFS_QUIET))
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "erofs")) {
                argv = strv_new(mkfs,
                                "-U", vol_id);
                if (!argv)
                        return log_oom();

                if (FLAGS_SET(flags, MKFS_QUIET) && strv_extend(&argv, "--quiet") < 0)
                        return log_oom();

                if (compression) {
                        _cleanup_free_ char *c = NULL;

                        c = strjoin("-z", compression);
                        if (!c)
                                return log_oom();

                        if (compression_level && !strextend(&c, ",level=", compression_level))
                                return log_oom();

                        if (strv_extend(&argv, c) < 0)
                                return log_oom();
                }

                if (strv_extend_many(&argv, node, root) < 0)
                        return log_oom();

        } else {
                /* Generic fallback for all other file systems */
                argv = strv_new(mkfs, node);
                if (!argv)
                        return log_oom();
        }

        if (extra_mkfs_args && strv_extend_strv(&argv, extra_mkfs_args, false) < 0)
                return log_oom();

        if (streq(fstype, "btrfs")) {
                struct stat st;

                if (stat(node, &st) < 0)
                        return log_error_errno(r, "Failed to stat '%s': %m", node);

                if (S_ISBLK(st.st_mode))
                        fork_flags |= FORK_NEW_MOUNTNS;
        }

        log_info("Formatting %s as %s", node, fstype);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = NULL;

                j = strv_join(argv, " ");
                log_debug("Executing mkfs command: %s", strna(j));
        }

        r = pidref_safe_fork_full(
                        "(mkfs)",
                        stdio_fds,
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        fork_flags,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                STRV_FOREACH_PAIR(k, v, env)
                        if (setenv(*k, *v, /* replace= */ true) < 0) {
                                log_error_errno(r, "Failed to set %s=%s environment variable: %m", *k, *v);
                                _exit(EXIT_FAILURE);
                        }

                /* mkfs.btrfs refuses to operate on block devices with mounted partitions, even if operating
                 * on unformatted free space, so let's trick it and other mkfs tools into thinking no
                 * partitions are mounted. See https://github.com/kdave/btrfs-progs/issues/640 for more
                 ° information. */
                 if (fork_flags & FORK_NEW_MOUNTNS)
                        (void) mount_nofollow_verbose(LOG_DEBUG, "/dev/null", "/proc/self/mounts", NULL, MS_BIND, NULL);

                execvp(mkfs, argv);

                log_error_errno(errno, "Failed to execute %s: %m", mkfs);

                _exit(EXIT_FAILURE);
        }

        if (root && streq(fstype, "vfat")) {
                r = do_mcopy(node, root);
                if (r < 0)
                        return r;
        }

        if (STR_IN_SET(fstype, "ext2", "ext3", "ext4", "btrfs", "f2fs", "xfs", "vfat", "swap"))
                log_info("%s successfully formatted as %s (label \"%s\", uuid %s)",
                         node, fstype, label, vol_id);
        else if (streq(fstype, "erofs"))
                log_info("%s successfully formatted as %s (uuid %s, no label)",
                         node, fstype, vol_id);
        else
                log_info("%s successfully formatted as %s (no label or uuid specified)",
                         node, fstype);

        return 0;
}

int mkfs_options_from_env(const char *component, const char *fstype, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        const char *e;
        char *n;

        assert(component);
        assert(fstype);
        assert(ret);

        n = strjoina("SYSTEMD_", component, "_MKFS_OPTIONS_", fstype);
        e = getenv(ascii_strupper(n));
        if (e) {
                l = strv_split(e, NULL);
                if (!l)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

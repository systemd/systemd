/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <unistd.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "id128-util.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
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
        assert(s);

        _cleanup_free_ char *q = NULL;
        int r;

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

static int do_mcopy(const char *node, const char *root) {
        _cleanup_free_ char *mcopy = NULL;
        _cleanup_strv_free_ char **argv = NULL;
        _cleanup_free_ DirectoryEntries *de = NULL;
        int r;

        assert(node);
        assert(root);

        /* Return early if there's nothing to copy. */
        if (dir_is_empty(root, /*ignore_hidden_or_backup=*/ false))
                return 0;

        r = find_executable("mcopy", &mcopy);
        if (r == -ENOENT)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Could not find mcopy binary.");
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether mcopy binary exists: %m");

        argv = strv_new(mcopy, "-s", "-p", "-Q", "-m", "-i", node);
        if (!argv)
                return log_oom();

        /* mcopy copies the top level directory instead of everything in it so we have to pass all
         * the subdirectories to mcopy instead to end up with the correct directory structure. */

        r = readdir_all_at(AT_FDCWD, root, RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s' contents: %m", root);

        for (size_t i = 0; i < de->n_entries; i++) {
                _cleanup_free_ char *p = NULL;

                p = path_join(root, de->entries[i]->d_name);
                if (!p)
                        return log_oom();

                if (!IN_SET(de->entries[i]->d_type, DT_REG, DT_DIR)) {
                        log_debug("%s is not a file/directory which are the only file types supported by vfat, ignoring", p);
                        continue;
                }

                if (strv_consume(&argv, TAKE_PTR(p)) < 0)
                        return log_oom();
        }

        if (strv_extend(&argv, "::") < 0)
                return log_oom();

        r = safe_fork("(mcopy)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Avoid failures caused by mismatch in expectations between mkfs.vfat and mcopy by disabling
                 * the stricter mcopy checks using MTOOLS_SKIP_CHECK. */
                execve(mcopy, argv, STRV_MAKE("MTOOLS_SKIP_CHECK=1", "TZ=UTC", strv_find_prefix(environ, "SOURCE_DATE_EPOCH=")));

                log_error_errno(errno, "Failed to execute mcopy: %m");

                _exit(EXIT_FAILURE);
        }

        return 0;
}

typedef struct ProtofileData {
        FILE *file;
        bool has_filename_with_spaces;
        const char *tmpdir;
} ProtofileData;

static int protofile_print_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ProtofileData *data = ASSERT_PTR(userdata);
        _cleanup_free_ char *copy = NULL;
        int r;

        if (event == RECURSE_DIR_LEAVE) {
                fputs("$\n", data->file);
                return 0;
        }

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        char type = S_ISDIR(sx->stx_mode)  ? 'd' :
                    S_ISREG(sx->stx_mode)  ? '-' :
                    S_ISLNK(sx->stx_mode)  ? 'l' :
                    S_ISFIFO(sx->stx_mode) ? 'p' :
                    S_ISBLK(sx->stx_mode)  ? 'b' :
                    S_ISCHR(sx->stx_mode)  ? 'c' : 0;
        if (type == 0)
                return RECURSE_DIR_CONTINUE;

        /* The protofile format does not support spaces in filenames as whitespace is used as a token
         * delimiter. To work around this limitation, mkfs.xfs allows escaping whitespace by using the /
         * character (which isn't allowed in filenames and as such can be used to escape whitespace). See
         * https://lore.kernel.org/linux-xfs/20230222090303.h6tujm7y32gjhgal@andromeda/T/#m8066b3e7d62a080ee7434faac4861d944e64493b
         * for more information.*/

        if (strchr(de->d_name, ' ')) {
                copy = strdup(de->d_name);
                if (!copy)
                        return log_oom();

                string_replace_char(copy, ' ', '/');
                data->has_filename_with_spaces = true;
        }

        fprintf(data->file, "%s %c%c%c%03o "UID_FMT" "GID_FMT" ",
                copy ?: de->d_name,
                type,
                sx->stx_mode & S_ISUID ? 'u' : '-',
                sx->stx_mode & S_ISGID ? 'g' : '-',
                (unsigned) (sx->stx_mode & 0777),
                sx->stx_uid, sx->stx_gid);

        if (S_ISREG(sx->stx_mode)) {
                _cleanup_free_ char *p = NULL;

                /* While we can escape whitespace in the filename, we cannot escape whitespace in the source
                 * path, so hack around that by creating a symlink to the path in a temporary directory and
                 * using the symlink as the source path instead. */

                if (strchr(path, ' ')) {
                        r = tempfn_random_child(data->tmpdir, "mkfs-xfs", &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate random child name in %s: %m", data->tmpdir);

                        if (symlink(path, p) < 0)
                                return log_error_errno(errno, "Failed to symlink %s to %s: %m", p, path);
                }

                fputs(p ?: path, data->file);
        } else if (S_ISLNK(sx->stx_mode)) {
                _cleanup_free_ char *p = NULL;

                r = readlinkat_malloc(dir_fd, de->d_name, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to read symlink %s: %m", path);

                /* If we have a symlink to a path with whitespace in it, we're out of luck, as there's no way
                 * to encode that in the mkfs.xfs protofile format. */

                if (strchr(p, ' '))
                        return log_error_errno(r, "Symlinks to paths containing whitespace are not supported by mkfs.xfs: %m");

                fputs(p, data->file);
        } else if (S_ISBLK(sx->stx_mode) || S_ISCHR(sx->stx_mode))
                fprintf(data->file, "%" PRIu32 " %" PRIu32, sx->stx_rdev_major, sx->stx_rdev_minor);

        fputc('\n', data->file);

        return RECURSE_DIR_CONTINUE;
}

static int make_protofile(const char *root, char **ret_path, bool *ret_has_filename_with_spaces, char **ret_tmpdir) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_and_freep) char *p = NULL;
        struct ProtofileData data = {};
        const char *vt;
        int r;

        assert(ret_path);
        assert(ret_has_filename_with_spaces);
        assert(ret_tmpdir);

        r = var_tmp_dir(&vt);
        if (r < 0)
                return log_error_errno(r, "Failed to get persistent temporary directory: %m");

        r = fopen_temporary_child(vt, &f, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file: %m");

        /* Explicitly use /tmp here because this directory cannot have spaces its path. */
        r = mkdtemp_malloc("/tmp/systemd-mkfs-XXXXXX", &tmpdir);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary directory: %m");

        data.file = f;
        data.tmpdir = tmpdir;

        fputs("/\n"
              "0 0\n"
              "d--755 0 0\n", f);

        r = recurse_dir_at(AT_FDCWD, root, STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID, UINT_MAX,
                           RECURSE_DIR_SORT, protofile_print_item, &data);
        if (r < 0)
                return log_error_errno(r, "Failed to recurse through %s: %m", root);

        fputs("$\n", f);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", p);

        *ret_path = TAKE_PTR(p);
        *ret_has_filename_with_spaces = data.has_filename_with_spaces;
        *ret_tmpdir = TAKE_PTR(tmpdir);

        return 0;
}

int make_filesystem(
                const char *node,
                const char *fstype,
                const char *label,
                const char *root,
                sd_id128_t uuid,
                bool discard,
                bool quiet,
                uint64_t sector_size,
                char * const *extra_mkfs_args) {

        _cleanup_free_ char *mkfs = NULL, *mangled_label = NULL;
        _cleanup_strv_free_ char **argv = NULL, **env = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *protofile_tmpdir = NULL;
        _cleanup_(unlink_and_freep) char *protofile = NULL;
        char vol_id[CONST_MAX(SD_ID128_UUID_STRING_MAX, 8U + 1U)] = {};
        int stdio_fds[3] = { -EBADF, STDERR_FILENO, STDERR_FILENO};
        ForkFlags flags = FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|
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
                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                "-I", "256",
                                "-m", "0",
                                "-E", discard ? "discard,lazy_itable_init=1" : "nodiscard,lazy_itable_init=1",
                                "-b", "4096",
                                "-T", "default",
                                node);

                if (root && strv_extend_strv(&argv, STRV_MAKE("-d", root), false) < 0)
                        return log_oom();

                if (quiet && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&env, "MKE2FS_DEVICE_SECTSIZE") < 0)
                                        return log_oom();

                        if (strv_extendf(&env, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "btrfs")) {
                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                node);
                if (!argv)
                        return log_oom();

                if (!discard && strv_extend(&argv, "--nodiscard") < 0)
                        return log_oom();

                if (root && strv_extend_strv(&argv, STRV_MAKE("-r", root), false) < 0)
                        return log_oom();

                if (quiet && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                /* mkfs.btrfs unconditionally warns about several settings changing from v5.15 onwards which
                 * isn't silenced by "-q", so let's redirect stdout to /dev/null as well. */
                if (quiet)
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "f2fs")) {
                argv = strv_new(mkfs,
                                "-g",  /* "default options" */
                                "-f",  /* force override, without this it doesn't seem to want to write to an empty partition */
                                "-l", label,
                                "-U", vol_id,
                                "-t", one_zero(discard),
                                node);

                if (quiet && strv_extend(&argv, "-q") < 0)
                        return log_oom();

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-w") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "xfs")) {
                const char *j;

                j = strjoina("uuid=", vol_id);

                argv = strv_new(mkfs,
                                "-L", label,
                                "-m", j,
                                "-m", "reflink=1",
                                node);
                if (!argv)
                        return log_oom();

                if (!discard && strv_extend(&argv, "-K") < 0)
                        return log_oom();

                if (root) {
                        bool has_filename_with_spaces = false;
                        _cleanup_free_ char *protofile_with_opt = NULL;

                        r = make_protofile(root, &protofile, &has_filename_with_spaces, &protofile_tmpdir);
                        if (r < 0)
                                return r;

                        /* Gross hack to make mkfs.xfs interpret slashes as spaces so we can encode filenames
                         * with spaces in the protofile format. */
                        if (has_filename_with_spaces)
                                protofile_with_opt = strjoin("slashes_are_spaces=1,", protofile);
                        else
                                protofile_with_opt = strdup(protofile);
                        if (!protofile_with_opt)
                                return -ENOMEM;

                        if (strv_extend_strv(&argv, STRV_MAKE("-p", protofile_with_opt), false) < 0)
                                return log_oom();
                }

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-s") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "size=%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                if (quiet && strv_extend(&argv, "-q") < 0)
                        return log_oom();

        } else if (streq(fstype, "vfat")) {

                argv = strv_new(mkfs,
                                "-i", vol_id,
                                "-n", label,
                                "-F", "32",  /* yes, we force FAT32 here */
                                node);

                if (sector_size > 0) {
                        if (strv_extend(&argv, "-S") < 0)
                                return log_oom();

                        if (strv_extendf(&argv, "%"PRIu64, sector_size) < 0)
                                return log_oom();
                }

                /* mkfs.vfat does not have a --quiet option so let's redirect stdout to /dev/null instead. */
                if (quiet)
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "swap")) {
                /* TODO: add --quiet once util-linux v2.38 is available everywhere. */

                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                node);

                if (quiet)
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "squashfs")) {

                argv = strv_new(mkfs,
                                root, node,
                                "-noappend");

                /* mksquashfs -quiet option is pretty new so let's redirect stdout to /dev/null instead. */
                if (quiet)
                        stdio_fds[1] = -EBADF;

        } else if (streq(fstype, "erofs")) {

                argv = strv_new(mkfs,
                                "-U", vol_id,
                                node, root);

                if (quiet && strv_extend(&argv, "--quiet") < 0)
                        return log_oom();

        } else
                /* Generic fallback for all other file systems */
                argv = strv_new(mkfs, node);

        if (!argv)
                return log_oom();

        if (extra_mkfs_args && strv_extend_strv(&argv, extra_mkfs_args, false) < 0)
                return log_oom();

        if (streq(fstype, "btrfs")) {
                struct stat st;

                if (stat(node, &st) < 0)
                        return log_error_errno(r, "Failed to stat '%s': %m", node);

                if (S_ISBLK(st.st_mode))
                        flags |= FORK_NEW_MOUNTNS;
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = NULL;

                j = strv_join(argv, " ");
                log_debug("Executing mkfs command: %s", strna(j));
        }

        r = safe_fork_full(
                        "(mkfs)",
                        stdio_fds,
                        /*except_fds=*/ NULL,
                        /*n_except_fds=*/ 0,
                        flags,
                        /*ret_pid=*/ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                STRV_FOREACH_PAIR(k, v, env)
                        if (setenv(*k, *v, /* replace = */ true) < 0) {
                                log_error_errno(r, "Failed to set %s=%s environment variable: %m", *k, *v);
                                _exit(EXIT_FAILURE);
                        }

                /* mkfs.btrfs refuses to operate on block devices with mounted partitions, even if operating
                 * on unformatted free space, so let's trick it and other mkfs tools into thinking no
                 * partitions are mounted. See https://github.com/kdave/btrfs-progs/issues/640 for more
                 ° information. */
                 if (flags & FORK_NEW_MOUNTNS)
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

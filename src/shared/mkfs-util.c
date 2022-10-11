/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "mkfs-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
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
        return fstype_is_ro(fstype) || STR_IN_SET(fstype, "ext2", "ext3", "ext4", "btrfs", "vfat");
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

static int setup_userns(uid_t uid, gid_t gid) {
        int r;

       /* mkfs programs tend to keep ownership intact when bootstrapping themselves from a root directory.
        * However, we'd like for the files to be owned by root instead, so we fork off a user namespace and
        * inside of it, map the uid/gid of the root directory to root in the user namespace. mkfs programs
        * will pick up on this and the files will be owned by root in the generated filesystem. */

        r = write_string_filef("/proc/self/uid_map", WRITE_STRING_FILE_DISABLE_BUFFER,
                                UID_FMT " " UID_FMT " " UID_FMT, 0u, uid, 1u);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to write mapping for "UID_FMT" to /proc/self/uid_map: %m",
                                       uid);

        r = write_string_file("/proc/self/setgroups", "deny", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write 'deny' to /proc/self/setgroups: %m");

        r = write_string_filef("/proc/self/gid_map", WRITE_STRING_FILE_DISABLE_BUFFER,
                                UID_FMT " " UID_FMT " " UID_FMT, 0u, gid, 1u);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to write mapping for "UID_FMT" to /proc/self/gid_map: %m",
                                       gid);

        return 0;
}

int make_filesystem(
                const char *node,
                const char *fstype,
                const char *label,
                const char *root,
                sd_id128_t uuid,
                bool discard) {

        _cleanup_free_ char *mkfs = NULL, *mangled_label = NULL;
        _cleanup_strv_free_ char **argv = NULL;
        char vol_id[CONST_MAX(SD_ID128_UUID_STRING_MAX, 8U + 1U)] = {};
        struct stat st;
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
        if (streq(fstype, "ext2")) {
                argv = strv_new(mkfs,
                                "-q",
                                "-L", label,
                                "-U", vol_id,
                                "-I", "256",
                                "-m", "0",
                                "-E", discard ? "discard,lazy_itable_init=1" : "nodiscard,lazy_itable_init=1",
                                node);
                if (!argv)
                        return log_oom();

                if (root) {
                        r = strv_extend_strv(&argv, STRV_MAKE("-d", root), false);
                        if (r < 0)
                                return log_oom();
                }

        } else if (STR_IN_SET(fstype, "ext3", "ext4")) {
                argv = strv_new(mkfs,
                                "-q",
                                "-L", label,
                                "-U", vol_id,
                                "-I", "256",
                                "-O", "has_journal",
                                "-m", "0",
                                "-E", discard ? "discard,lazy_itable_init=1" : "nodiscard,lazy_itable_init=1",
                                node);

                if (root) {
                        r = strv_extend_strv(&argv, STRV_MAKE("-d", root), false);
                        if (r < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "btrfs")) {
                argv = strv_new(mkfs,
                                "-q",
                                "-L", label,
                                "-U", vol_id,
                                node);
                if (!argv)
                        return log_oom();

                if (!discard) {
                        r = strv_extend(&argv, "--nodiscard");
                        if (r < 0)
                                return log_oom();
                }

                if (root) {
                        r = strv_extend_strv(&argv, STRV_MAKE("-r", root), false);
                        if (r < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "f2fs")) {
                argv = strv_new(mkfs,
                                "-q",
                                "-g",  /* "default options" */
                                "-f",  /* force override, without this it doesn't seem to want to write to an empty partition */
                                "-l", label,
                                "-U", vol_id,
                                "-t", one_zero(discard),
                                node);

        } else if (streq(fstype, "xfs")) {
                const char *j;

                j = strjoina("uuid=", vol_id);

                argv = strv_new(mkfs,
                                "-q",
                                "-L", label,
                                "-m", j,
                                "-m", "reflink=1",
                                node);
                if (!argv)
                        return log_oom();

                if (!discard) {
                        r = strv_extend(&argv, "-K");
                        if (r < 0)
                                return log_oom();
                }

        } else if (streq(fstype, "vfat"))

                argv = strv_new(mkfs,
                                "-i", vol_id,
                                "-n", label,
                                "-F", "32",  /* yes, we force FAT32 here */
                                node);

        else if (streq(fstype, "swap"))
                /* TODO: add --quiet here if
                 * https://github.com/util-linux/util-linux/issues/1499 resolved. */

                argv = strv_new(mkfs,
                                "-L", label,
                                "-U", vol_id,
                                node);

        else if (streq(fstype, "squashfs"))

                argv = strv_new(mkfs,
                                root, node,
                                "-quiet",
                                "-noappend");
        else
                /* Generic fallback for all other file systems */
                argv = strv_new(mkfs, node);

        if (!argv)
                return log_oom();

        if (root && stat(root, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", root);

        r = safe_fork("(mkfs)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|(root ? FORK_NEW_USERNS : 0), NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                if (root) {
                        r = setup_userns(st.st_uid, st.st_gid);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                execvp(mkfs, argv);

                log_error_errno(errno, "Failed to execute %s: %m", mkfs);

                _exit(EXIT_FAILURE);
        }

        if (root && streq(fstype, "vfat")) {
                _cleanup_closedir_ DIR *rootdir = NULL;

                strv_free(argv);

                argv = strv_new("mcopy", "-b", "-s", "-p", "-Q", "-n", "-m", "-i", node);
                if (!argv)
                        return log_oom();

                /* mcopy copies the top level directory instead of everything in it so we have to pass all
                 * the subdirectories to mcopy instead to end up with the correct directory structure. */

                rootdir = opendir(root);
                if (!rootdir)
                        return log_error_errno(errno, "Failed to open directory '%s'", root);

                FOREACH_DIRENT(de, rootdir, return -errno) {
                        char *p = path_join(root, de->d_name);
                        if (!p)
                                return log_oom();

                        r = strv_consume(&argv, TAKE_PTR(p));
                        if (r < 0)
                                return log_oom();
                }

                r = strv_extend(&argv, "::");
                if (r < 0)
                        return log_oom();

                r = safe_fork("(mcopy)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_NEW_USERNS, NULL);
                if (r < 0)
                        return r;
                if (r == 0) {
                        r = setup_userns(st.st_uid, st.st_gid);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        execvp("mcopy", argv);

                        log_error_errno(errno, "Failed to execute mcopy: %m");

                        _exit(EXIT_FAILURE);
                }
        }

        if (STR_IN_SET(fstype, "ext2", "ext3", "ext4", "btrfs", "f2fs", "xfs", "vfat", "swap"))
                log_info("%s successfully formatted as %s (label \"%s\", uuid %s)",
                         node, fstype, label, vol_id);
        else
                log_info("%s successfully formatted as %s (no label or uuid specified)",
                         node, fstype);

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "id128-util.h"
#include "mkfs-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"

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

int make_filesystem(
                const char *node,
                const char *fstype,
                const char *label,
                sd_id128_t uuid,
                bool discard) {

        _cleanup_free_ char *mkfs = NULL;
        char mangled_label[8 + 3 + 1],
             vol_id[CONST_MAX(ID128_UUID_STRING_MAX, 8 + 1)] = {};
        int r;

        assert(node);
        assert(fstype);
        assert(label);

        if (streq(fstype, "swap")) {
                r = find_executable("mkswap", &mkfs);
                if (r == -ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkswap binary not available.");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mkswap binary exists: %m");
        } else {
                r = mkfs_exists(fstype);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether mkfs binary for %s exists: %m", fstype);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkfs binary for %s is not available.", fstype);

                mkfs = strjoin("mkfs.", fstype);
                if (!mkfs)
                        return log_oom();
        }

        if (streq(fstype, "vfat")) {
                /* Classic FAT only allows 11 character uppercase labels */
                strncpy(mangled_label, label, sizeof(mangled_label)-1);
                mangled_label[sizeof(mangled_label)-1] = 0;
                ascii_strupper(mangled_label);
                label = mangled_label;

                xsprintf(vol_id, "%08" PRIx32,
                         ((uint32_t) uuid.bytes[0] << 24) |
                         ((uint32_t) uuid.bytes[1] << 16) |
                         ((uint32_t) uuid.bytes[2] << 8) |
                         ((uint32_t) uuid.bytes[3])); /* Take first 32 bytes of UUID */
        }

        if (isempty(vol_id))
                id128_to_uuid_string(uuid, vol_id);

        r = safe_fork("(mkfs)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                /* When changing this conditional, also adjust the log statement below. */
                if (streq(fstype, "ext2"))
                        (void) execlp(mkfs, mkfs,
                                      "-q",
                                      "-L", label,
                                      "-U", vol_id,
                                      "-I", "256",
                                      "-m", "0",
                                      "-E", discard ? "discard,lazy_itable_init=1" : "nodiscard,lazy_itable_init=1",
                                      node, NULL);

                else if (STR_IN_SET(fstype, "ext3", "ext4"))
                        (void) execlp(mkfs, mkfs,
                                      "-q",
                                      "-L", label,
                                      "-U", vol_id,
                                      "-I", "256",
                                      "-O", "has_journal",
                                      "-m", "0",
                                      "-E", discard ? "discard,lazy_itable_init=1" : "nodiscard,lazy_itable_init=1",
                                      node, NULL);

                else if (streq(fstype, "btrfs")) {
                        (void) execlp(mkfs, mkfs,
                                      "-q",
                                      "-L", label,
                                      "-U", vol_id,
                                      node,
                                      discard ? NULL : "--nodiscard",
                                      NULL);

                } else if (streq(fstype, "xfs")) {
                        const char *j;

                        j = strjoina("uuid=", vol_id);

                        (void) execlp(mkfs, mkfs,
                                      "-q",
                                      "-L", label,
                                      "-m", j,
                                      "-m", "reflink=1",
                                      node,
                                      discard ? NULL : "-K",
                                      NULL);

                } else if (streq(fstype, "vfat"))

                        (void) execlp(mkfs, mkfs,
                                      "-i", vol_id,
                                      "-n", label,
                                      "-F", "32",  /* yes, we force FAT32 here */
                                      node, NULL);

                else if (streq(fstype, "swap"))
                        /* TODO: add --quiet here if
                         * https://github.com/util-linux/util-linux/issues/1499 resolved. */

                        (void) execlp(mkfs, mkfs,
                                      "-L", label,
                                      "-U", vol_id,
                                      node, NULL);

                else
                        /* Generic fallback for all other file systems */
                        (void) execlp(mkfs, mkfs, node, NULL);

                log_error_errno(errno, "Failed to execute %s: %m", mkfs);

                _exit(EXIT_FAILURE);
        }

        if (STR_IN_SET(fstype, "ext2", "ext3", "ext4", "btrfs", "xfs", "vfat", "swap"))
                log_info("%s successfully formatted as %s (label \"%s\", uuid %s)",
                         node, fstype, label, vol_id);
        else
                log_info("%s successfully formatted as %s (no label or uuid specified)",
                         node, fstype);

        return 0;
}

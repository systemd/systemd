/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "blkid-util.h"
#include "blockdev-util.h"
#include "chase.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "mountpoint-util.h"
#include "pcrextend-util.h"
#include "strv.h"

static int device_get_file_system_word(
                sd_device *d,
                const char *prefix,
                char **ret) {

#if HAVE_BLKID
        int r;
#endif

        assert(d);
        assert(prefix);
        assert(ret);

#if HAVE_BLKID
        _cleanup_close_ int block_fd = sd_device_open(d, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (block_fd < 0)
                return block_fd;

        _cleanup_(blkid_free_probep) blkid_probe b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, block_fd, 0, 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_UUID|BLKID_SUBLKS_LABEL);
        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return -ENOPKG;

        assert(r == _BLKID_SAFEPROBE_FOUND);

        _cleanup_strv_free_ char **l = strv_new(prefix);
        if (!l)
                return -ENOMEM;

        FOREACH_STRING(field, "TYPE", "UUID", "LABEL", "PART_ENTRY_UUID", "PART_ENTRY_TYPE", "PART_ENTRY_NAME") {
                const char *v = NULL;

                (void) blkid_probe_lookup_value(b, field, &v, NULL);

                _cleanup_free_ char *escaped = xescape(strempty(v), ":"); /* Avoid ambiguity around ":" */
                if (!escaped)
                        return -ENOMEM;

                r = strv_consume(&l, TAKE_PTR(escaped));
                if (r < 0)
                        return r;
        }

        assert(strv_length(l) == 7); /* We always want 7 components, to avoid ambiguous strings */

        _cleanup_free_ char *word = strv_join(l, ":");
        if (!word)
                return -ENOMEM;

        *ret = TAKE_PTR(word);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int pcrextend_file_system_word(const char *path, char **ret_word, char **ret_normalized_path) {
        _cleanup_free_ char *normalized_path = NULL, *normalized_escaped = NULL, *prefix = NULL, *word = NULL;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(path);
        assert(ret_word);

        dfd = chase_and_open(path, NULL, 0, O_DIRECTORY|O_CLOEXEC, &normalized_path);
        if (dfd < 0)
                return log_error_errno(dfd, "Failed to open path '%s': %m", path);

        r = is_mount_point_at(dfd, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if path '%s' is mount point: %m", normalized_path);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "Specified path '%s' is not a mount point, refusing.", normalized_path);

        normalized_escaped = xescape(normalized_path, ":"); /* Avoid ambiguity around ":" */
        if (!normalized_escaped)
                return log_oom();

        prefix = strjoin("file-system:", normalized_escaped);
        if (!prefix)
                return log_oom();

        r = block_device_new_from_fd(dfd, BLOCK_DEVICE_LOOKUP_BACKING, &d);
        if (r < 0) {
                log_notice_errno(r, "Unable to determine backing block device of '%s', using generic fallback file system identity string: %m", path);

                word = strjoin(prefix, "::::::");
                if (!word)
                        return log_oom();
        } else {
                r = device_get_file_system_word(d, prefix, &word);
                if (r < 0)
                        return log_error_errno(r, "Failed to get file system identifier string for '%s': %m", path);
        }

        *ret_word = TAKE_PTR(word);

        if (ret_normalized_path)
                *ret_normalized_path = TAKE_PTR(normalized_path);

        return 0;
}

int pcrextend_machine_id_word(char **ret) {
        _cleanup_free_ char *word = NULL;
        sd_id128_t mid;
        int r;

        assert(ret);

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire machine ID: %m");

        word = strjoin("machine-id:", SD_ID128_TO_STRING(mid));
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

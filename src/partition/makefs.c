/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "main-func.h"
#include "mkfs-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *device = NULL, *fstype = NULL, *detected = NULL, *label = NULL;
        _cleanup_close_ int lock_fd = -EBADF;
        sd_id128_t uuid;
        struct stat st;
        int r;

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program expects two arguments.");

        /* type and device must be copied because makefs calls safe_fork, which clears argv[] */
        fstype = strdup(argv[1]);
        if (!fstype)
                return log_oom();

        device = strdup(argv[2]);
        if (!device)
                return log_oom();

        if (stat(device, &st) < 0)
                return log_error_errno(errno, "Failed to stat \"%s\": %m", device);

        if (S_ISBLK(st.st_mode)) {
                /* Lock the device so that udev doesn't interfere with our work */

                lock_fd = lock_whole_block_device(st.st_rdev, LOCK_EX);
                if (lock_fd < 0)
                        return log_error_errno(lock_fd, "Failed to lock whole block device of \"%s\": %m", device);
        } else
                log_debug("%s is not a block device, no need to lock.", device);

        r = probe_filesystem(device, &detected);
        if (r == -EUCLEAN)
                return log_error_errno(r, "Ambiguous results of probing for file system on \"%s\", refusing to proceed.", device);
        if (r < 0)
                return log_error_errno(r, "Failed to probe \"%s\": %m", device);
        if (detected) {
                log_info("'%s' is not empty (contains file system of type %s), exiting.", device, detected);
                return 0;
        }

        r = sd_id128_randomize(&uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to generate UUID for file system: %m");

        r = path_extract_filename(device, &label);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name from '%s': %m", device);

        return make_filesystem(device,
                               fstype,
                               label,
                               /* root = */ NULL,
                               uuid,
                               /* discard = */ true,
                               /* quiet = */ true,
                               /* sector_size = */ 0,
                               /* compression = */ NULL,
                               /* compression_level = */ NULL,
                               /* extra_mkfs_options = */ NULL);
}

DEFINE_MAIN_FUNCTION(run);

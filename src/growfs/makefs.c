/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "build.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "mkfs-util.h"
#include "path-util.h"
#include "pretty-print.h"

#include "makefs.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-makefs@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] DEVICE FSTYPE \n\n"
               "Make file system on device.\n\n"
               "Options:\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *device = NULL, *fstype = NULL, *detected = NULL, *label = NULL;
        _cleanup_close_ int lock_fd = -EBADF;
        sd_id128_t uuid;
        struct stat st;
        int r;

        log_setup();

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

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

                lock_fd = lock_whole_block_device(st.st_rdev, O_WRONLY, LOCK_EX);
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
                               /* root= */ NULL,
                               uuid,
                               MKFS_DISCARD | MKFS_QUIET,
                               /* sector_size= */ 0,
                               /* compression= */ NULL,
                               /* compression_level= */ NULL,
                               /* extra_mkfs_options= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);

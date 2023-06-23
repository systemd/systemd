/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>

#include "devnum-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "sleep-util.h"

static const char *arg_resume_device = NULL;
static uint64_t arg_resume_offset = 0; /* in memory pages */

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects one or two arguments.");

        umask(0022);

        if (!in_initrd())
                return 0;

        arg_resume_device = argv[1];

        if (argc == 3) {
                r = safe_atou64(argv[2], &arg_resume_offset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse resume offset %s: %m", argv[2]);
        }

        if (stat(arg_resume_device, &st) < 0)
                return log_error_errno(errno, "Failed to stat resume device '%s': %m", arg_resume_device);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Resume device '%s' is not a block device.", arg_resume_device);

        /* The write shall not return if a resume takes place. */
        r = write_resume_config(st.st_rdev, arg_resume_offset, arg_resume_device);
        log_full_errno(r < 0 ? LOG_ERR : LOG_DEBUG,
                       r < 0 ? r : SYNTHETIC_ERRNO(ENOENT),
                       "Unable to resume from device '%s' (" DEVNUM_FORMAT_STR ") offset %" PRIu64 ", continuing boot process.",
                       arg_resume_device, DEVNUM_FORMAT_VAL(st.st_rdev), arg_resume_offset);

        return r;
}

DEFINE_MAIN_FUNCTION(run);

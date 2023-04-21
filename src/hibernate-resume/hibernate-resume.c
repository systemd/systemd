/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>

#include "fileio.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "static-destruct.h"
#include "string-util.h"

static char *arg_resume_device = NULL;
static uint64_t arg_resume_offset = 0;

STATIC_DESTRUCTOR_REGISTER(arg_resume_device, unsetp);

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects two arguments.");

        umask(0022);

        if (!in_initrd())
                return 0;

        arg_resume_device = argv[1];

        r = safe_atou64(argv[2], &arg_resume_offset);
        if (r < 0)
                return log_error_errno(r, "Failed to parse resume offset %s: %m", argv[2]);

        if (stat(arg_resume_device, &st) < 0)
                return log_error_errno(errno, "Failed to stat resume device '%s': %m", arg_resume_device);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Resume device '%s' is not a block device.", arg_resume_device);

        r = write_string_filef("/sys/power/resume_offset", WRITE_STRING_FILE_DISABLE_BUFFER, "%" PRIu64, arg_resume_offset);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to write resume offset %" PRIu64 " to /sys/power/resume_offset for device '%s': %m",
                                       arg_resume_offset, arg_resume_device);

        r = write_string_file("/sys/power/resume", FORMAT_DEVNUM(st.st_rdev), WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write '" DEVNUM_FORMAT_STR "' to /sys/power/resume: %m", DEVNUM_FORMAT_VAL(st.st_rdev));

        /*
         * The write above shall not return.
         *
         * However, failed resume is a normal condition (may mean that there is
         * no hibernation image).
         */

        log_info("Could not resume from device '%s' (" DEVNUM_FORMAT_STR ") offset %" PRIu64 ".",
                 arg_resume_device,
                 DEVNUM_FORMAT_VAL(st.st_rdev),
                 arg_resume_offset);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

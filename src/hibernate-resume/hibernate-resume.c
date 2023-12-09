/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>

#include "devnum-util.h"
#include "hibernate-resume-config.h"
#include "hibernate-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "static-destruct.h"

static HibernateInfo arg_info = {};

STATIC_DESTRUCTOR_REGISTER(arg_info, hibernate_info_done);

static int setup_hibernate_info_and_warn(void) {
        int r;

        r = acquire_hibernate_info(&arg_info);
        if (r == -ENODEV) {
                log_info_errno(r, "No resume device found, exiting.");
                return 0;
        }
        if (r < 0)
                return r;

        compare_hibernate_location_and_warn(&arg_info);

        return 1;
}

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        if (argc < 1 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects zero, one, or two arguments.");

        umask(0022);

        if (!in_initrd())
                return 0;

        if (argc > 1) {
                arg_info.device = argv[1];

                if (argc == 3) {
                        r = safe_atou64(argv[2], &arg_info.offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resume offset %s: %m", argv[2]);
                }
        } else {
                r = setup_hibernate_info_and_warn();
                if (r <= 0)
                        return r;

                if (arg_info.efi)
                        clear_efi_hibernate_location_and_warn();
        }

        if (stat(arg_info.device, &st) < 0)
                return log_error_errno(errno, "Failed to stat resume device '%s': %m", arg_info.device);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Resume device '%s' is not a block device.", arg_info.device);

        /* The write shall not return if a resume takes place. */
        r = write_resume_config(st.st_rdev, arg_info.offset, arg_info.device);
        log_full_errno(r < 0 ? LOG_ERR : LOG_DEBUG,
                       r < 0 ? r : SYNTHETIC_ERRNO(ENOENT),
                       "Unable to resume from device '%s' (" DEVNUM_FORMAT_STR ") offset %" PRIu64 ", continuing boot process.",
                       arg_info.device, DEVNUM_FORMAT_VAL(st.st_rdev), arg_info.offset);

        return r;
}

DEFINE_MAIN_FUNCTION(run);

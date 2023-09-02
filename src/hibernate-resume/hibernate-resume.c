/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>

#include "device-nodes.h"
#include "devnum-util.h"
#include "efivars.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "sleep-util.h"
#include "string-util.h"

static const char *arg_resume_device = NULL;
static uint64_t arg_resume_offset = 0; /* in memory pages */
static const char *arg_resume_device_efi = NULL;
static uint64_t arg_resume_offset_efi = 0;
static bool arg_clear_efi = false;

static int parse_and_validate_arguments(int argc, char *argv[]) {
        if (!IN_SET(argc, 2, 3, 5))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects one, two, or four arguments.");

        arg_resume_device = empty_to_null(argv[1]);
        if (argc < 4 && !arg_resume_device)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No resume device specified.");

        if (!isempty(argv[2])) {
                r = safe_atou64(argv[2], &arg_resume_offset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse resume offset %s: %m", argv[2]);
        }

        if (argc < 4)
                return 0;

        arg_resume_device_efi = argv[3];

        r = safe_atou64(argv[4], &arg_resume_offset_efi);
        if (r < 0)
                return log_error_errno(r, "Failed to parse EFI HibernateLocation resume offset %s: %m", argv[4]);

        arg_clear_efi = true;

        if (!arg_resume_device) {
                arg_resume_device = arg_resume_device_efi;
                arg_resume_offset = arg_resume_offset_efi;
        } else {
                if (!path_equal(arg_resume_device, arg_resume_device_efi)) {
                        r = devnode_same(arg_resume_device, arg_resume_device_efi);
                        if (r < 0)
                                log_warning_errno(r,
                                                  "Failed to check if resume=%s is the same device as EFI HibernateLocation device '%s', ignoring: %m",
                                                  arg_resume_device, arg_resume_device_efi);
                        if (r == 0)
                                log_warning("resume=%s doesn't match with EFI HibernateLocation device '%s', proceeding anyway with resume=.",
                                            arg_resume_device, arg_resume_device_efi);
                }

                if (arg_resume_offset != arg_resume_offset_efi)
                        log_warning("resume_offset=%" PRIu64 " doesn't match with EFI HibernateLocation offset %" PRIu64 ", proceeding anyway with resume_offset=.",
                                    arg_resume_offset, arg_resume_offset_efi);
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        r = parse_and_validate_arguments(argc, argv);
        if (r < 0)
                return r;

        umask(0022);

        if (!in_initrd())
                return 0;

        if (arg_clear_efi) {
                r = efi_set_variable(EFI_SYSTEMD_VARIABLE(HibernateLocation), NULL, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to clear EFI variable HibernateLocation, ignoring: %m");
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

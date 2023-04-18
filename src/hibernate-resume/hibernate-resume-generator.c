/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "dropin.h"
#include "efivars.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

static const char *arg_dest = NULL;
static char *arg_resume_device = NULL;
static char *arg_resume_offset = NULL;
static char *arg_resume_options = NULL;
static char *arg_root_options = NULL;
static bool arg_noresume = false;
static bool arg_write_offset = false;

STATIC_DESTRUCTOR_REGISTER(arg_resume_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_resume_offset, freep);
STATIC_DESTRUCTOR_REGISTER(arg_resume_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {

        if (streq(key, "resume")) {
                char *s;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                s = fstab_node_to_udev_node(value);
                if (!s)
                        return log_oom();

                free_and_replace(arg_resume_device, s);

        } else if (streq(key, "resume_offset")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (free_and_strdup(&arg_resume_offset, value) < 0)
                        return log_oom();

        } else if (streq(key, "resumeflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_resume_options, ",", value))
                        return log_oom();

        } else if (streq(key, "rootflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_root_options, ",", value))
                        return log_oom();

        } else if (streq(key, "noresume")) {
                if (value) {
                        log_warning("\"noresume\" kernel command line switch specified with an argument, ignoring.");
                        return 0;
                }

                arg_noresume = true;
        }

        return 0;
}

static int parse_efi_hibernate_info(void) {
        _cleanup_strv_free_ char **info_split = NULL;
        _cleanup_free_ char *info = NULL, *device = NULL;
        const char *offset;
        dev_t dev;
        int r;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE(HibernateInfo), &info);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get EFI variable HibernateInfo: %m");

        info_split = strv_split(info, "=");
        if (!info_split)
                return log_oom();

        r = parse_devnum(info_split[0], &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to parse HibernateInfo device '%s': %m", info_split[0]);

        r = devname_from_devnum(S_IFBLK, dev, &device);
        if (r < 0)
                return log_warning_errno(r, "Failed to get resume devname from devnum '%s': %m", info_split[0]);

        offset = info_split[1];

        if (!arg_resume_device) {
                arg_resume_device = TAKE_PTR(device);

                if (offset) {
                        arg_resume_offset = strdup(offset);
                        if (!arg_resume_offset)
                                return log_oom();

                        arg_write_offset = true;
                }
        } else {
                if (!streq(arg_resume_device, device))
                        log_warning("resume=%s mismatches with HibernateInfo device '%s', proceeding anyway.",
                                    arg_resume_device, device);

                if (!streq_ptr(arg_resume_offset, offset))
                        log_warning("resume_offset=%s mismatches with HibernateInfo offset %s, proceeding anyway.",
                                    strna(arg_resume_offset), strna(offset));
        }

        return 0;
}

static int process_resume(void) {
        _cleanup_free_ char *service_unit = NULL, *device_unit = NULL, *lnk = NULL;
        int r;

        if (!arg_resume_device)
                return 0;

        r = unit_name_from_path_instance("systemd-hibernate-resume", arg_resume_device, ".service",
                                         &service_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        lnk = strjoin(arg_dest, "/" SPECIAL_SYSINIT_TARGET ".wants/", service_unit);
        if (!lnk)
                return log_oom();

        (void) mkdir_parents_label(lnk, 0755);
        if (symlink(SYSTEM_DATA_UNIT_DIR "/systemd-hibernate-resume@.service", lnk) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", lnk);

        if (arg_write_offset) {
                if (access("/sys/power/resume_offset", W_OK) < 0) {
                        if (errno == ENOENT)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Kernel too old, can't set resume_offset=%s for device '%s'.",
                                                       arg_resume_offset, arg_resume_device);

                        return log_error_errno(errno, "/sys/power/resume_offset not writable: %m");
                }

                r = write_string_file("/sys/power/resume_offset", arg_resume_offset, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to write swap file offset %s to /sys/power/resume_offset for device '%s': %m",
                                               arg_resume_offset, arg_resume_device);
        }

        r = unit_name_from_path(arg_resume_device, ".device", &device_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = write_drop_in(arg_dest, device_unit, 40, "device-timeout",
                          "# Automatically generated by systemd-hibernate-resume-generator\n\n"
                          "[Unit]\nJobTimeoutSec=0");
        if (r < 0)
                log_warning_errno(r, "Failed to write device timeout drop-in: %m");

        r = generator_write_timeouts(arg_dest,
                                     arg_resume_device,
                                     arg_resume_device,
                                     arg_resume_options ?: arg_root_options,
                                     NULL);
        if (r < 0)
                return r;

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r = 0;

        arg_dest = ASSERT_PTR(dest);

        /* Don't even consider resuming outside of initrd. */
        if (!in_initrd()) {
                log_debug("Not running in an initrd, quitting.");
                return 0;
        }

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (arg_noresume) {
                log_notice("Found \"noresume\" on the kernel command line, quitting.");
                return 0;
        }

        if (is_efi_boot()) {
                (void) parse_efi_hibernate_info();

                r = efi_set_variable(EFI_SYSTEMD_VARIABLE(HibernateInfo), NULL, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to clear EFI variable HibernateInfo, ignoring: %m");
        }

        return process_resume();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);

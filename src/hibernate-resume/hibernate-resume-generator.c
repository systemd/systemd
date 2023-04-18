/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "unit-name.h"

static const char *arg_dest = NULL;
static char *arg_resume_device = NULL;
static char *arg_resume_options = NULL;
static char *arg_root_options = NULL;
static bool arg_noresume = false;
static uint64_t arg_resume_offset = 0;

STATIC_DESTRUCTOR_REGISTER(arg_resume_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_resume_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "resume")) {
                char *s;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                s = fstab_node_to_udev_node(value);
                if (!s)
                        return log_oom();

                free_and_replace(arg_resume_device, s);

        } else if (proc_cmdline_key_streq(key, "resume_offset")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou64(value, &arg_resume_offset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse resume_offset=%s: %m", value);

        } else if (proc_cmdline_key_streq(key, "resumeflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_resume_options, ",", value))
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "rootflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_root_options, ",", value))
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "noresume")) {
                if (value) {
                        log_warning("\"noresume\" kernel command line switch specified with an argument, ignoring.");
                        return 0;
                }

                arg_noresume = true;
        }

        return 0;
}

static int process_resume(void) {
        _cleanup_free_ char *device_unit = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (!arg_resume_device)
                return 0;

        r = unit_name_from_path(arg_resume_device, ".device", &device_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate device unit name from path '%s': %m", arg_resume_device);

        r = generator_open_unit_file(arg_dest, NULL, SPECIAL_HIBERNATE_RESUME_SERVICE, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=Resume from hibernation\n"
                "Documentation=man:systemd-hibernate-resume.service(8)\n"
                "DefaultDependencies=no\n"
                "BindsTo=%1$s\n"
                "Wants=local-fs-pre.target\n"
                "After=%1$s\n"
                "Before=local-fs-pre.target\n"
                "AssertPathExists=/etc/initrd-release\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "ExecStart=" ROOTLIBEXECDIR "/systemd-hibernate-resume %2$s %3$" PRIu64,
                device_unit,
                arg_resume_device,
                arg_resume_offset);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to create " SPECIAL_HIBERNATE_RESUME_SERVICE ": %m");

        r = generator_add_symlink(arg_dest, SPECIAL_SYSINIT_TARGET, "wants", SPECIAL_HIBERNATE_RESUME_SERVICE);
        if (r < 0)
                return r;

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
        int r;

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

        return process_resume();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "id128-util.h"
#include "initrd-util.h"
#include "json.h"
#include "log.h"
#include "main-func.h"
#include "os-util.h"
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

#if ENABLE_EFI
typedef struct EFIHibernateLocation {
        sd_id128_t uuid;
        uint64_t offset;
        char *id;
        char *image_id;
        char *version_id;
        char *image_version;
} EFIHibernateLocation;
#endif

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

static int parse_efi_hibernate_location(void) {
        int r = 0;

#if ENABLE_EFI
        static const JsonDispatch dispatch_table[] = {
                { "uuid",         JSON_VARIANT_STRING,   json_dispatch_id128,        offsetof(EFIHibernateLocation, id),            JSON_MANDATORY             },
                { "offset",       JSON_VARIANT_UNSIGNED, json_dispatch_uint64,       offsetof(EFIHibernateLocation, offset),        JSON_MANDATORY             },
                { "id",           JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(EFIHibernateLocation, id),            JSON_PERMISSIVE|JSON_DEBUG },
                { "imageId",      JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(EFIHibernateLocation, image_id),      JSON_PERMISSIVE|JSON_DEBUG },
                { "versionId",    JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(EFIHibernateLocation, version_id),    JSON_PERMISSIVE|JSON_DEBUG },
                { "imageVersion", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(EFIHibernateLocation, image_version), JSON_PERMISSIVE|JSON_DEBUG },
                {},
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *location_str = NULL, *device = NULL, *id = NULL, *image_id = NULL,
                       *version_id = NULL, *image_version = NULL;
        char node[STRLEN("UUID=") + SD_ID128_UUID_STRING_MAX];
        EFIHibernateLocation location = {};
        int log_level, log_level_ignore;

        log_level = arg_resume_device ? LOG_DEBUG : LOG_ERR;
        log_level_ignore = arg_resume_device ? LOG_DEBUG : LOG_WARNING;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE(HibernateLocation), &location_str);
        if (r == -ENOENT) {
                log_debug("EFI variable HibernateLocation is not set, skipping.");
                return 0;
        }
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to get EFI variable HibernateLocation: %m");

        r = json_parse(location_str, 0, &v, NULL, NULL);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to parse HibernateLocation JSON object: %m");

        r = json_dispatch(v, dispatch_table, NULL, JSON_LOG, &location);
        if (r < 0)
                return r;

        xsprintf(node, "UUID=" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(location.uuid));

        device = fstab_node_to_udev_node(node);
        if (!device)
                return log_full_errno(log_level, SYNTHETIC_ERRNO(ENODEV), "Failed to get resume device through HibernateLocation.");

        r = parse_os_release(NULL,
                             "ID", &id,
                             "IMAGE_ID", &image_id,
                             "VERSION_ID", &version_id,
                             "IMAGE_VERSION", &image_version);
        if (r < 0)
                log_full_errno(log_level_ignore, r, "Failed to parse os-release, ignoring: %m");

        if (!streq_ptr(id, location.id) ||
            !streq_ptr(image_id, location.image_id) ||
            !streq_ptr(version_id, location.version_id) ||
            !streq_ptr(image_version, location.image_version)) {

                log_notice("HibernateLocation system info mismatches with os-release, not resuming from it.");
                return 0;
        }

        if (!arg_resume_device) {
                arg_resume_device = TAKE_PTR(device);
                arg_resume_offset = location.offset;
        } else {
                if (!streq(arg_resume_device, device))
                        log_warning("resume=%s mismatches with HibernateLocation device '%s', proceeding anyway.",
                                    arg_resume_device, device);

                if (arg_resume_offset != location.offset)
                        log_warning("resume_offset=%" PRIu64 " mismatches with HibernateLocation offset %" PRIu64 ", proceeding anyway.",
                                    arg_resume_offset, location.offset);
        }

        r = efi_set_variable(EFI_SYSTEMD_VARIABLE(HibernateLocation), NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to clear EFI variable HibernateLocation, ignoring: %m");
#endif

        return r;
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

        r = parse_efi_hibernate_location();
        if (r == -ENOMEM)
                return r;

        return process_resume();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "build.h"
#include "chase.h"
#include "device-util.h"
#include "dlopen-note.h"
#include "errno-util.h"
#include "fd-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "mountpoint-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "validatefs-util.h"
#include "verbs.h"

static char *arg_target = NULL;
static char *arg_root = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_target, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

COMMAND(
        "systemd-validatefs\0",
        "Check file system validation constraints.",
        .argspec = "MOUNTPOINT\0",
        .man_pages = "systemd-validatefs@.service(8)\0",
);

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("root", "PATH|auto", "Operate relative to the specified path"):
                        if (streq(opts.arg, "auto"))
                                r = free_and_strdup_warn(&arg_root, in_initrd() ? "/sysroot" : NULL);
                        else {
                                if (!path_is_absolute(opts.arg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "--root= argument must be 'auto' or absolute path, got: %s", opts.arg);

                                r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        }
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        char **args = option_parser_get_args(&opts);

        if (strv_length(args) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s expects exactly one argument (the mount point).",
                                       program_invocation_short_name);

        arg_target = strdup(args[0]);
        if (!arg_target)
                return log_oom();

        if (arg_root && !path_startswith(arg_target, arg_root))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Specified path '%s' does not start with specified root '%s', refusing.",
                                       arg_target, arg_root);
        return 1;
}

static int validate_gpt_label(blkid_probe b, const ValidateFields *f) {
        assert(b);
        assert(f);

        const char *v = NULL;
        (void) sym_blkid_probe_lookup_value(b, "PART_ENTRY_NAME", &v, /* len= */ NULL);

        return validate_fields_check_gpt_label(f, v, LOG_ERR);
}

static int validate_gpt_type(blkid_probe b, const ValidateFields *f) {
        assert(b);
        assert(f);

        const char *v = NULL;
        (void) sym_blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, /* len= */ NULL);

        sd_id128_t id;
        if (!v || sd_id128_from_string(v, &id) < 0)
                return validate_fields_check_gpt_type(f, /* type= */ NULL, LOG_ERR);

        return validate_fields_check_gpt_type(f, &id, LOG_ERR);
}

static int validate_gpt_metadata_one(sd_device *d, const char *path, const ValidateFields *f) {
        int r;

        assert(d);
        assert(f);

        r = dlopen_libblkid(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_close_ int block_fd = sd_device_open(d, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (block_fd < 0)
                return log_error_errno(block_fd, "Failed to open block device backing '%s': %m", path);

        _cleanup_(blkid_free_probep) blkid_probe b = sym_blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = sym_blkid_probe_set_device(b, block_fd, 0, 0);
        if (r != 0)
                return log_error_errno(errno_or_else(ENOMEM), "Failed to set up block device prober for '%s': %m", path);

        (void) sym_blkid_probe_enable_superblocks(b, 1);
        (void) sym_blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_LABEL);
        (void) sym_blkid_probe_enable_partitions(b, 1);
        (void) sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_error_errno(errno_or_else(EIO), "Failed to probe block device of '%s': %m", path);
        if (r == _BLKID_SAFEPROBE_AMBIGUOUS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Found multiple file system labels on block device '%s'.", path);
        if (r == _BLKID_SAFEPROBE_NOT_FOUND)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Found no file system label on block device '%s'.", path);

        assert(r == _BLKID_SAFEPROBE_FOUND);

        const char *v = NULL;
        (void) sym_blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, /* len= */ NULL);
        if (!streq_ptr(v, "gpt"))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "File system is supposed to be on a GPT partition table, but is not, refusing.");

        r = validate_gpt_label(b, f);
        if (r < 0)
                return r;

        r = validate_gpt_type(b, f);
        if (r < 0)
                return r;

        return 0;
}

static int validate_gpt_metadata(int fd, const char *path, const ValidateFields *f) {
        int r;

        assert(fd >= 0);
        assert(path);
        assert(f);

        if (!validate_fields_need_gpt(f))
                return 0;

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        r = block_device_new_from_fd(fd, BLOCK_DEVICE_LOOKUP_BACKING, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to find block device backing '%s': %m", path);

        /* Now validate all subordinate devices individually. */
        bool have_slaves = false;
        const char *suffix;
        FOREACH_DEVICE_CHILD_WITH_SUFFIX(d, child, suffix) {
                if (!path_startswith(suffix, "slaves"))
                        continue;

                have_slaves = true;

                r = validate_gpt_metadata_one(child, path, f);
                if (r < 0)
                        return r;
        }

        /* If this device has no subordinate devices, then validate the device itself instead */
        if (!have_slaves) {
                r = validate_gpt_metadata_one(d, path, f);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int validate_fields_check(int fd, const char *path, const ValidateFields *f) {
        int r;

        assert(fd >= 0);
        assert(path);
        assert(f);

        r = validate_fields_check_mount_point(f, arg_root, path, LOG_ERR);
        if (r < 0)
                return r;

        r = validate_gpt_metadata(fd, path, f);
        if (r < 0)
                return r;

        log_info("File system '%s' passed validation constraints, proceeding.", path);
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBBLKID_NOTE(required);

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_free_ char *resolved = NULL;
        _cleanup_close_ int target_fd = chase_and_open(arg_target, arg_root, CHASE_MUST_BE_DIRECTORY, O_DIRECTORY|O_CLOEXEC, &resolved);
        if (target_fd < 0)
                return log_error_errno(target_fd, "Failed to open directory '%s': %m", arg_target);

        r = is_mount_point_at(target_fd, /* path= */ NULL, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", resolved);
        if (!r)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "Directory '%s' is not a mount point.", resolved);

        _cleanup_(validate_fields_done) ValidateFields f = {};
        r = validate_fields_read(target_fd, LOG_ERR, &f);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("File system '%s' has no validation constraints set, not validating.", resolved);
                return 0;
        }

        return validate_fields_check(target_fd, resolved, &f);
}

DEFINE_MAIN_FUNCTION(run);

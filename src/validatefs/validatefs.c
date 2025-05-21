/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "build.h"
#include "chase.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "gpt.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "mountpoint-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "xattr-util.h"

static char *arg_target = NULL;
static char *arg_root = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_target, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        int r;

        _cleanup_free_ char *link = NULL;
        r = terminal_urlify_man("systemd-validatefs@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] /path/to/mountpoint\n"
               "\n%3$sCheck file system validation constraints.%4$s\n\n"
               "  -h --help            Show this help and exit\n"
               "     --version         Print version string and exit\n"
               "     --root=PATH|auto  Operate relative to the specified path\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
        };

        int c, r;

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'         },
                { "version" , no_argument,       NULL, ARG_VERSION },
                { "root",     required_argument, NULL, ARG_ROOT    },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        if (streq(optarg, "auto")) {
                                arg_root = mfree(arg_root);

                                if (in_initrd()) {
                                        arg_root = strdup("/sysroot");
                                        if (!arg_root)
                                                return log_oom();
                                }

                                break;
                        }

                        if (!path_is_absolute(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--root= argument must be 'auto' or absolute path, got: %s", optarg);

                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind + 1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s excepts exactly one argument (the mount point).",
                                       program_invocation_short_name);

        arg_target = strdup(argv[optind]);
        if (!arg_target)
                return log_oom();

        if (arg_root && !path_startswith(arg_target, arg_root))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path '%s' does not start with specified root '%s', refusing.", arg_target, arg_root);

        return 1;
}

typedef struct ValidateFields {
        sd_id128_t *gpt_type_uuid;
        size_t n_gpt_type_uuid;
        char **gpt_label;
        char **mount_point;
} ValidateFields;

static void validate_fields_done(ValidateFields *f) {
        assert(f);

        free(f->gpt_type_uuid);
        strv_free(f->gpt_label);
        strv_free(f->mount_point);
}

static char* validate_fields_gpt_type_uuid_as_string(const ValidateFields *f) {
        _cleanup_free_ char *joined = NULL;

        assert(f);

        FOREACH_ARRAY(u, f->gpt_type_uuid, f->n_gpt_type_uuid) {
                if (!strextend_with_separator(&joined, ", ", SD_ID128_TO_UUID_STRING(*u)))
                        return NULL;

                const char *id = gpt_partition_type_uuid_to_string(*u);
                if (id)
                        (void) strextend(&joined, " (", id, ")");
        }

        return TAKE_PTR(joined);
}

static int validate_fields_read(int fd, ValidateFields *ret) {
        _cleanup_(validate_fields_done) ValidateFields f = {};
        int r;

        assert(fd >= 0);
        assert(ret);

        _cleanup_strv_free_ char **l = NULL;
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.gpt_type_uuid", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_error_errno(r, "Failed to read 'user.validatefs.gpt_type_uuid' xattr: %m");
        } else {
                STRV_FOREACH(i, l) {
                        if (!GREEDY_REALLOC(f.gpt_type_uuid, f.n_gpt_type_uuid+1))
                                return log_oom();

                        r = sd_id128_from_string(*i, f.gpt_type_uuid + f.n_gpt_type_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse 'user.validatefs.gpt_type_uuid' xattr: %s", *i);

                        f.n_gpt_type_uuid++;
                }
        }

        l = strv_free(l);
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.gpt_label", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_error_errno(r, "Failed to read 'user.validatefs.gpt_label' xattr: %m");
        } else {
                STRV_FOREACH(i, l)
                        if (!utf8_is_valid(*i) ||
                            string_has_cc(*i, /* ok= */ NULL))
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Extended attribute 'user.validatefs.gpt_label' contains invalid characters, refusing: %s", *i);

                f.gpt_label = TAKE_PTR(l);
        }

        l = strv_free(l);
        r = getxattr_at_strv(fd, /* path= */ NULL, "user.validatefs.mount_point", AT_EMPTY_PATH, &l);
        if (r < 0) {
                if (r != -ENODATA && !ERRNO_IS_NOT_SUPPORTED(r))
                        return log_error_errno(r, "Failed to read 'user.validatefs.mount_point' xattr: %m");
        } else {
                STRV_FOREACH(i, l)
                        if (!utf8_is_valid(*i) ||
                            string_has_cc(*i, /* ok= */ NULL) ||
                            !path_is_absolute(*i) ||
                            !path_is_normalized(*i))
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Path listed in extended attribute 'user.validatefs.mount_point' is not a valid, normalized, absolute path or contains invalid characters, refusing: %s", *i);

                f.mount_point = TAKE_PTR(l);
        }

        r = f.n_gpt_type_uuid > 0 || !strv_isempty(f.gpt_label) || !strv_isempty(f.mount_point);
        *ret = TAKE_STRUCT(f);
        return r;
}

static int validate_mount_point(const char *path, const ValidateFields *f) {
        assert(path);
        assert(f);

        if (strv_isempty(f->mount_point))
                return 0;

        STRV_FOREACH(i, f->mount_point) {
                _cleanup_free_ char *jj = NULL;
                const char *j;

                if (arg_root) {
                        jj = path_join(arg_root, *i);
                        if (!jj)
                                return log_oom();

                        j = jj;
                } else
                        j = *i;

                if (path_equal(path, j))
                        return 0;
        }

        _cleanup_free_ char *joined = strv_join(f->mount_point, ", ");
        return log_error_errno(
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be mounted on one of %s only, but is mounted on %s, refusing.",
                        strna(joined), path);
}

static int validate_gpt_label(blkid_probe b, const ValidateFields *f) {
        assert(b);
        assert(f);

        if (strv_isempty(f->gpt_label))
                return 0;

        const char *v = NULL;
        (void) blkid_probe_lookup_value(b, "PART_ENTRY_NAME", &v, /* len= */ NULL);

        if (strv_contains(f->gpt_label, strempty(v)))
                return 0;

        _cleanup_free_ char *joined = strv_join(f->gpt_label, "', '");
        return log_error_errno(
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be placed in a partition with labels '%s' only, but is placed in one labelled '%s', refusing.",
                        strna(joined), strempty(v));
}

static int validate_gpt_type(blkid_probe b, const ValidateFields *f) {
        assert(b);
        assert(f);

        if (f->n_gpt_type_uuid == 0)
                return 0;

        const char *v = NULL;
        (void) blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, /* len= */ NULL);

        sd_id128_t id;
        if (!v || sd_id128_from_string(v, &id) < 0) {
                _cleanup_free_ char *joined = validate_fields_gpt_type_uuid_as_string(f);
                return log_error_errno(
                                SYNTHETIC_ERRNO(EPERM),
                                "File system is supposed to be placed in a partition of type UUIDs %s only, but has no type, refusing.",
                                strna(joined));
        }

        FOREACH_ARRAY(u, f->gpt_type_uuid, f->n_gpt_type_uuid)
                if (sd_id128_equal(*u, id))
                        return 0;

        _cleanup_free_ char *joined = validate_fields_gpt_type_uuid_as_string(f);
        return log_error_errno(
                        SYNTHETIC_ERRNO(EPERM),
                        "File system is supposed to be placed in a partition of type UUIDs %s only, but has type '%s', refusing.",
                        strna(joined), SD_ID128_TO_UUID_STRING(id));
}

static int validate_gpt_metadata_one(sd_device *d, const char *path, const ValidateFields *f) {
        int r;

        assert(d);
        assert(f);

        _cleanup_close_ int block_fd = sd_device_open(d, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (block_fd < 0)
                return log_error_errno(block_fd, "Failed to open block device backing '%s': %m", path);

        _cleanup_(blkid_free_probep) blkid_probe b = blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = blkid_probe_set_device(b, block_fd, 0, 0);
        if (r != 0)
                return log_error_errno(errno_or_else(ENOMEM), "Failed to set up block device prober for '%s': %m", path);

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_LABEL);
        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_error_errno(errno_or_else(EIO), "Failed to probe block device of '%s': %m", path);
        if (r == _BLKID_SAFEPROBE_AMBIGUOUS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Found multiple file system labels on block device '%s'.", path);
        if (r == _BLKID_SAFEPROBE_NOT_FOUND)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Found no file system label on block device '%s'.", path);

        assert(r == _BLKID_SAFEPROBE_FOUND);

        const char *v = NULL;
        (void) blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, /* len= */ NULL);
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

        if (strv_isempty(f->gpt_label) && f->n_gpt_type_uuid == 0)
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

        r = validate_mount_point(path, f);
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

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_free_ char *resolved = NULL;
        _cleanup_close_ int target_fd = chase_and_open(arg_target, arg_root, CHASE_MUST_BE_DIRECTORY, O_DIRECTORY|O_CLOEXEC, &resolved);
        if (target_fd < 0)
                return log_error_errno(target_fd, "Failed to open directory '%s': %m", arg_target);

        r = is_mount_point_at(target_fd, /* filename= */ NULL, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", resolved);
        if (!r)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "Directory '%s' is not a mount point.", resolved);

        _cleanup_(validate_fields_done) ValidateFields f = {};
        r = validate_fields_read(target_fd, &f);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("File system '%s' has no validation constraints set, not validating.", resolved);
                return 0;
        }

        return validate_fields_check(target_fd, resolved, &f);
}

DEFINE_MAIN_FUNCTION(run);

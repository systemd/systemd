/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "import-raw.h"
#include "import-tar.h"
#include "import-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"

static char *arg_image_root = NULL;
static ImportFlags arg_import_flags = IMPORT_BTRFS_SUBVOL | IMPORT_BTRFS_QUOTA | IMPORT_CONVERT_QCOW2 | IMPORT_SYNC;
static uint64_t arg_offset = UINT64_MAX, arg_size_max = UINT64_MAX;
static ImageClass arg_class = IMAGE_MACHINE;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_image_root, freep);

static int normalize_local(const char *local, char **ret) {
        _cleanup_free_ char *ll = NULL;
        int r;

        assert(ret);

        if (arg_import_flags & IMPORT_DIRECT) {

                if (!local)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No local path specified.");

                if (!path_is_absolute(local))  {
                        ll = path_join(arg_image_root, local);
                        if (!ll)
                                return log_oom();

                        local = ll;
                }

                if (!path_is_valid(local))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local path name '%s' is not valid.", local);
        } else {
                if (local) {
                        if (!image_name_is_valid(local))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Local image name '%s' is not valid.",
                                                       local);
                } else
                        local = "imported";

                if (!FLAGS_SET(arg_import_flags, IMPORT_FORCE)) {
                        r = image_find(arg_runtime_scope, arg_class, local, NULL, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "Image '%s' already exists.",
                                                       local);
                }
        }

        if (!ll) {
                ll = strdup(local);
                if (!ll)
                        return log_oom();
        }

        *ret = TAKE_PTR(ll);
        return 0;
}

static int open_source(const char *path, const char *local, int *ret_open_fd) {
        _cleanup_close_ int open_fd = -EBADF;
        int retval;

        assert(local);
        assert(ret_open_fd);

        if (path) {
                open_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open source file '%s': %m", path);

                retval = open_fd;

                if (arg_offset != UINT64_MAX)
                        log_info("Importing '%s', saving at offset %" PRIu64 " in '%s'.", path, arg_offset, local);
                else
                        log_info("Importing '%s', saving as '%s'.", path, local);
        } else {
                _cleanup_free_ char *pretty = NULL;

                retval = STDIN_FILENO;

                (void) fd_get_path(STDIN_FILENO, &pretty);

                if (arg_offset != UINT64_MAX)
                        log_info("Importing '%s', saving at offset %" PRIu64 " in '%s'.", strempty(pretty), arg_offset, local);
                else
                        log_info("Importing '%s', saving as '%s'.", strempty(pretty), local);
        }

        if (!FLAGS_SET(arg_import_flags, IMPORT_DIRECT))
                log_info("Operating on image directory '%s'.", arg_image_root);

        if (!FLAGS_SET(arg_import_flags, IMPORT_SYNC))
                log_info("File system synchronization on completion is off.");

        *ret_open_fd = TAKE_FD(open_fd);
        return retval;
}

static void on_tar_finished(TarImport *import, int error, void *userdata) {
        sd_event *event = userdata;
        assert(import);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_tar, "tar", "FILE [NAME]", 2, 3, 0, "Import a TAR image");
static int verb_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(tar_import_unrefp) TarImport *import = NULL;
        _cleanup_free_ char *ll = NULL, *normalized = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -EBADF;
        int r, fd;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                _cleanup_free_ char *l = NULL;

                r = path_extract_filename(path, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

                r = tar_strip_suffixes(l, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;
        }

        r = normalize_local(local, &normalized);
        if (r < 0)
                return r;

        fd = open_source(path, normalized, &open_fd);
        if (fd < 0)
                return fd;

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = tar_import_new(&import, event, arg_image_root, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = tar_import_start(
                        import,
                        fd,
                        normalized,
                        arg_import_flags & IMPORT_FLAGS_MASK_TAR);
        if (r < 0)
                return log_error_errno(r, "Failed to import image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_raw_finished(RawImport *import, int error, void *userdata) {
        sd_event *event = userdata;
        assert(import);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_raw, "raw", "FILE [NAME]", 2, 3, 0, "Import a RAW image");
static int verb_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(raw_import_unrefp) RawImport *import = NULL;
        _cleanup_free_ char *ll = NULL, *normalized = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -EBADF;
        int r, fd;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                _cleanup_free_ char *l = NULL;

                r = path_extract_filename(path, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

                r = raw_strip_suffixes(l, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;
        }

        r = normalize_local(local, &normalized);
        if (r < 0)
                return r;

        fd = open_source(path, normalized, &open_fd);
        if (fd < 0)
                return fd;

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = raw_import_new(&import, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = raw_import_start(
                        import,
                        fd,
                        normalized,
                        arg_offset,
                        arg_size_max,
                        arg_import_flags & IMPORT_FLAGS_MASK_RAW);
        if (r < 0)
                return log_error_errno(r, "Failed to import image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "%sImport disk images.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("force", NULL, "Force creation of image"):
                        arg_import_flags |= IMPORT_FORCE;
                        break;

                OPTION_LONG("image-root", "PATH", "Image root directory"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("read-only", NULL, "Create a read-only image"):
                        arg_import_flags |= IMPORT_READ_ONLY;
                        break;

                OPTION_LONG("direct", NULL, "Import directly to specified file"):
                        arg_import_flags |= IMPORT_DIRECT;
                        break;

                OPTION_LONG("btrfs-subvol", "BOOL",
                            "Controls whether to create a btrfs subvolume instead of a directory"):
                        r = parse_boolean_argument("--btrfs-subvol=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, r);
                        break;

                OPTION_LONG("btrfs-quota", "BOOL",
                            "Controls whether to set up quota for btrfs subvolume"):
                        r = parse_boolean_argument("--btrfs-quota=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_QUOTA, r);
                        break;

                OPTION_LONG("convert-qcow2", "BOOL",
                            "Controls whether to convert QCOW2 images to regular disk images"):
                        r = parse_boolean_argument("--convert-qcow2=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_CONVERT_QCOW2, r);
                        break;

                OPTION_LONG("sync", "BOOL", "Controls whether to sync() before completing"):
                        r = parse_boolean_argument("--sync=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_SYNC, r);
                        break;

                OPTION_LONG("offset", "BYTES", "Offset to seek to in destination"): {
                        uint64_t u;

                        r = safe_atou64(opts.arg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --offset= argument: %s", opts.arg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --offset= switch too large: %s", opts.arg);

                        arg_offset = u;
                        break;
                }

                OPTION_LONG("size-max", "BYTES", "Maximum number of bytes to write to destination"): {
                        uint64_t u;

                        r = parse_size(opts.arg, 1024, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --size-max= argument: %s", opts.arg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --size-max= switch too large: %s", opts.arg);

                        arg_size_max = u;
                        break;
                }

                OPTION_LONG("class", "CLASS",
                            "Select image class (machine, sysext, confext, portable)"):
                        arg_class = image_class_from_string(opts.arg);
                        if (arg_class < 0)
                                return log_error_errno(arg_class, "Failed to parse --class= argument: %s", opts.arg);
                        break;

                OPTION_COMMON_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        /* Make sure offset+size is still in the valid range if both set */
        if (arg_offset != UINT64_MAX && arg_size_max != UINT64_MAX &&
            ((arg_size_max > (UINT64_MAX - arg_offset)) ||
             !FILE_SIZE_VALID(arg_offset + arg_size_max)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset und maximum size out of range.");

        if (arg_offset != UINT64_MAX && !FLAGS_SET(arg_import_flags, IMPORT_DIRECT))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset only supported in --direct mode.");

        if (!arg_image_root) {
                r = image_root_pick(arg_runtime_scope < 0 ? RUNTIME_SCOPE_SYSTEM : arg_runtime_scope, arg_class, /* runtime= */ false, &arg_image_root);
                if (r < 0)
                        return log_error_errno(r, "Failed to pick image root: %m");
        }

        if (arg_runtime_scope == RUNTIME_SCOPE_USER)
                arg_import_flags |= IMPORT_FOREIGN_UID;

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static void parse_env(void) {
        int r;

        /* Let's make these relatively low-level settings also controllable via env vars. User can then set
         * them to systemd-import if they like to tweak behaviour */

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_SUBVOL");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_SUBVOL: %m");

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_QUOTA");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_BTRFS_QUOTA, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_QUOTA: %m");

        r = getenv_bool("SYSTEMD_IMPORT_SYNC");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_SYNC, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_SYNC: %m");
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        parse_env();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

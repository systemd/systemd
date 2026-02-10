/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "import-raw.h"
#include "import-tar.h"
#include "import-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
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

#include "import.args.inc"

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

static int import_tar(int argc, char *argv[], void *userdata) {
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

static int import_raw(int argc, char *argv[], void *userdata) {
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
        printf("%1$s [OPTIONS...] {COMMAND} ...\n"
               "\n%4$sImport disk images.%5$s\n"
               "\n%2$sCommands:%3$s\n"
               "  tar FILE [NAME]             Import a TAR image\n"
               "  raw FILE [NAME]             Import a RAW image\n"
               "\n%2$sOptions:%3$s\n"
               OPTION_HELP_GENERATED,
               program_invocation_short_name,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

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

        return 1;
}

static int import_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, verb_help  },
                { "tar",  2,        3,        0, import_tar },
                { "raw",  2,        3,        0, import_raw },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
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

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return import_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);

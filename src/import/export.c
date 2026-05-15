/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "export-raw.h"
#include "export-tar.h"
#include "fd-util.h"
#include "format-table.h"
#include "import-common.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "verbs.h"

static ImportFlags arg_import_flags = 0;
static Compression arg_compress = _COMPRESSION_INVALID;
static ImageClass arg_class = IMAGE_MACHINE;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

static void determine_compression_from_filename(const char *p) {
        if (arg_compress >= 0)
                return;

        arg_compress = p ? compression_from_filename(p) : COMPRESSION_NONE;
}

static void on_tar_finished(TarExport *export, int error, void *userdata) {
        sd_event *event = userdata;
        assert(export);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_export_tar, "tar", "NAME [FILE]", 2, 3, 0,
     "Export a TAR image");
static int verb_export_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(tar_export_unrefp) TarExport *export = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -EBADF;
        int r, fd;

        local = argv[1];
        if (image_name_is_valid(local)) {
                r = image_find(arg_runtime_scope, arg_class, local, NULL, &image);
                if (r == -ENOENT)
                        return log_error_errno(r, "Image %s not found.", local);
                if (r < 0)
                        return log_error_errno(r, "Failed to look for image %s: %m", local);

                local = image->path;
        } else
                local = argv[1];

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        determine_compression_from_filename(path);

        if (path) {
                open_fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open tar image for export: %m");

                fd = open_fd;

                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, path, compression_to_string(arg_compress));
        } else {
                _cleanup_free_ char *pretty = NULL;

                if (isatty_safe(STDOUT_FILENO))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Refusing to write archive to TTY.");

                fd = STDOUT_FILENO;

                (void) fd_get_path(fd, &pretty);
                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, strna(pretty), compression_to_string(arg_compress));
        }

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = tar_export_new(&export, event, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate exporter: %m");

        r = tar_export_start(
                        export,
                        local,
                        fd,
                        arg_compress,
                        arg_import_flags & IMPORT_FLAGS_MASK_TAR);
        if (r < 0)
                return log_error_errno(r, "Failed to export image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_raw_finished(RawExport *export, int error, void *userdata) {
        sd_event *event = userdata;
        assert(export);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_export_raw, "raw", "NAME [FILE]", 2, 3, 0,
     "Export a RAW image");
static int verb_export_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(raw_export_unrefp) RawExport *export = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -EBADF;
        int r, fd;

        local = argv[1];
        if (image_name_is_valid(local)) {
                r = image_find(arg_runtime_scope, arg_class, local, NULL, &image);
                if (r == -ENOENT)
                        return log_error_errno(r, "Image %s not found.", local);
                if (r < 0)
                        return log_error_errno(r, "Failed to look for image %s: %m", local);

                local = image->path;
        } else
                local = argv[1];

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        determine_compression_from_filename(path);

        if (path) {
                open_fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open raw image for export: %m");

                fd = open_fd;

                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, path, compression_to_string(arg_compress));
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDOUT_FILENO;

                (void) fd_get_path(fd, &pretty);
                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, strna(pretty), compression_to_string(arg_compress));
        }

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = raw_export_new(&export, event, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate exporter: %m");

        r = raw_export_start(export, local, fd, arg_compress);
        if (r < 0)
                return log_error_errno(r, "Failed to export image: %m");

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
               "%sExport disk images.%s\n"
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
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("format", "FORMAT", "Select format"):
                        arg_compress = compression_from_string_harder(opts.arg);
                        if (arg_compress < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", opts.arg);
                        break;

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

        if (arg_runtime_scope == RUNTIME_SCOPE_USER)
                arg_import_flags |= IMPORT_FOREIGN_UID;

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

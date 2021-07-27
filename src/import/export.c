/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "discover-image.h"
#include "export-raw.h"
#include "export-tar.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-util.h"
#include "main-func.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"

static ImportCompressType arg_compress = IMPORT_COMPRESS_UNKNOWN;

static void determine_compression_from_filename(const char *p) {

        if (arg_compress != IMPORT_COMPRESS_UNKNOWN)
                return;

        if (!p) {
                arg_compress = IMPORT_COMPRESS_UNCOMPRESSED;
                return;
        }

        if (endswith(p, ".xz"))
                arg_compress = IMPORT_COMPRESS_XZ;
        else if (endswith(p, ".gz"))
                arg_compress = IMPORT_COMPRESS_GZIP;
        else if (endswith(p, ".bz2"))
                arg_compress = IMPORT_COMPRESS_BZIP2;
        else
                arg_compress = IMPORT_COMPRESS_UNCOMPRESSED;
}

static int interrupt_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        log_notice("Transfer aborted.");
        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static void on_tar_finished(TarExport *export, int error, void *userdata) {
        sd_event *event = userdata;
        assert(export);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
}

static int export_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(tar_export_unrefp) TarExport *export = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -1;
        int r, fd;

        if (hostname_is_valid(argv[1], 0)) {
                r = image_find(IMAGE_MACHINE, argv[1], NULL, &image);
                if (r == -ENOENT)
                        return log_error_errno(r, "Machine image %s not found.", argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to look for machine %s: %m", argv[1]);

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

                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, path, import_compress_type_to_string(arg_compress));
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDOUT_FILENO;

                (void) fd_get_path(fd, &pretty);
                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, strna(pretty), import_compress_type_to_string(arg_compress));
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = tar_export_new(&export, event, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate exporter: %m");

        r = tar_export_start(export, local, fd, arg_compress);
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

        sd_event_exit(event, abs(error));
}

static int export_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(raw_export_unrefp) RawExport *export = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_close_ int open_fd = -1;
        int r, fd;

        if (hostname_is_valid(argv[1], 0)) {
                r = image_find(IMAGE_MACHINE, argv[1], NULL, &image);
                if (r == -ENOENT)
                        return log_error_errno(r, "Machine image %s not found.", argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to look for machine %s: %m", argv[1]);

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

                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, path, import_compress_type_to_string(arg_compress));
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDOUT_FILENO;

                (void) fd_get_path(fd, &pretty);
                log_info("Exporting '%s', saving to '%s' with compression '%s'.", local, strna(pretty), import_compress_type_to_string(arg_compress));
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

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

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Export container or virtual machine images.\n\n"
               "  -h --help                    Show this help\n"
               "     --version                 Show package version\n"
               "     --format=FORMAT           Select format\n\n"
               "Commands:\n"
               "  tar NAME [FILE]              Export a TAR image\n"
               "  raw NAME [FILE]              Export a RAW image\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORMAT,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'         },
                { "version", no_argument,       NULL, ARG_VERSION },
                { "format",  required_argument, NULL, ARG_FORMAT  },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_FORMAT:
                        if (streq(optarg, "uncompressed"))
                                arg_compress = IMPORT_COMPRESS_UNCOMPRESSED;
                        else if (streq(optarg, "xz"))
                                arg_compress = IMPORT_COMPRESS_XZ;
                        else if (streq(optarg, "gzip"))
                                arg_compress = IMPORT_COMPRESS_GZIP;
                        else if (streq(optarg, "bzip2"))
                                arg_compress = IMPORT_COMPRESS_BZIP2;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", optarg);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int export_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, help       },
                { "tar",  2,        3,        0, export_tar },
                { "raw",  2,        3,        0, export_raw },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return export_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);

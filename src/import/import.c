/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <getopt.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-raw.h"
#include "import-tar.h"
#include "import-util.h"
#include "machine-image.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"

static bool arg_force = false;
static bool arg_read_only = false;
static const char *arg_image_root = "/var/lib/machines";

static int interrupt_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        log_notice("Transfer aborted.");
        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static void on_tar_finished(TarImport *import, int error, void *userdata) {
        sd_event *event = userdata;
        assert(import);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
}

static int import_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(tar_import_unrefp) TarImport *import = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_free_ char *ll = NULL;
        _cleanup_close_ int open_fd = -1;
        int r, fd;

        if (argc >= 2)
                path = argv[1];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (argc >= 3)
                local = argv[2];
        else if (path)
                local = basename(path);
        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                r = tar_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!machine_name_is_valid(local)) {
                        log_error("Local image name '%s' is not valid.", local);
                        return -EINVAL;
                }

                if (!arg_force) {
                        r = image_find(local, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        else if (r > 0) {
                                log_error_errno(EEXIST, "Image '%s' already exists.", local);
                                return -EEXIST;
                        }
                }
        } else
                local = "imported";

        if (path) {
                open_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open tar image to import: %m");

                fd = open_fd;

                log_info("Importing '%s', saving as '%s'.", path, local);
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDIN_FILENO;

                (void) readlink_malloc("/proc/self/fd/0", &pretty);
                log_info("Importing '%s', saving as '%s'.", strna(pretty), local);
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = tar_import_new(&import, event, arg_image_root, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = tar_import_start(import, fd, local, arg_force, arg_read_only);
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

        sd_event_exit(event, abs(error));
}

static int import_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(raw_import_unrefp) RawImport *import = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *path = NULL, *local = NULL;
        _cleanup_free_ char *ll = NULL;
        _cleanup_close_ int open_fd = -1;
        int r, fd;

        if (argc >= 2)
                path = argv[1];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (argc >= 3)
                local = argv[2];
        else if (path)
                local = basename(path);
        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                r = raw_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!machine_name_is_valid(local)) {
                        log_error("Local image name '%s' is not valid.", local);
                        return -EINVAL;
                }

                if (!arg_force) {
                        r = image_find(local, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        else if (r > 0) {
                                log_error_errno(EEXIST, "Image '%s' already exists.", local);
                                return -EEXIST;
                        }
                }
        } else
                local = "imported";

        if (path) {
                open_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open raw image to import: %m");

                fd = open_fd;

                log_info("Importing '%s', saving as '%s'.", path, local);
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDIN_FILENO;

                (void) readlink_malloc("/proc/self/fd/0", &pretty);
                log_info("Importing '%s', saving as '%s'.", pretty, local);
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = raw_import_new(&import, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = raw_import_start(import, fd, local, arg_force, arg_read_only);
        if (r < 0)
                return log_error_errno(r, "Failed to import image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Import container or virtual machine images.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --image-root=PATH        Image root directory\n"
               "     --read-only              Create a read-only image\n\n"
               "Commands:\n"
               "  tar FILE [NAME]             Import a TAR image\n"
               "  raw FILE [NAME]             Import a RAW image\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_IMAGE_ROOT,
                ARG_READ_ONLY,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
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

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int import_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, help       },
                { "tar",  2,        3,        0, import_tar },
                { "raw",  2,        3,        0, import_raw },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

int main(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        (void) ignore_signals(SIGPIPE, -1);

        r = import_main(argc, argv);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

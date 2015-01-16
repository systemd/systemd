/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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
#include "event-util.h"
#include "verbs.h"
#include "build.h"
#include "import-raw.h"
#include "import-dkr.h"

static bool arg_force = false;
static const char *arg_image_root = "/var/lib/machines";

static const char* arg_dkr_index_url = DEFAULT_DKR_INDEX_URL;

static void on_raw_finished(RawImport *import, int error, void *userdata) {
        sd_event *event = userdata;
        assert(import);

        if (error == 0)
                log_info("Operation completed successfully.");
        else
                log_info_errno(error, "Operation failed: %m");

        sd_event_exit(event, error);
}

static int pull_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(raw_import_unrefp) RawImport *import = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *url, *local, *suffix;
        int r;

        url = argv[1];
        if (!raw_url_is_valid(url)) {
                log_error("URL '%s' is not valid.", url);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                const char *e, *p;

                e = url + strlen(url);
                while (e > url && e[-1] == '/')
                        e--;

                p = e;
                while (p > url && p[-1] != '/')
                        p--;

                local = strndupa(p, e - p);
        }

        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                const char *p;

                suffix = endswith(local, ".raw.xz");
                if (!suffix)
                        suffix = endswith(local, ".raw");
                if (!suffix)
                        suffix = endswith(local, ".xz");
                if (suffix)
                        local = strndupa(local, suffix - local);

                if (!machine_name_is_valid(local)) {
                        log_error("Local image name '%s' is not valid.", local);
                        return -EINVAL;
                }

                p = strappenda(arg_image_root, "/", local, ".raw");
                if (laccess(p, F_OK) >= 0) {
                        if (!arg_force) {
                                log_info("Image '%s' already exists.", local);
                                return 0;
                        }
                } else if (errno != ENOENT)
                        return log_error_errno(errno, "Can't check if image '%s' already exists: %m", local);

                log_info("Pulling '%s', saving as '%s'.", url, local);
        } else
                log_info("Pulling '%s'.", url);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, SIGTERM, SIGINT, -1) == 0);
        sd_event_add_signal(event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        r = raw_import_new(&import, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = raw_import_pull(import, url, local, arg_force);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");

        return 0;
}

static void on_dkr_finished(DkrImport *import, int error, void *userdata) {
        sd_event *event = userdata;
        assert(import);

        if (error == 0)
                log_info("Operation completed successfully.");
        else
                log_info_errno(error, "Operation failed: %m");

        sd_event_exit(event, error);
}

static int pull_dkr(int argc, char *argv[], void *userdata) {
        _cleanup_(dkr_import_unrefp) DkrImport *import = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *name, *tag, *local;
        int r;

        if (!arg_dkr_index_url) {
                log_error("Please specify an index URL with --dkr-index-url=");
                return -EINVAL;
        }

        tag = strchr(argv[1], ':');
        if (tag) {
                name = strndupa(argv[1], tag - argv[1]);
                tag++;
        } else {
                name = argv[1];
                tag = "latest";
        }

        if (!dkr_name_is_valid(name)) {
                log_error("Remote name '%s' is not valid.", name);
                return -EINVAL;
        }

        if (!dkr_tag_is_valid(tag)) {
                log_error("Tag name '%s' is not valid.", tag);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                local = strchr(name, '/');
                if (local)
                        local++;
                else
                        local = name;
        }

        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                const char *p;

                if (!machine_name_is_valid(local)) {
                        log_error("Local image name '%s' is not valid.", local);
                        return -EINVAL;
                }

                p = strappenda(arg_image_root, "/", local);
                if (laccess(p, F_OK) >= 0) {
                        if (!arg_force) {
                                log_info("Image '%s' already exists.", local);
                                return 0;
                        }
                } else if (errno != ENOENT)
                        return log_error_errno(errno, "Can't check if image '%s' already exists: %m", local);

                log_info("Pulling '%s' with tag '%s', saving as '%s'.", name, tag, local);
        } else
                log_info("Pulling '%s' with tag '%s'.", name, tag);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, SIGTERM, SIGINT, -1) == 0);
        sd_event_add_signal(event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);

        r = dkr_import_new(&import, event, arg_dkr_index_url, arg_image_root, on_dkr_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate importer: %m");

        r = dkr_import_pull(import, name, tag, local, arg_force);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Import container or virtual machine image.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --image-root=            Image root directory\n"
               "     --dkr-index-url=URL      Specify index URL to use for downloads\n\n"
               "Commands:\n"
               "  pull-dkr REMOTE [NAME]      Download a DKR image\n"
               "  pull-raw URL [NAME]         Download a RAW image\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_DKR_INDEX_URL,
                ARG_IMAGE_ROOT,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "dkr-index-url",   required_argument, NULL, ARG_DKR_INDEX_URL   },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
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
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_DKR_INDEX_URL:
                        if (!dkr_url_is_valid(optarg)) {
                                log_error("Index URL is not valid: %s", optarg);
                                return -EINVAL;
                        }

                        arg_dkr_index_url = optarg;
                        break;

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
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
                { "help",     VERB_ANY, VERB_ANY, 0, help     },
                { "pull-dkr", 2,        3,        0, pull_dkr },
                { "pull-raw", 2,        3,        0, pull_raw },
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

        r = import_main(argc, argv);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

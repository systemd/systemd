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

#include "alloc-util.h"
#include "event-util.h"
#include "hostname-util.h"
#include "import-util.h"
#include "machine-image.h"
#include "parse-util.h"
#include "pull-dkr.h"
#include "pull-raw.h"
#include "pull-tar.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"
#include "web-util.h"

static bool arg_force = false;
static const char *arg_image_root = "/var/lib/machines";
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static const char* arg_dkr_index_url = DEFAULT_DKR_INDEX_URL;
static bool arg_settings = true;

static int interrupt_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        log_notice("Transfer aborted.");
        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static void on_tar_finished(TarPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
}

static int pull_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(tar_pull_unrefp) TarPull *pull = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *url, *local;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        int r;

        url = argv[1];
        if (!http_url_is_valid(url)) {
                log_error("URL '%s' is not valid.", url);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(url, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed get final component of URL: %m");

                local = l;
        }

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

                log_info("Pulling '%s', saving as '%s'.", url, local);
        } else
                log_info("Pulling '%s'.", url);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = tar_pull_new(&pull, event, arg_image_root, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = tar_pull_start(pull, url, local, arg_force, arg_verify, arg_settings);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_raw_finished(RawPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
}

static int pull_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(raw_pull_unrefp) RawPull *pull = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *url, *local;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        int r;

        url = argv[1];
        if (!http_url_is_valid(url)) {
                log_error("URL '%s' is not valid.", url);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(url, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed get final component of URL: %m");

                local = l;
        }

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

                log_info("Pulling '%s', saving as '%s'.", url, local);
        } else
                log_info("Pulling '%s'.", url);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = raw_pull_new(&pull, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = raw_pull_start(pull, url, local, arg_force, arg_verify, arg_settings);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_dkr_finished(DkrPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
}

static int pull_dkr(int argc, char *argv[], void *userdata) {
        _cleanup_(dkr_pull_unrefp) DkrPull *pull = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        const char *name, *reference, *local, *digest;
        int r;

        if (!arg_dkr_index_url) {
                log_error("Please specify an index URL with --dkr-index-url=");
                return -EINVAL;
        }

        if (arg_verify != IMPORT_VERIFY_NO) {
                log_error("Pulls from dkr do not support image verification, please pass --verify=no.");
                return -EINVAL;
        }

        digest = strchr(argv[1], '@');
        if (digest) {
                reference = digest + 1;
                name = strndupa(argv[1], digest - argv[1]);
        } else {
                reference = strchr(argv[1], ':');
                if (reference) {
                        name = strndupa(argv[1], reference - argv[1]);
                        reference++;
                } else {
                        name = argv[1];
                        reference = "latest";
                }
        }

        if (!dkr_name_is_valid(name)) {
                log_error("Remote name '%s' is not valid.", name);
                return -EINVAL;
        }

        if (!dkr_ref_is_valid(reference)) {
                log_error("Tag name '%s' is not valid.", reference);
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

                log_info("Pulling '%s' with reference '%s', saving as '%s'.", name, reference, local);
        } else
                log_info("Pulling '%s' with reference '%s'.", name, reference);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        (void) sd_event_add_signal(event, NULL, SIGTERM, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT, interrupt_signal_handler, NULL);

        r = dkr_pull_new(&pull, event, arg_dkr_index_url, arg_image_root, on_dkr_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = dkr_pull_start(pull, name, reference, local, arg_force, DKR_PULL_V2);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Download container or virtual machine images.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --verify=MODE            Verify downloaded image, one of: 'no',\n"
               "                              'checksum', 'signature'\n"
               "     --settings=BOOL          Download settings file with image\n"
               "     --image-root=PATH        Image root directory\n"
               "     --dkr-index-url=URL      Specify index URL to use for downloads\n\n"
               "Commands:\n"
               "  tar URL [NAME]              Download a TAR image\n"
               "  raw URL [NAME]              Download a RAW image\n"
               "  dkr REMOTE [NAME]           Download a DKR image\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_DKR_INDEX_URL,
                ARG_IMAGE_ROOT,
                ARG_VERIFY,
                ARG_SETTINGS,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "dkr-index-url",   required_argument, NULL, ARG_DKR_INDEX_URL   },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
                { "verify",          required_argument, NULL, ARG_VERIFY          },
                { "settings",        required_argument, NULL, ARG_SETTINGS        },
                {}
        };

        int c, r;

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

                case ARG_DKR_INDEX_URL:
                        if (!http_url_is_valid(optarg)) {
                                log_error("Index URL is not valid: %s", optarg);
                                return -EINVAL;
                        }

                        arg_dkr_index_url = optarg;
                        break;

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
                        break;

                case ARG_VERIFY:
                        arg_verify = import_verify_from_string(optarg);
                        if (arg_verify < 0) {
                                log_error("Invalid verification setting '%s'", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_SETTINGS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --settings= parameter '%s'", optarg);

                        arg_settings = r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int pull_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, help     },
                { "tar",  2,        3,        0, pull_tar },
                { "raw",  2,        3,        0, pull_raw },
                { "dkr",  2,        3,        0, pull_dkr },
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

        r = pull_main(argc, argv);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <locale.h>

#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "hostname-util.h"
#include "import-util.h"
#include "machine-image.h"
#include "main-func.h"
#include "parse-util.h"
#include "pull-raw.h"
#include "pull-tar.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"
#include "web-util.h"

static bool arg_force = false;
static const char *arg_image_root = "/var/lib/machines";
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static bool arg_settings = true;
static bool arg_roothash = true;

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
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
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

        local = empty_or_dash_to_null(local);

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
                        r = image_find(IMAGE_MACHINE, local, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else {
                                log_error("Image '%s' already exists.", local);
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
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
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

        local = empty_or_dash_to_null(local);

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
                        r = image_find(IMAGE_MACHINE, local, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else {
                                log_error("Image '%s' already exists.", local);
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

        r = raw_pull_start(pull, url, local, arg_force, arg_verify, arg_settings, arg_roothash);
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
               "     --roothash=BOOL          Download root hash file with image\n"
               "     --image-root=PATH        Image root directory\n\n"
               "Commands:\n"
               "  tar URL [NAME]              Download a TAR image\n"
               "  raw URL [NAME]              Download a RAW image\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_IMAGE_ROOT,
                ARG_VERIFY,
                ARG_SETTINGS,
                ARG_ROOTHASH,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
                { "verify",          required_argument, NULL, ARG_VERIFY          },
                { "settings",        required_argument, NULL, ARG_SETTINGS        },
                { "roothash",        required_argument, NULL, ARG_ROOTHASH        },
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

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
                        break;

                case ARG_VERIFY:
                        arg_verify = import_verify_from_string(optarg);
                        if (arg_verify < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid verification setting '%s'", optarg);

                        break;

                case ARG_SETTINGS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --settings= parameter '%s': %m", optarg);

                        arg_settings = r;
                        break;

                case ARG_ROOTHASH:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --roothash= parameter '%s': %m", optarg);

                        arg_roothash = r;
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

        (void) ignore_signals(SIGPIPE, -1);

        return pull_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);

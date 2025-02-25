/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-json.h"

#include "ansi-color.h"
#include "build.h"
#include "device-util.h"
#include "efivars.h"
#include "factory-reset.h"
#include "fs-util.h"
#include "main-func.h"
#include "os-util.h"
#include "pretty-print.h"
#include "verbs.h"

static bool arg_retrigger = false;
static bool arg_quiet = false;

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-bless-boot.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND\n"
               "\n%5$sQuery, request, cancel factory reset operation.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  status             Report current factory reset status\n"
               "  request            Request a factory reset on next boot\n"
               "  cancel             Cancel a prior factory reset request for next boot\n"
               "  complete           Mark a factory reset as complete\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --retrigger     Retrigger block devices\n"
               "  -q --quiet         Suppress output\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PATH = 0x100,
                ARG_VERSION,
                ARG_RETRIGGER,
        };

        static const struct option options[] = {
                { "help",      no_argument, NULL, 'h'           },
                { "version",   no_argument, NULL, ARG_VERSION   },
                { "retrigger", no_argument, NULL, ARG_RETRIGGER },
                { "quiet",     no_argument, NULL, 'q'           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hq", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_RETRIGGER:
                        arg_retrigger = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int verb_status(int argc, char *argv[], void *userdata) {
        enum {
                /* Report current mode also as via exit status, but only return a subset of states */
                EXIT_OFF     = EXIT_SUCCESS,
                EXIT_ON      = 10,
                EXIT_PENDING = 11,
        };

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine factory reset mode: %m");

        if (!arg_quiet)
                puts(factory_reset_mode_to_string(f));

        return f == FACTORY_RESET_ON ? EXIT_ON :
                f == FACTORY_RESET_PENDING ? EXIT_PENDING : EXIT_OFF;
}

static int verb_request(int argc, char *argv[], void *userdata) {
        int r;

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine current factory reset mode: %m");
        if (f == FACTORY_RESET_ON)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "System currently in factory reset mode, refusing to request another one.");
        if (f == FACTORY_RESET_PENDING) {
                log_info("Factory request already requested, skipping.");
                return 0;
        }

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Not an EFI boot, requesting factory reset via EFI variable not supported.");

        _cleanup_free_ char *id = NULL, *image_id = NULL, *version_id = NULL, *image_version = NULL;
        r = parse_os_release(
                        /* root= */ NULL,
                        "ID", &id,
                        "IMAGE_ID", &image_id,
                        "VERSION_ID", &version_id,
                        "IMAGE_VERSION", &image_version);
        if (r < 0)
                return log_error_errno(r, "Failed to parse os-release: %m");

        if (!id)
                return log_error_errno(SYNTHETIC_ERRNO(EBADR), "os-release data lacks ID= field, refusing.");

        sd_id128_t boot_id;
        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("osReleaseId", id),
                        SD_JSON_BUILD_PAIR_CONDITION(!!version_id, "osReleaseVersionId", SD_JSON_BUILD_STRING(version_id)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!image_id, "osReleaseImageId", SD_JSON_BUILD_STRING(image_id)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!image_version, "osReleaseImageVersion", SD_JSON_BUILD_STRING(image_version)),
                        SD_JSON_BUILD_PAIR_ID128("bootId", boot_id));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        _cleanup_free_ char *formatted = NULL;
        r = sd_json_variant_format(v, /* flags= */ 0, &formatted);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON object: %m");

        r = efi_set_variable_string(EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"), formatted);
        if (r < 0)
                return log_error_errno(r, "Failed to set EFI variable FactoryResetRequest: %m");

        log_debug("Set EFI variable FactoryResetRequest to '%s'.", formatted);

        if (!arg_quiet)
                log_info("Factory reset requested.");

        return 0;
}

static int verb_cancel(int argc, char *argv[], void *userdata) {
        int r;

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine current factory reset mode: %m");
        if (f == FACTORY_RESET_ON)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "System already executing factory reset, cannot cancel.");
        if (f != FACTORY_RESET_PENDING) {
                log_info("No factory reset has been requested, cannot cancel, skipping.");
                return 0;
        }

        if (!is_efi_boot()) {
                if (!arg_quiet)
                        log_info("Not an EFI boot, cannot remove FactoryResetMode EFI variable, not cancelling.");

                return 0;
        }

        r = efi_set_variable(EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"), /* value= */ NULL, /* size= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to remove FactoryResetRequest EFI variable: %m");

        if (!arg_quiet)
                log_info("Factory reset cancelled.");

        return 0;
}

static int retrigger_block_devices(void) {
        int r;

        /* Let's retrigger block devices after factory reset is complete: it's quite likely that some
         * partitions went away or got recreated, and will only be considered relevant once factory reset
         * mode is left. For example, /dev/disk/gpt-auto-root is like that: it is only created once factory
         * reset mode is complete. */

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to enable enumeration of uninitialized devices: %m");

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match = */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to filter device enumeration by 'block' subsystem: %m");

        if (!arg_quiet)
                log_info("Retriggering block devices.");

        FOREACH_DEVICE(e, d) {
                r = sd_device_trigger(d, SD_DEVICE_CHANGE);
                if (r < 0)
                        log_device_debug_errno(d, r, "Failed to trigger block device, ignoring: %m");
        }

        return 0;
}

static int verb_complete(int argc, char *argv[], void *userdata) {
        int r;

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to dermine factory reset state: %m");
        log_debug("Current factory state is: %s", factory_reset_mode_to_string(f));
        if (f != FACTORY_RESET_ON) {
                log_info("Attempted to leave factory reset mode, even though we are not in factory reset mode. Ignoring.");
                return 0;
        }

        r = efi_set_variable(EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"), /* value= */ NULL, /* size= */ 0);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to remove FactoryResetRequest EFI variable: %m");

        r = touch("/run/systemd/factory-reset-complete");
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/factory-reset-complete file: %m");

        if (!arg_quiet)
                log_info("Successfully left factory reset mode.");

        if (arg_retrigger)
                (void) retrigger_block_devices();

        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "status",   VERB_ANY, 1, VERB_DEFAULT, verb_status   },
                { "request",  VERB_ANY, 1, 0,            verb_request  },
                { "cancel",   VERB_ANY, 1, 0,            verb_cancel   },
                { "complete", VERB_ANY, 1, 0,            verb_complete },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);

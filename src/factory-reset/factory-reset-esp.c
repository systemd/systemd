/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "bootspec.h"
#include "build.h"
#include "chase.h"
#include "devnum-util.h"
#include "factory-reset.h"
#include "find-esp.h"
#include "log.h"
#include "main-func.h"
#include "os-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"

bool arg_dry_run = false;

static int find_boot_paths(char **ret_esp, char **ret_xbootldr) {
        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        r = find_esp_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &esp_path,
                              NULL, NULL, NULL, NULL, &esp_devid);
        if (r < 0)
                return r;

        r = find_xbootldr_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &xbootldr_path,
                                   NULL, &xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r;

        if (esp_path && xbootldr_path && devnum_set_and_equal(esp_devid, xbootldr_devid))
                xbootldr_path = mfree(xbootldr_path);

        *ret_esp = TAKE_PTR(esp_path);
        *ret_xbootldr = TAKE_PTR(xbootldr_path);
        return 0;
}

static int delete_dir(char *path) {
        int r;

        _cleanup_free_ char *canonical = NULL;
        struct stat st;
        r = chase_and_stat(path, NULL, CHASE_NOFOLLOW, &canonical, &st);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase %s: %m", path);

        r = stat_verify_directory(&st);
        if (r < 0)
                return r;

        if (arg_dry_run) {
                log_info("Would delete: %s", canonical);
                return 0;
        }

        return rm_rf(canonical, REMOVE_PHYSICAL|REMOVE_ROOT|REMOVE_CHMOD);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-factory-reset-esp.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%5$sDelete non-vendor contents from ESP and XBOOTLDR.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "     --dry-run       Don't take destructive action\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
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
                ARG_DRY_RUN = 0x100,
                ARG_VERSION,
        };

        static const struct option options[] = {
                { "dry-run",   no_argument, NULL, ARG_DRY_RUN,  },
                { "help",      no_argument, NULL, 'h'           },
                { "version",   no_argument, NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!arg_dry_run) {
                FactoryResetMode f = factory_reset_mode();
                if (f < 0)
                        return log_error_errno(f, "Failed to determine factory reset mode: %m");
                if (f != FACTORY_RESET_PENDING && f != FACTORY_RESET_ON) {
                        log_warning("We are currently not in factory reset mode. Enabling dry run");
                        arg_dry_run = true;
                }
        }

        _cleanup_free_ char *os_id = NULL, *image_id = NULL;
        r = parse_os_release(
                        /* root= */ NULL,
                        "ID", &os_id,
                        "IMAGE_ID", &image_id);
        if (r < 0)
                return log_error_errno(r, "Failed to parse os-release: %m");

        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        r = find_boot_paths(&esp_path, &xbootldr_path);
        if (r < 0)
                return log_error_errno(r, "Failed to find boot paths: %m");

        _cleanup_(boot_config_free) BootConfig bc = BOOT_CONFIG_NULL;
        r = boot_config_load(&bc, esp_path, xbootldr_path);
        if (r < 0)
                return log_error_errno(r, "Failed to load boot config: %m");

        bool found_our_uki = false;
        bool found_foreign_uki = false;
        FOREACH_ARRAY(entry, bc.entries, bc.n_entries) {
                if (entry->type != BOOT_ENTRY_TYPE2)
                        continue;

                if (!streq_ptr(entry->os_id, os_id) || !streq_ptr(entry->os_image_id, image_id)) {
                        log_debug("Ignoring foreign UKI: %s (%s)\n", entry->id, entry->path);
                        found_foreign_uki = true;
                        continue;
                }
                found_our_uki = true;

                log_debug("Cleaning up UKI: %s (%s)\n", entry->id, entry->path);

                _cleanup_free_ char *dropin_dir = strjoin(entry->path, ".extra.d");
                r = delete_dir(dropin_dir);
                if (r == -ENOENT) {
                        log_debug("UKI %s doesn't have a drop-in dir, skipping", entry->id);
                        continue;
                }
                if (r < 0)
                        log_error_errno(r, "Failed to delete drop-in dir %s, skipping: %m", dropin_dir);
        }

        if (!found_our_uki) {
                log_debug("Didn't find a UKI belonging to us, so there's nothing to do.");
                return 0;
        }

        if (found_foreign_uki) {
                log_warning("Found another installed OS that uses UKIs. Keeping global search paths");
                return 0;
        }

        // TODO: Wipe the global addons
        // TODO: Wipe the global credentials
        // TODO: Wipe the global sysexts + confexts

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

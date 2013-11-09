/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <sys/timex.h>

#include "boot.h"
#include "build.h"
#include "util.h"
#include "utf8.h"

static int help(void) {

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change firmware and boot manager settings.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "Commands:\n"
               "  status                 Show current boot settings\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int boot_info_new(struct boot_info **info) {
        struct boot_info *in;
        int err;

        in = new0(struct boot_info, 1);
        if (!in)
                return -ENOMEM;

        err = sd_id128_get_machine(&in->machine_id);
        if (err < 0)
                goto err;

        err = sd_id128_get_boot(&in->boot_id);
        if (err < 0)
                goto err;

        in->fw_entry_active = -1;
        in->loader_entry_active = -1;

        *info = in;
        return 0;
err:
        free(in);
        return err;
}

static void boot_info_entries_free(struct boot_info_entry *entries, size_t n) {
        size_t i;

        for (i = 0; i < n; i++) {
                free(entries[i].title);
                free(entries[i].path);
        }
        free(entries);
}

static void boot_info_free(struct boot_info *info) {
        free(info->fw_type);
        free(info->fw_info);
        boot_info_entries_free(info->fw_entries, info->fw_entries_count);
        free(info->fw_entries_order);
        free(info->loader);
        free(info->loader_image_path);
        free(info->loader_options_added);
        boot_info_entries_free(info->loader_entries, info->loader_entries_count);
        free(info);
}

static int show_status(char **args, unsigned n) {
        char buf[64];
        struct boot_info *info;
        int err;

        err = boot_info_new(&info);
        if (err < 0)
                return -ENOMEM;

        err = boot_info_query(info);

        printf("System:\n");
        printf("   Machine ID: %s\n", sd_id128_to_string(info->machine_id, buf));
        printf("      Boot ID: %s\n", sd_id128_to_string(info->boot_id, buf));
        if (info->fw_type)
                printf("     Firmware: %s (%s)\n", info->fw_type, strna(info->fw_info));
        if (info->fw_secure_boot >= 0)
                printf("  Secure Boot: %s\n", info->fw_secure_boot ? "enabled" : "disabled");
        if (info->fw_secure_boot_setup_mode >= 0)
                printf("   Setup Mode: %s\n", info->fw_secure_boot_setup_mode ? "setup" : "user");
        printf("\n");

        if (info->fw_entry_active >= 0) {
                printf("Selected Firmware Entry:\n");
                printf("        Title: %s\n", strna(info->fw_entries[info->fw_entry_active].title));
                if (!sd_id128_equal(info->fw_entries[info->fw_entry_active].part_uuid, SD_ID128_NULL))
                        printf("    Partition: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                               SD_ID128_FORMAT_VAL(info->fw_entries[info->fw_entry_active].part_uuid));
                else
                        printf("    Partition: n/a\n");
                if (info->fw_entries[info->fw_entry_active].path)
                        printf("         File: %s%s\n", draw_special_char(DRAW_TREE_RIGHT), info->fw_entries[info->fw_entry_active].path);
        }
        printf("\n");

        if (info->loader) {
                printf("Boot Loader:\n");
                printf("      Product: %s\n", info->loader);
                if (!sd_id128_equal(info->loader_part_uuid, SD_ID128_NULL))
                        printf("    Partition: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                               SD_ID128_FORMAT_VAL(info->loader_part_uuid));
                        else
                                printf("    Partition: n/a\n");
                printf("         File: %s%s\n", draw_special_char(DRAW_TREE_RIGHT), strna(info->loader_image_path));
                printf("\n");

                if (info->loader_entry_active >= 0) {
                        printf("Selected Boot Loader Entry:\n");
                        printf("        Title: %s\n", strna(info->loader_entries[info->loader_entry_active].title));
                        printf("         File: %s\n", info->loader_entries[info->loader_entry_active].path);
                        if (info->loader_options_added)
                                printf("      Options: %s\n", info->loader_options_added);
                }
        } else
                printf("No suitable data is provided by the boot manager. See:\n"
                       "  http://www.freedesktop.org/wiki/Software/systemd/BootLoaderInterface\n"
                       "  http://www.freedesktop.org/wiki/Specifications/BootLoaderSpec\n"
                       "for details.\n");
        printf("\n");

        boot_info_free(info);
        return err;
}

static int bootctl_main(int argc, char *argv[]) {
        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(char **args, unsigned n);
        } verbs[] = {
                { "status",                LESS,   1, show_status      },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "status" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }
                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }
                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }
                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        return verbs[i].dispatch(argv + optind, left);
}

int main(int argc, char *argv[]) {
        int r, retval = EXIT_FAILURE;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        r = bootctl_main(argc, argv);
        retval = r < 0 ? EXIT_FAILURE : r;
finish:
        return retval;
}

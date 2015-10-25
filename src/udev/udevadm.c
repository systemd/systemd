/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
/*
 * Copyright (C) 2007-2012 Kay Sievers <kay@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>

#include "selinux-util.h"
#include "string-util.h"
#include "udev.h"

static int adm_version(struct udev *udev, int argc, char *argv[]) {
        printf("%s\n", VERSION);
        return 0;
}

static const struct udevadm_cmd udevadm_version = {
        .name = "version",
        .cmd = adm_version,
};

static int adm_help(struct udev *udev, int argc, char *argv[]);

static const struct udevadm_cmd udevadm_help = {
        .name = "help",
        .cmd = adm_help,
};

static const struct udevadm_cmd *udevadm_cmds[] = {
        &udevadm_info,
        &udevadm_trigger,
        &udevadm_settle,
        &udevadm_control,
        &udevadm_monitor,
        &udevadm_hwdb,
        &udevadm_test,
        &udevadm_test_builtin,
        &udevadm_version,
        &udevadm_help,
};

static int adm_help(struct udev *udev, int argc, char *argv[]) {
        unsigned int i;

        printf("%s [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n\n"
               "Send control commands or test the device manager.\n\n"
               "Commands:\n"
               , program_invocation_short_name);

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                if (udevadm_cmds[i]->help != NULL)
                        printf("  %-12s  %s\n", udevadm_cmds[i]->name, udevadm_cmds[i]->help);
        return 0;
}

static int run_command(struct udev *udev, const struct udevadm_cmd *cmd, int argc, char *argv[]) {
        if (cmd->debug)
                log_set_max_level(LOG_DEBUG);
        log_debug("calling: %s", cmd->name);
        return cmd->cmd(udev, argc, argv);
}

int main(int argc, char *argv[]) {
        struct udev *udev;
        static const struct option options[] = {
                { "debug", no_argument, NULL, 'd' },
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                {}
        };
        const char *command;
        unsigned int i;
        int rc = 1, c;

        udev = udev_new();
        if (udev == NULL)
                goto out;

        log_parse_environment();
        log_open();
        mac_selinux_init("/dev");

        while ((c = getopt_long(argc, argv, "+dhV", options, NULL)) >= 0)
                switch (c) {

                case 'd':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        rc = adm_help(udev, argc, argv);
                        goto out;

                case 'V':
                        rc = adm_version(udev, argc, argv);
                        goto out;

                default:
                        goto out;
                }

        command = argv[optind];

        if (command != NULL)
                for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                        if (streq(udevadm_cmds[i]->name, command)) {
                                argc -= optind;
                                argv += optind;
                                /* we need '0' here to reset the internal state */
                                optind = 0;
                                rc = run_command(udev, udevadm_cmds[i], argc, argv);
                                goto out;
                        }

        fprintf(stderr, "%s: missing or unknown command\n", program_invocation_short_name);
        rc = 2;
out:
        mac_selinux_finish();
        udev_unref(udev);
        log_close();
        return rc;
}

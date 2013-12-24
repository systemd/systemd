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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "udev.h"

void udev_main_log(struct udev *udev, int priority,
                   const char *file, int line, const char *fn,
                   const char *format, va_list args)
{
        log_metav(priority, file, line, fn, format, args);
}

static int adm_version(struct udev *udev, int argc, char *argv[])
{
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

static int adm_help(struct udev *udev, int argc, char *argv[])
{
        unsigned int i;

        fprintf(stderr, "Usage: udevadm [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n");
        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                if (udevadm_cmds[i]->help != NULL)
                        printf("  %-12s %s\n", udevadm_cmds[i]->name, udevadm_cmds[i]->help);
        fprintf(stderr, "\n");
        return 0;
}

static int run_command(struct udev *udev, const struct udevadm_cmd *cmd, int argc, char *argv[])
{
        if (cmd->debug)
                log_set_max_level(LOG_DEBUG);
        log_debug("calling: %s", cmd->name);
        return cmd->cmd(udev, argc, argv);
}

int main(int argc, char *argv[])
{
        struct udev *udev;
        static const struct option options[] = {
                { "debug", no_argument, NULL, 'd' },
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                {}
        };
        const char *command;
        unsigned int i;
        int rc = 1;

        udev = udev_new();
        if (udev == NULL)
                goto out;

        log_parse_environment();
        log_open();
        udev_set_log_fn(udev, udev_main_log);
        label_init("/dev");

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "+dhV", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'd':
                        log_set_max_level(LOG_DEBUG);
                        udev_set_log_priority(udev, LOG_DEBUG);
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
        }
        command = argv[optind];

        if (command != NULL)
                for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++) {
                        if (streq(udevadm_cmds[i]->name, command)) {
                                argc -= optind;
                                argv += optind;
                                /* we need '0' here to reset the internal state */
                                optind = 0;
                                rc = run_command(udev, udevadm_cmds[i], argc, argv);
                                goto out;
                        }
                }

        fprintf(stderr, "missing or unknown command\n\n");
        adm_help(udev, argc, argv);
        rc = 2;
out:
        label_finish();
        udev_unref(udev);
        log_close();
        return rc;
}

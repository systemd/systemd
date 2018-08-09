/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>

#include "selinux-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "udev.h"

static int adm_version(struct udev *udev, int argc, char *argv[]) {
        printf("%s\n", PACKAGE_VERSION);
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
        _cleanup_free_ char *link = NULL;
        size_t i;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n\n"
               "Send control commands or test the device manager.\n\n"
               "Commands:\n"
               , program_invocation_short_name);

        for (i = 0; i < ELEMENTSOF(udevadm_cmds); i++)
                if (udevadm_cmds[i]->help != NULL)
                        printf("  %-12s  %s\n", udevadm_cmds[i]->name, udevadm_cmds[i]->help);

        printf("\nSee the %s for details.\n", link);
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

        udev_parse_config();
        log_parse_environment();
        log_open();

        mac_selinux_init();

        udev = udev_new();
        if (udev == NULL)
                goto out;

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

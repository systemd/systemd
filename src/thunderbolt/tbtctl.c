/***
  This file is part of systemd.

  Copyright 2017 Christian J. Kellner

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

#include "thunderbolt.h"

#include <getopt.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#include "conf-parser.h"
#include "chattr-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fileio.h"
#include "hash-funcs.h"
#include "io-util.h"
#include "locale-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "random-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "umask-util.h"
#include "util.h"

struct CtlCmd {
        const char *name;
        int       (*func) (struct udev *udev, int argc, char *argv[]);
        const char *desc;
        bool        root;
};

static inline void print_json_kv(const char *key, const char *value, bool more) {
        printf("\"%s\": \"%s\"%s\n", key, value, more ? "," : "");
}

static inline void print_json_kb(const char *key, bool value, bool more) {
        printf("\"%s\": %s%s\n", key, true_false(value), more ? "," : "");
}


static void device_print_json(TbStore *store, TbDevice *device, bool more) {
        bool in_store;

        printf("{\n");
        print_json_kv("uuid", device->uuid, true);
        print_json_kv("name", device->name, true);
        print_json_kv("vendor", device->vendor, true);

        if (!tb_device_is_online(device)) {
                print_json_kv("status", "offline", true);
        } else if (device->authorized == AUTH_NEEDED) {
                print_json_kv("status", "unauthorized", true);
                print_json_kb("authorized", false, true);
        } else if (device->authorized == AUTH_USER) {
                print_json_kv("status", "authorized (user)", true);
                print_json_kb("authorized", true, true);
                print_json_kv("auth-method", "user", true);
        } else if (device->authorized ==  AUTH_KEY) {
                print_json_kv("status", "authorized (key)", true);
                print_json_kb("authorized", true, true);
                print_json_kv("auth-method", "key", true);
        } else {
                print_json_kv("status", "unknown", true);
        }

        if (tb_device_is_online(device)) {
                SecurityLevel s = tb_device_get_security_level(device);
                const char *str;
                 if (s == _SECURITY_INVALID)
                         str = "unknown\n";
                 else
                         str = security_to_string(s);
                print_json_kv("security", str, true);
        }

        in_store = tb_store_have_device(store, device->uuid);
        print_json_kb("stored", in_store, in_store);
        if (in_store) {
                Auth auth = AUTH_INITIALIZER;
                int r;

                r = store_get_auth(store, device->uuid, &auth);
                if (r < 0) {
                        print_json_kv("policy", "error", false);
                } else if (!auth_level_can_authorize(auth.level)) {
                        print_json_kv("policy", "ignore", false);
                } else if (auth.level == AUTH_USER) {
                        print_json_kv("policy", "authorize", true);
                        print_json_kv("policy-method", "user", false);
                } else if (auth.level == AUTH_KEY) {
                        print_json_kv("policy", "authorize", true);
                        print_json_kv("policy-method", "key", false);
                }
        }

        printf("}%s", more ? "," : "");
}

static void device_print(TbStore *store, TbDevice *device) {
        SecurityLevel security;
        Auth auth = AUTH_INITIALIZER;
        const char *status;
        const char *st_sym, *st_con, *st_coff;
        const char *policy_str;
        int r;
        bool in_store;

        if (!tb_device_is_online(device)) {
                status = "offline";
                st_con = ansi_highlight_blue();;
                st_sym = special_glyph(BLACK_CIRCLE);
        } else if (device->authorized == AUTH_NEEDED) {
                status = "unauthorized";
                st_con = ansi_highlight_yellow();
                st_sym = special_glyph(BLACK_CIRCLE);
        } else if (device->authorized == AUTH_USER) {
                status = "authorized (user)";
                st_con = ansi_highlight_green();
                st_sym = special_glyph(BLACK_CIRCLE);
        } else if (device->authorized ==  AUTH_KEY) {
                status = "authorized (key)";
                st_con = ansi_highlight_green();
                st_sym = special_glyph(BLACK_CIRCLE);
        } else {
                status = "unknown authorization";
                st_con = ansi_highlight_red();
                st_sym = special_glyph(BLACK_CIRCLE);
        }

        st_coff = ansi_normal();

        printf("%s%s%s %s\n", st_con, st_sym, st_coff, device->name);
        printf("  %s vendor:     %s\n", special_glyph(TREE_BRANCH), device->vendor);
        printf("  %s uuid:       %s\n", special_glyph(TREE_BRANCH), device->uuid);
        printf("  %s status:     %s\n", special_glyph(TREE_BRANCH), status);

        if (tb_device_is_online(device)) {
                printf("  %s security:   ", special_glyph(TREE_BRANCH));

                security = tb_device_get_security_level(device);
                if (security == _SECURITY_INVALID)
                        printf("unknown\n");
                else
                        printf("%s\n", security_to_string(security));
        }

        in_store = tb_store_have_device(store, device->uuid);
        printf("  %s in store:   %s\n", special_glyph(TREE_RIGHT), yes_no(in_store));

        if (!in_store)
                goto out;

        r = store_get_auth(store, device->uuid, &auth);
        if (r < 0)
                policy_str = "error";
        else if (!auth_level_can_authorize(auth.level))
                policy_str = "ignore";
        else if (auth.level == AUTH_USER)
                policy_str = "authorize (user)";
        else if (auth.level == AUTH_KEY)
                policy_str = "authorize (key)";

        printf("     %s policy:  %s\n", special_glyph(TREE_BRANCH), policy_str);
        printf("     %s key:     %s\n", special_glyph(TREE_RIGHT), yes_no(!!auth.key));

 out:
        printf("\n");
}

static int list_devices_udev(struct udev *udev, TbDeviceVec **vec) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *enumerate = NULL;
        struct udev_list_entry *list_entry = NULL, *first = NULL;
        TbDeviceVec *v;
        int r;

        v = tb_device_vec_ensure_allocated(vec);
        if (v == NULL)
                return -ENOMEM;

        enumerate = udev_enumerate_new(udev);
        if (enumerate == NULL)
                return -ENOMEM;

        r = udev_enumerate_add_match_subsystem(enumerate, "thunderbolt");
        if (r < 0)
                return r;

        r = udev_enumerate_add_match_sysattr(enumerate, "unique_id", NULL);
        if (r < 0)
                return r;

        udev_enumerate_scan_devices(enumerate);

        first = udev_enumerate_get_list_entry(enumerate);
        udev_list_entry_foreach(list_entry, first) {
                TbDevice *device;
                const char *name;

                name = udev_list_entry_get_name(list_entry);
                r = tb_device_new_from_syspath(udev, name, &device);
                if (r < 0)
                        continue;

                tb_device_vec_push_back(v, device);
        }

        return 0;
}

static int list_devices(struct udev *udev, int argc, char *argv[]) {
        _cleanup_tb_device_vec_free_ TbDeviceVec *devices = NULL;
        _cleanup_tb_store_free_ TbStore *store = NULL;
        TbDevice *device = NULL;
        unsigned i;
        int c, r;
        bool show_all = false;
        bool json = false;

        static const struct option options[] = {
                { "all",    no_argument, NULL, 'a' },
                { "json",   no_argument, NULL, 'J' },
                {}

        };

        while ((c = getopt_long(argc, argv, "ah", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        show_all = true;
                        break;
                case 'J':
                        json = true;
                        break;
                case 'h':
                        fprintf(stderr, "FIXME: need help\n");
                        return EXIT_SUCCESS;
                default:
                        return EXIT_FAILURE;

                }

        r = tb_store_new(&store);
        if (r < 0) {
                log_error_errno(r, "Couldn't open store: %m");
                return EXIT_FAILURE;
        }

        r = list_devices_udev(udev, &devices);
        if (r < 0) {
                log_error_errno(r, "Could not list devices from udev: %m");
                return EXIT_FAILURE;
        }

        if (show_all) {
                r = tb_store_load_missing(store, &devices);
                if (r < 0)
                        log_error_errno(r, "Could not load devices from DB: %m");
        }

        tb_device_vec_sort(devices);

        if (json)
                printf("[");

        for (i = 0; i < devices->n; i++) {
                device = tb_device_vec_at(devices, i);
                if (json)
                        device_print_json(store, device, i + 1 < devices->n);
                else
                        device_print(store, device);

                tb_device_free(&device);
        }

        if (json)
                printf("]\n");

        return EXIT_SUCCESS;
}

static const struct CtlCmd cmd_list = {
        .name = "list",
        .func = list_devices,
        .desc = "List thunderbolt devices",
};

static int authorize_user(struct udev *udev, int argc, char *argv[]) {
        _cleanup_tb_device_free_ TbDevice *device = NULL;
        _cleanup_auth_reset_ Auth auth = AUTH_INITIALIZER;
        _cleanup_tb_store_free_ TbStore *store = NULL;
        SecurityLevel sl;
        int r;

        if (argc < 2) {
                fprintf(stderr, "%s: need sysfs path\n",
                        program_invocation_short_name);
                return EXIT_FAILURE;
        }

        r = tb_store_new(&store);
        if (r < 0) {
                log_error_errno(r, "Couldn't open store: %m");
                return EXIT_FAILURE;
        }

        r = tb_device_new_from_syspath(udev, argv[1], &device);
        if (r < 0) {
                log_error_errno(r, "Couldn't open device: %m");
                return EXIT_FAILURE;
        }

        if (device->authorized != AUTH_NEEDED) {
                log_error("Device already authorized");
                return EXIT_FAILURE;
        }

        sl = tb_device_get_security_level(device);
        if (sl < 0) {
                log_error_errno(r, "Failed to get host controller security level");
                return EXIT_FAILURE;
        }
        if (sl != SECURITY_USER && sl != SECURITY_SECURE) {
                log_error("Security level of controller insufficient");
                return EXIT_FAILURE;
        }

        r = store_get_auth(store, device->uuid, &auth);
        if (r < 0) {
                log_error_errno(r, "Failed to read authorization from store: %m");
                return EXIT_FAILURE;
        }

        if (auth.level == AUTH_MISSING)
                auth.level = sl;
        if (auth.level == AUTH_KEY && auth.key == NULL)
                auth_generate_key_string(&auth);

        r = tb_device_authorize(device, &auth);
        if (r < 0) {
                log_error_errno(r, "Failed to authorize device: %m");
                return EXIT_FAILURE;
        }

        if (auth.store != STORE_NONE)
                return EXIT_SUCCESS;

        r = store_put_device(store, device, &auth);
        if (r < 0) {
                log_error_errno(r, "Failed to commit device to store: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static const struct CtlCmd cmd_authorize = {
        .name = "authorize",
        .func = authorize_user,
        .desc = "Authorize a thunderbolt device",
        .root = true,
};

static int authorize_udev(struct udev *udev, int argc, char *argv[]) {
        _cleanup_tb_device_free_ TbDevice *device = NULL;
        _cleanup_tb_store_free_ TbStore *store = NULL;
        _cleanup_auth_reset_ Auth auth = AUTH_INITIALIZER;
        SecurityLevel sl;
        int r;

        if (argc < 2) {
                fprintf(stderr, "%s: need sysfs path\n",
                        program_invocation_short_name);
                return EXIT_FAILURE;
        }

        r = tb_store_new(&store);
        if (r < 0) {
                log_error_errno(r, "Couldn't open store: %m");
                return EXIT_FAILURE;
        }

        r = tb_device_new_from_syspath(udev, argv[1], &device);
        if (r < 0) {
                log_error_errno(r, "Couldn't open device: %m");
                return EXIT_FAILURE;
        }

        r = store_get_auth(store, device->uuid, &auth);
        if (r < 0) {
                log_error_errno(r, "Failed to load authorization: %m");
                return EXIT_FAILURE;
        }

        if (!auth_level_can_authorize(auth.level)) {
                log_debug("Unknown or ignored device: %s", device->uuid);
                /* Unknown or ignored device */
                return EXIT_SUCCESS;
        }

        sl = tb_device_get_security_level(device);
        if (sl < 0) {
                log_error_errno(sl, "Failed to determine security level");
                return EXIT_FAILURE;
        }

        if (sl != SECURITY_USER && sl != SECURITY_SECURE) {
                log_debug("Security level of controller insufficient");
                /* not an error here */
                return EXIT_SUCCESS;
        }

        auth.level = MIN(auth.level, sl);

        r = tb_device_authorize(device, &auth);
        if (r < 0) {
                log_error_errno(r, "Failed to authorize device: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static const struct CtlCmd cmd_udev = {
        .name = "udev",
        .func = authorize_udev,
        .desc = "internal command for udev rules",
        .root = true,
};


static int forget_device(struct udev *udev, int argc, char *argv[]) {
        _cleanup_tb_store_free_ TbStore *store = NULL;
        const char *uuid;
        int r;

        if (argc < 2) {
                fprintf(stderr, "%s: need device uuid\n",
                        program_invocation_short_name);
                return EXIT_FAILURE;
        }

        uuid = argv[1];

        r = tb_store_new(&store);
        if (r < 0) {
                log_error_errno(r, "Couldn't open store: %m");
                return EXIT_FAILURE;
        }

        r = tb_store_remove_auth(store, uuid);
        if (r < 0 && errno != -ENOENT) {
                log_error_errno(r, "Could not remove authorization: %m");
                return EXIT_FAILURE;
        }

        r = tb_store_remove_device(store, uuid);
        if (r < 0) {
                log_error_errno(r, "Could not remove device: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static const struct CtlCmd cmd_forget = {
        .name = "forget",
        .func = forget_device,
        .desc = "Remove a device from the database",
        .root = true,
};


static const struct CtlCmd *ctrl_cmds[] = {
        &cmd_list,
        &cmd_authorize,
        &cmd_forget,

        &cmd_udev
};

static void help(void) {
        unsigned int i;

        printf("%s [--version] [--debug] COMMAND [OPTIONS]\n\n"
               "Manager thunderbolt devices\n\n"
               "  -h --help             Show this help and exit\n"
               "  --version             Print version string and exit\n"
               "\n"
               "Commands:\n"
               , program_invocation_short_name);

        for (i = 0; i < ELEMENTSOF(ctrl_cmds); i++) {
                const struct CtlCmd *cmd = ctrl_cmds[i];
                if (!cmd->desc)
                        continue;

                printf("  %-20s  %s\n", cmd->name, cmd->desc);
        }
}


#define ARG_VERSION  0x100
#define ARG_NOROOT   0x101

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        const char *cmdname;
        const struct CtlCmd *cmd;
        bool root_check = true;
        static const struct option options[] = {
                { "debug",   no_argument, NULL, 'd' },
                { "help",    no_argument, NULL, 'h' },
                { "version", no_argument, NULL, ARG_VERSION },
                { "noroot",  no_argument, NULL, ARG_NOROOT  },
                {}
        };
        unsigned int i;
        int c, r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        while ((c = getopt_long(argc, argv, "+dhV", options, NULL)) >= 0)
                switch (c) {

                case 'd':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        help();
                        return EXIT_SUCCESS;

                case ARG_VERSION:
                        version();
                        return EXIT_SUCCESS;

                case ARG_NOROOT:
                        root_check = false;
                        break;

                default:
                        assert_not_reached("Unhandled option");
                }


        cmdname = argv[optind];

        if (!cmdname) {
                fprintf(stderr, "%s: need to specify command\n", program_invocation_short_name);
                fprintf(stderr, "  use --help for available commands\n");
                return EXIT_FAILURE;
        }

        cmd = NULL;
        for (i = 0; i < ELEMENTSOF(ctrl_cmds); i++) {
                if (streq(ctrl_cmds[i]->name, cmdname)) {
                        cmd = ctrl_cmds[i];
                        break;
                }
        }

        if (!cmd) {
                fprintf(stderr, "%s: invalid command: %s\n",
                        program_invocation_short_name, cmdname);
                fprintf(stderr, "  use --help for available commands\n");
                return EXIT_FAILURE;
        }

        if (root_check && cmd->root && geteuid() != 0) {
                fprintf(stderr, "%s %s must be invoked as root.\n",
                program_invocation_short_name, cmdname);
                return EXIT_FAILURE;
        }

        udev = udev_new();
        if (!udev) {
                log_oom();
                return EXIT_FAILURE;
        }


        argc -= optind;
        argv += optind;
        optind = 0;

        r = cmd->func(udev, argc, argv);

        return r;
}

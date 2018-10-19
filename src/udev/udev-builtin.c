/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "string-util.h"
#include "udev-builtin.h"
#include "udev.h"

static bool initialized;

static const struct udev_builtin *builtins[] = {
#if HAVE_BLKID
        [UDEV_BUILTIN_BLKID] = &udev_builtin_blkid,
#endif
        [UDEV_BUILTIN_BTRFS] = &udev_builtin_btrfs,
        [UDEV_BUILTIN_HWDB] = &udev_builtin_hwdb,
        [UDEV_BUILTIN_INPUT_ID] = &udev_builtin_input_id,
        [UDEV_BUILTIN_KEYBOARD] = &udev_builtin_keyboard,
#if HAVE_KMOD
        [UDEV_BUILTIN_KMOD] = &udev_builtin_kmod,
#endif
        [UDEV_BUILTIN_NET_ID] = &udev_builtin_net_id,
        [UDEV_BUILTIN_NET_LINK] = &udev_builtin_net_setup_link,
        [UDEV_BUILTIN_PATH_ID] = &udev_builtin_path_id,
        [UDEV_BUILTIN_USB_ID] = &udev_builtin_usb_id,
#if HAVE_ACL
        [UDEV_BUILTIN_UACCESS] = &udev_builtin_uaccess,
#endif
};

void udev_builtin_init(void) {
        unsigned i;

        if (initialized)
                return;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i] && builtins[i]->init)
                        builtins[i]->init();

        initialized = true;
}

void udev_builtin_exit(void) {
        unsigned i;

        if (!initialized)
                return;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i] && builtins[i]->exit)
                        builtins[i]->exit();

        initialized = false;
}

bool udev_builtin_validate(void) {
        unsigned i;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i] && builtins[i]->validate && builtins[i]->validate())
                        return true;
        return false;
}

void udev_builtin_list(void) {
        unsigned i;

        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i])
                        fprintf(stderr, "  %-14s  %s\n", builtins[i]->name, builtins[i]->help);
}

const char *udev_builtin_name(enum udev_builtin_cmd cmd) {
        if (!builtins[cmd])
                return NULL;

        return builtins[cmd]->name;
}

bool udev_builtin_run_once(enum udev_builtin_cmd cmd) {
        if (!builtins[cmd])
                return false;

        return builtins[cmd]->run_once;
}

enum udev_builtin_cmd udev_builtin_lookup(const char *command) {
        char name[UTIL_PATH_SIZE];
        enum udev_builtin_cmd i;
        char *pos;

        strscpy(name, sizeof(name), command);
        pos = strchr(name, ' ');
        if (pos)
                pos[0] = '\0';
        for (i = 0; i < ELEMENTSOF(builtins); i++)
                if (builtins[i] && streq(builtins[i]->name, name))
                        return i;
        return UDEV_BUILTIN_MAX;
}

int udev_builtin_run(struct udev_device *dev, enum udev_builtin_cmd cmd, const char *command, bool test) {
        _cleanup_strv_free_ char **argv = NULL;

        if (!builtins[cmd])
                return -EOPNOTSUPP;

        argv = strv_split_full(command, NULL, SPLIT_QUOTES | SPLIT_RELAX);
        if (!argv)
                return -ENOMEM;

        /* we need '0' here to reset the internal state */
        optind = 0;
        return builtins[cmd]->cmd(dev, strv_length(argv), argv, test);
}

int udev_builtin_add_property(struct udev_device *dev, bool test, const char *key, const char *val) {
        udev_device_add_property(dev, key, val);

        if (test)
                printf("%s=%s\n", key, val);
        return 0;
}

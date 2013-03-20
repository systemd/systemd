/*
 * keymap - dump keymap of an evdev device or set a new keymap from a file
 *
 * Based on keyfuzz by Lennart Poettering <mzqrovna@0pointer.net>
 * Adapted for udev-extras by Martin Pitt <martin.pitt@ubuntu.com>
 *
 * Copyright (C) 2006, Lennart Poettering
 * Copyright (C) 2009, Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/input.h>

static const struct key* lookup_key (const char *str, unsigned int len);

#include "keys-from-name.h"
#include "keys-to-name.h"
#include "macro.h"
#include "util.h"

#define MAX_SCANCODES 1024

static int evdev_open(const char *dev)
{
        int fd;
        char fn[PATH_MAX];

        if (!startswith(dev, "/dev")) {
                snprintf(fn, sizeof(fn), "/dev/%s", dev);
                dev = fn;
        }

        if ((fd = open(dev, O_RDWR)) < 0) {
                fprintf(stderr, "error open('%s'): %m\n", dev);
                return -1;
        }
        return fd;
}

static int evdev_get_keycode(int fd, unsigned scancode, int e)
{
        unsigned codes[2];

        codes[0] = scancode;
        if (ioctl(fd, EVIOCGKEYCODE, codes) < 0) {
                if (e && errno == EINVAL) {
                        return -2;
                } else {
                        fprintf(stderr, "EVIOCGKEYCODE for scan code 0x%x: %m\n", scancode);
                        return -1;
                }
        }
        return codes[1];
}

static int evdev_set_keycode(int fd, unsigned scancode, int keycode)
{
        unsigned codes[2];

        codes[0] = scancode;
        codes[1] = (unsigned) keycode;

        if (ioctl(fd, EVIOCSKEYCODE, codes) < 0) {
                fprintf(stderr, "EVIOCSKEYCODE: %m\n");
                return -1;
        }
        return 0;
}

static int evdev_driver_version(int fd, char *v, size_t l)
{
        int version;

        if (ioctl(fd, EVIOCGVERSION, &version)) {
                fprintf(stderr, "EVIOCGVERSION: %m\n");
                return -1;
        }

        snprintf(v, l, "%i.%i.%i.", version >> 16, (version >> 8) & 0xff, version & 0xff);
        return 0;
}

static int evdev_device_name(int fd, char *n, size_t l)
{
        if (ioctl(fd, EVIOCGNAME(l), n) < 0) {
                fprintf(stderr, "EVIOCGNAME: %m\n");
                return -1;
        }
        return 0;
}

/* Return a lower-case string with KEY_ prefix removed */
static const char* format_keyname(const char* key) {
        static char result[101];
        const char* s;
        int len;

        for (s = key+4, len = 0; *s && len < 100; ++len, ++s)
                result[len] = tolower(*s);
        result[len] = '\0';
        return result;
}

static int dump_table(int fd) {
        char version[256], name[256];
        unsigned scancode;
        int r = -1;

        if (evdev_driver_version(fd, version, sizeof(version)) < 0)
                goto fail;

        if (evdev_device_name(fd, name, sizeof(name)) < 0)
                goto fail;

        printf("### evdev %s, driver '%s'\n", version, name);

        r = 0;
        for (scancode = 0; scancode < MAX_SCANCODES; scancode++) {
                int keycode;

                if ((keycode = evdev_get_keycode(fd, scancode, 1)) < 0) {
                        if (keycode == -2)
                                continue;
                        r = -1;
                        break;
                }

                if (keycode < KEY_MAX && key_names[keycode])
                        printf("0x%03x %s\n", scancode, format_keyname(key_names[keycode]));
                else
                        printf("0x%03x 0x%03x\n", scancode, keycode);
        }
fail:
        return r;
}

static void set_key(int fd, const char* scancode_str, const char* keyname)
{
        unsigned scancode;
        char *endptr;
        char t[105] = "KEY_UNKNOWN";
        const struct key *k;

        scancode = (unsigned) strtol(scancode_str, &endptr, 0);
        if (*endptr != '\0') {
                fprintf(stderr, "ERROR: Invalid scancode\n");
                exit(1);
        }

        snprintf(t, sizeof(t), "KEY_%s", keyname);

        if (!(k = lookup_key(t, strlen(t)))) {
                fprintf(stderr, "ERROR: Unknown key name '%s'\n", keyname);
                exit(1);
        }

        if (evdev_set_keycode(fd, scancode, k->id) < 0)
                fprintf(stderr, "setting scancode 0x%2X to key code %i failed\n",
                        scancode, k->id);
        else
                printf("setting scancode 0x%2X to key code %i\n",
                        scancode, k->id);
}

static int merge_table(int fd, FILE *f) {
        int r = 0;
        int line = 0;

        while (!feof(f)) {
                char s[256], *p;
                unsigned scancode;
                int new_keycode, old_keycode;

                if (!fgets(s, sizeof(s), f))
                        break;

                line++;
                p = s+strspn(s, "\t ");
                if (*p == '#' || *p == '\n')
                        continue;

                if (sscanf(p, "%i %i", &scancode, &new_keycode) != 2) {
                        char t[105] = "KEY_UNKNOWN";
                        const struct key *k;

                        if (sscanf(p, "%i %100s", &scancode, t+4) != 2) {
                                fprintf(stderr, "WARNING: Parse failure at line %i, ignoring.\n", line);
                                r = -1;
                                continue;
                        }

                        if (!(k = lookup_key(t, strlen(t)))) {
                                fprintf(stderr, "WARNING: Unknown key '%s' at line %i, ignoring.\n", t, line);
                                r = -1;
                                continue;
                        }

                        new_keycode = k->id;
                }


                if ((old_keycode = evdev_get_keycode(fd, scancode, 0)) < 0) {
                        r = -1;
                        continue;
                }

                if (evdev_set_keycode(fd, scancode, new_keycode) < 0) {
                        r = -1;
                        continue;
                }

                if (new_keycode != old_keycode)
                        fprintf(stderr, "Remapped scancode 0x%02x to 0x%02x (prior: 0x%02x)\n",
                                scancode, new_keycode, old_keycode);
        }

        fclose(f);
        return r;
}


/* read one event; return 1 if valid */
static int read_event(int fd, struct input_event* ev)
{
        int ret;
        ret = read(fd, ev, sizeof(struct input_event));

        if (ret < 0) {
                perror("read");
                return 0;
        }
        if (ret != sizeof(struct input_event)) {
                fprintf(stderr, "did not get enough data for event struct, aborting\n");
                return 0;
        }

        return 1;
}

static void print_key(unsigned scancode, uint16_t keycode, int has_scan, int has_key)
{
        const char *keyname;

        /* ignore key release events */
        if (has_key == 1)
                return;

        if (has_key == 0 && has_scan != 0) {
                fprintf(stderr, "got scan code event 0x%02X without a key code event\n",
                        scancode);
                return;
        }

        if (has_scan != 0)
                printf("scan code: 0x%02X   ", scancode);
        else
                printf("(no scan code received)  ");

        keyname = key_names[keycode];
        if (keyname != NULL)
                printf("key code: %s\n", format_keyname(keyname));
        else
                printf("key code: %03X\n", keycode);
}

static void interactive(int fd)
{
        struct input_event ev;
        unsigned last_scan = 0;
        uint16_t last_key = 0;
        int has_scan; /* boolean */
        int has_key; /* 0: none, 1: release, 2: press */

        /* grab input device */
        ioctl(fd, EVIOCGRAB, 1);
        puts("Press ESC to finish, or Control-C if this device is not your primary keyboard");

        has_scan = has_key = 0;
        while (read_event(fd, &ev)) {
                /* Drivers usually send the scan code first, then the key code,
                 * then a SYN. Some drivers (like thinkpad_acpi) send the key
                 * code first, and some drivers might not send SYN events, so
                 * keep a robust state machine which can deal with any of those
                 */

                if (ev.type == EV_MSC && ev.code == MSC_SCAN) {
                        if (has_scan) {
                                fputs("driver did not send SYN event in between key events; previous event:\n",
                                      stderr);
                                print_key(last_scan, last_key, has_scan, has_key);
                                has_key = 0;
                        }

                        last_scan = ev.value;
                        has_scan = 1;
                        /*printf("--- got scan %u; has scan %i key %i\n", last_scan, has_scan, has_key); */
                }
                else if (ev.type == EV_KEY) {
                        if (has_key) {
                                fputs("driver did not send SYN event in between key events; previous event:\n",
                                      stderr);
                                print_key(last_scan, last_key, has_scan, has_key);
                                has_scan = 0;
                        }

                        last_key = ev.code;
                        has_key = 1 + ev.value;
                        /*printf("--- got key %hu; has scan %i key %i\n", last_key, has_scan, has_key);*/

                        /* Stop on ESC */
                        if (ev.code == KEY_ESC && ev.value == 0)
                                break;
                }
                else if (ev.type == EV_SYN) {
                        /*printf("--- got SYN; has scan %i key %i\n", has_scan, has_key);*/
                        print_key(last_scan, last_key, has_scan, has_key);

                        has_scan = has_key = 0;
                }

        }

        /* release input device */
        ioctl(fd, EVIOCGRAB, 0);
}

_noreturn_ static void help(int error)
{
        const char* h = "Usage: keymap <event device> [<map file>]\n"
                        "       keymap <event device> scancode keyname [...]\n"
                        "       keymap -i <event device>\n";
        if (error) {
                fputs(h, stderr);
                exit(2);
        } else {
                fputs(h, stdout);
                exit(0);
        }
}

int main(int argc, char **argv)
{
        static const struct option options[] = {
                { "help", no_argument, NULL, 'h' },
                { "interactive", no_argument, NULL, 'i' },
                {}
        };
        int fd = -1;
        int opt_interactive = 0;
        int i;

        while (1) {
                int option;

                option = getopt_long(argc, argv, "hi", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'h':
                        help(0);

                case 'i':
                        opt_interactive = 1;
                        break;
                default:
                        return 1;
                }
        }

        if (argc < optind+1)
                help (1);

        if ((fd = evdev_open(argv[optind])) < 0)
                return 3;

        /* one argument (device): dump or interactive */
        if (argc == optind+1) {
                if (opt_interactive)
                        interactive(fd);
                else
                        dump_table(fd);
                return 0;
        }

        /* two arguments (device, mapfile): set map file */
        if (argc == optind+2) {
                const char *filearg = argv[optind+1];
                if (strchr(filearg, '/')) {
                        /* Keymap file argument is a path */
                        FILE *f = fopen(filearg, "re");
                        if (f)
                                merge_table(fd, f);
                        else
                                perror(filearg);
                } else {
                        /* Keymap file argument is a filename */
                        /* Open override file if present, otherwise default file */
                        char keymap_path[PATH_MAX];
                        FILE *f;

                        snprintf(keymap_path, sizeof(keymap_path), "/etc/udev/keymaps/%s", filearg);
                        f = fopen(keymap_path, "re");
                        if (f) {
                                merge_table(fd, f);
                        } else {
                                snprintf(keymap_path, sizeof(keymap_path), UDEVLIBEXECDIR "/keymaps/%s", filearg);
                                f = fopen(keymap_path, "re");
                                if (f)
                                        merge_table(fd, f);
                                else
                                        perror(keymap_path);
                        }
                }
                return 0;
        }

        /* more arguments (device, scancode/keyname pairs): set keys directly */
        if ((argc - optind - 1) % 2 == 0) {
                for (i = optind+1; i < argc; i += 2)
                        set_key(fd, argv[i], argv[i+1]);
                return 0;
        }

        /* invalid number of arguments */
        help(1);
        return 1; /* not reached */
}

/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <locale.h>
#include <langinfo.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/tiocl.h>
#include <linux/kd.h>

#include "util.h"
#include "log.h"
#include "macro.h"

static bool is_console(int fd) {
        unsigned char data[1];

        data[0] = TIOCL_GETFGCONSOLE;
        return ioctl(fd, TIOCLINUX, data) >= 0;
}

static bool is_locale_utf8(void) {
        const char *set;

        if (!setlocale(LC_ALL, ""))
                return true;

        set = nl_langinfo(CODESET);
        if (!set)
                return true;

        return streq(set, "UTF-8");
}

static int disable_utf8(int fd) {
        int r = 0, k;

        if (ioctl(fd, KDSKBMODE, K_XLATE) < 0)
                r = -errno;

        if (loop_write(fd, "\033%@", 3, false) < 0)
                r = -errno;

        if ((k = write_one_line_file("/sys/module/vt/parameters/default_utf8", "0")) < 0)
                r = k;

        if (r < 0)
                log_warning("Failed to disable UTF-8: %s", strerror(errno));

        return r;
}

static int load_keymap(const char *vc, const char *map, bool utf8, pid_t *_pid) {
        const char *args[7];
        int i = 0;
        pid_t pid;

        args[i++] = "/bin/loadkeys";
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;
        if (utf8)
                args[i++] = "-u";
        args[i++] = map;
        args[i++] = NULL;

        if ((pid = fork()) < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;
        return 0;
}

static int load_font(const char *vc, const char *font, const char *map, const char *unimap, pid_t *_pid) {
        const char *args[9];
        int i = 0;
        pid_t pid;

        args[i++] = "/bin/setfont";
        args[i++] = "-C";
        args[i++] = vc;
        args[i++] = font;
        if (map) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (unimap) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        args[i++] = NULL;

        if ((pid = fork()) < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;
        return 0;
}

int main(int argc, char **argv) {
        const char *vc;
        char *vc_keymap = NULL;
        char *vc_font = NULL;
        char *vc_font_map = NULL;
        char *vc_font_unimap = NULL;
        int fd = -1;
        bool utf8;
        int r = EXIT_FAILURE;
        pid_t font_pid = 0, keymap_pid = 0;

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (argv[1])
                vc = argv[1];
        else
                vc = "/dev/tty0";

        if ((fd = open(vc, O_RDWR|O_CLOEXEC)) < 0) {
                log_error("Failed to open %s: %m", vc);
                goto finish;
        }

        if (!is_console(fd)) {
                log_error("Device %s is not a virtual console.", vc);
                goto finish;
        }

        if (!(utf8 = is_locale_utf8()))
                disable_utf8(fd);

#ifdef TARGET_FEDORA
        if ((r = parse_env_file("/etc/sysconfig/i18n", NEWLINE,
                                "SYSFONT", &vc_font,
                                "SYSFONTACM", &vc_font_map,
                                "UNIMAP", &vc_font_unimap,
                                NULL)) < 0) {

                if (r != -ENOENT)
                        log_warning("Failed to read /etc/sysconfig/i18n: %s", strerror(-r));
        }

        if ((r = parse_env_file("/etc/sysconfig/keyboard", NEWLINE,
                                "KEYTABLE", &vc_keymap,
                                "KEYMAP", &vc_keymap,
                                NULL)) < 0) {

                if (r != -ENOENT)
                        log_warning("Failed to read /etc/sysconfig/i18n: %s", strerror(-r));
        }

        if (access("/etc/sysconfig/console/default.kmap", F_OK) >= 0) {
                char *t;

                if (!(t = strdup("/etc/sysconfig/console/default.kmap"))) {
                        log_error("Out of memory.");
                        goto finish;
                }

                free(vc_keymap);
                vc_keymap = t;
        }
#endif

        /* Override distribution-specific options with the
         * distribution-independent configuration */
        if ((r = parse_env_file("/etc/vconsole", NEWLINE,
                                "VCONSOLE_KEYMAP", &vc_keymap,
                                "VCONSOLE_FONT", &vc_font,
                                "VCONSOLE_FONT_MAP", &vc_font_map,
                                "VCONSOLE_FONT_UNIMAP", &vc_font_unimap,
                                NULL)) < 0) {

                if (r != -ENOENT)
                        log_warning("Failed to read /etc/vconsole: %s", strerror(-r));
        }

        if ((r = parse_env_file("/proc/cmdline", WHITESPACE,
#ifdef TARGET_FEDORA
                                "SYSFONT", &vc_font,
                                "KEYTABLE", &vc_keymap,
#endif
                                "vconsole.keymap", &vc_keymap,
                                "vconsole.font", &vc_font,
                                "vconsole.font.map", &vc_font_map,
                                "vconsole.font.unimap", &vc_font_unimap,
                                NULL)) < 0) {

                if (r != -ENOENT)
                        log_warning("Failed to read /proc/cmdline: %s", strerror(-r));
        }

        if (!vc_keymap)
                vc_keymap = strdup("us");
        if (!vc_font)
                vc_font = strdup("latarcyrheb-sun16");

        if (!vc_keymap || !vc_font) {
                log_error("Failed to allocate strings.");
                goto finish;
        }

        if (load_keymap(vc, vc_keymap, utf8, &keymap_pid) >= 0 &&
            load_font(vc, vc_font, vc_font_map, vc_font_unimap, &font_pid) >= 0)
                r = EXIT_SUCCESS;

finish:
        if (keymap_pid > 0)
                wait_for_terminate_and_warn("/bin/loadkeys", keymap_pid);

        if (font_pid > 0)
                wait_for_terminate_and_warn("/bin/setfont", font_pid);

        free(vc_keymap);
        free(vc_font);
        free(vc_font_map);
        free(vc_font_unimap);

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

/***
  This file is part of systemd.

  Copyright 2010 Kay Sievers

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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"
#include "virt.h"

#define MAX_CONSOLES 63

static bool is_vconsole(int fd) {
        unsigned char data[1];

        data[0] = TIOCL_GETFGCONSOLE;
        return ioctl(fd, TIOCLINUX, data) >= 0;
}

static bool is_settable(int n, int *fd) {
        char vcname[strlen("/dev/vcs") + DECIMAL_STR_MAX(int)];
        int fdt, r, curr_mode;

        /* skip non-allocated ttys */
        xsprintf(vcname, "/dev/vcs%i", n);
        if (access(vcname, F_OK) < 0)
                return false;

        /* try to open terminal */
        xsprintf(vcname, "/dev/tty%i", n);
        fdt = open_terminal(vcname, O_RDWR|O_CLOEXEC);
        if (fdt < 0)
                return false;

        r = ioctl(fdt, KDGKBMODE, &curr_mode);
        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Oterwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */
        if (r || (curr_mode != K_XLATE && curr_mode != K_UNICODE)) {
                close(fdt);
                return false;
        }

        *fd = fdt;
        return true;
}

static int toggle_utf8_default(bool utf8) {
        int r;

        r = write_string_file("/sys/module/vt/parameters/default_utf8", utf8 ? "1" : "0", 0);
        if (r < 0)
                log_warning_errno(r, "Failed to %s sysfs UTF-8 flag: %m", utf8 ? "enable" : "disable");
        return r == 0;
}

static int toggle_utf8(int fd, bool utf8) {
        struct termios tc;
        int r;

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0) {
                r = -errno;
                log_warning_errno(r, "Failed to %s UTF-8 kbdmode: %m", utf8 ? "enable" : "disable");
                return r;
        }

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", 3, false);
        if (r < 0) {
                log_warning_errno(r, "Failed to %s UTF-8 term processing: %m", utf8 ? "enable" : "disable");
                return r;
        }

        r = tcgetattr(fd, &tc);
        if (r == 0) {
                if (utf8)
                        tc.c_iflag |= IUTF8;
                else
                        tc.c_iflag &= ~IUTF8;
                r = tcsetattr(fd, TCSANOW, &tc);
        }
        if (r < 0)
                log_warning_errno(r, "Failed to %s stty iutf8 flag: %m", utf8 ? "enable" : "disable");

        return r == 0;
}

static int keyboard_load_and_wait(const char *vc, const char *map, const char *map_toggle, bool utf8) {
        const char *args[8];
        int i = 0, r;
        pid_t pid;

        /* An empty map means kernel map */
        if (isempty(map))
                return 1;

        args[i++] = KBD_LOADKEYS;
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;
        if (utf8)
                args[i++] = "-u";
        args[i++] = map;
        if (map_toggle)
                args[i++] = map_toggle;
        args[i++] = NULL;

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");
        else if (pid == 0) {

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate_and_warn(KBD_LOADKEYS, pid, true);
        if (r < 0)
                return r;

        return r == 0;
}

static int font_load(const char *vc, const char *font, const char *map, const char *unimap, pid_t *dpid) {
        const char *args[9];
        int i = 0;
        pid_t pid;

        /* Note: any of the elements can be loaded independently */
        if (isempty(font) && isempty(map) && isempty(unimap))
                return 1;

        args[i++] = KBD_SETFONT;
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

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");
        else if (pid == 0) {

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        } else
                *dpid = pid;
        return 1;
}

static int font_load_wait_all(int vc_max, pid_t *wait_tab) {
        int i, r = 0;

        for (i = 0 ; i < vc_max ; i++) {
                if (wait_tab[i] > 0)
                        r |= wait_for_terminate_and_warn(KBD_SETFONT, wait_tab[i], true);
        }

        return r == 0;
}

int main(int argc, char **argv) {
        const char *vc;
        _cleanup_free_ char
                *vc_cnt = NULL, *vc_keymap = NULL, *vc_keymap_toggle = NULL,
                *vc_font = NULL, *vc_font_map = NULL, *vc_font_unimap = NULL;
        _cleanup_close_ int fd = -1;
        pid_t wait_tab[MAX_CONSOLES] = { 0 };
        bool utf8, single = false, console_changed = false, ok = true;
        int i, vc_max, r = EXIT_FAILURE;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argv[1]) {
                vc = argv[1];
                single = true;
        } else
                vc = "/dev/tty0";

        fd = open_terminal(vc, O_RDWR|O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(fd, "Failed to open %s: %m", vc);
                return EXIT_FAILURE;
        }

        if (!is_vconsole(fd)) {
                log_error("Device %s is not a virtual console.", vc);
                return EXIT_FAILURE;
        }

        utf8 = is_locale_utf8();

        r = parse_env_file("/etc/vconsole.conf", NEWLINE,
                           "VC_MAX", &vc_cnt,
                           "KEYMAP", &vc_keymap,
                           "KEYMAP_TOGGLE", &vc_keymap_toggle,
                           "FONT", &vc_font,
                           "FONT_MAP", &vc_font_map,
                           "FONT_UNIMAP", &vc_font_unimap,
                           NULL);

        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/vconsole.conf: %m");

        /* Let the kernel command line override /etc/vconsole.conf */
        if (detect_container() <= 0) {
                r = parse_env_file("/proc/cmdline", WHITESPACE,
                                   "vconsole.vc.max", &vc_cnt,
                                   "vconsole.keymap", &vc_keymap,
                                   "vconsole.keymap.toggle", &vc_keymap_toggle,
                                   "vconsole.font", &vc_font,
                                   "vconsole.font.map", &vc_font_map,
                                   "vconsole.font.unimap", &vc_font_unimap,
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline: %m");
        }

        /* Sanitize vc_cnt */
        if (vc_cnt == NULL)
                vc_max = 12;
        else {
                r = safe_atoi(vc_cnt, &vc_max);
                if (r || vc_max < 1 || vc_max > MAX_CONSOLES) {
                        log_error("Invalid value for VC_MAX (vconsole.vc.max), it should be between 1 and " STRINGIFY(MAX_CONSOLES));
                        return EXIT_FAILURE;
                }
        }

        /*
         * First do per-console tasks;
         * if no console is changed don't do global changes afterwards
         */
        if (single) {
                ok = ok && toggle_utf8(fd, utf8) > 0;
                ok = ok && font_load(vc, vc_font, vc_font_map, vc_font_unimap, &wait_tab[0]) > 0;
                vc_max = 1;
                console_changed = true;
        } else
                for (i = 1; i <= vc_max; i++) {
                        char vci[strlen("/dev/tty") + DECIMAL_STR_MAX(int)];
                        int fdi;

                        if (!is_settable(i, &fdi))
                                continue;
                        xsprintf(vci, "/dev/tty%i", i);

                        ok = ok && toggle_utf8(fdi, utf8) > 0;
                        ok = ok && font_load(vci, vc_font, vc_font_map, vc_font_unimap, &wait_tab[i-1]) > 0;
                        close(fdi);
                        console_changed = true;
                }

        if (console_changed) {
                ok = ok && font_load_wait_all(vc_max, wait_tab) > 0;
                /* proceed with global stuff */
                ok = ok && toggle_utf8_default(utf8) > 0;
                ok = ok && keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) > 0;
        }

        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

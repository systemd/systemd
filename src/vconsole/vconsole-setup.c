/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2016 Michal Soltys <soltys@ziu.info>
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
#include <sysexits.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"
#include "virt.h"

static int verify_vc_device(int fd) {
        unsigned char data[] = {
                TIOCL_GETFGCONSOLE,
        };

        int r;

        r = ioctl(fd, TIOCLINUX, data);
        if (r < 0)
                return -errno;

        return r;
}

static int verify_vc_allocation(unsigned idx) {
        char vcname[sizeof("/dev/vcs") + DECIMAL_STR_MAX(unsigned) - 2];

        xsprintf(vcname, "/dev/vcs%u", idx);

        if (access(vcname, F_OK) < 0)
                return -errno;

        return 0;
}

static int verify_vc_allocation_byfd(int fd) {
        struct vt_stat vcs = {};

        if (ioctl(fd, VT_GETSTATE, &vcs) < 0)
                return -errno;

        return verify_vc_allocation(vcs.v_active);
}

static int verify_vc_kbmode(int fd) {
        int curr_mode;

        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */

        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
                return -errno;

        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
}

static int toggle_utf8_vc(const char *name, int fd, bool utf8) {
        int r;
        struct termios tc = {};

        assert(name);
        assert(fd >= 0);

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode on %s: %m", enable_disable(utf8), name);

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", 3, false);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s UTF-8 term processing on %s: %m", enable_disable(utf8), name);

        r = tcgetattr(fd, &tc);
        if (r >= 0) {
                SET_FLAG(tc.c_iflag, IUTF8, utf8);
                r = tcsetattr(fd, TCSANOW, &tc);
        }
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s iutf8 flag on %s: %m", enable_disable(utf8), name);

        log_debug("UTF-8 kbdmode %sd on %s", enable_disable(utf8), name);
        return 0;
}

static int toggle_utf8_sysfs(bool utf8) {
        int r;

        r = write_string_file("/sys/module/vt/parameters/default_utf8", one_zero(utf8), WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s sysfs UTF-8 flag: %m", enable_disable(utf8));

        log_debug("Sysfs UTF-8 flag %sd", enable_disable(utf8));
        return 0;
}

static int keyboard_load_and_wait(const char *vc, const char *map, const char *map_toggle, bool utf8) {
        const char *args[8];
        unsigned i = 0;
        pid_t pid;
        int r;

        /* An empty map means kernel map */
        if (isempty(map))
                return 0;

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

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd;

                cmd = strv_join((char**) args, " ");
                log_debug("Executing \"%s\"...", strnull(cmd));
        }

        r = safe_fork("(loadkeys)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(KBD_LOADKEYS, pid, WAIT_LOG);
}

static int font_load_and_wait(const char *vc, const char *font, const char *map, const char *unimap) {
        const char *args[9];
        unsigned i = 0;
        pid_t pid;
        int r;

        /* Any part can be set independently */
        if (isempty(font) && isempty(map) && isempty(unimap))
                return 0;

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        if (!isempty(map)) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (!isempty(unimap)) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        if (!isempty(font))
                args[i++] = font;
        args[i++] = NULL;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd;

                cmd = strv_join((char**) args, " ");
                log_debug("Executing \"%s\"...", strnull(cmd));
        }

        r = safe_fork("(setfont)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(KBD_SETFONT, pid, WAIT_LOG);
}

/*
 * A newly allocated VT uses the font from the source VT. Here
 * we update all possibly already allocated VTs with the configured
 * font. It also allows to restart systemd-vconsole-setup.service,
 * to apply a new font to all VTs.
 *
 * We also setup per-console utf8 related stuff: kbdmode, term
 * processing, stty iutf8.
 */
static void setup_remaining_vcs(int src_fd, unsigned src_idx, bool utf8) {
        struct console_font_op cfo = {
                .op = KD_FONT_OP_GET,
                .width = UINT_MAX, .height = UINT_MAX,
                .charcount = UINT_MAX,
        };
        struct unimapinit adv = {};
        struct unimapdesc unimapd;
        _cleanup_free_ struct unipair* unipairs = NULL;
        _cleanup_free_ void *fontbuf = NULL;
        unsigned i;
        int r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs) {
                log_oom();
                return;
        }

        /* get metadata of the current font (width, height, count) */
        r = ioctl(src_fd, KDFONTOP, &cfo);
        if (r < 0)
                log_warning_errno(errno, "KD_FONT_OP_GET failed while trying to get the font metadata: %m");
        else {
                /* verify parameter sanity first */
                if (cfo.width > 32 || cfo.height > 32 || cfo.charcount > 512)
                        log_warning("Invalid font metadata - width: %u (max 32), height: %u (max 32), count: %u (max 512)",
                                    cfo.width, cfo.height, cfo.charcount);
                else {
                        /*
                         * Console fonts supported by the kernel are limited in size to 32 x 32 and maximum 512
                         * characters. Thus with 1 bit per pixel it requires up to 65536 bytes. The height always
                         * requires 32 per glyph, regardless of the actual height - see the comment above #define
                         * max_font_size 65536 in drivers/tty/vt/vt.c for more details.
                         */
                        fontbuf = malloc_multiply((cfo.width + 7) / 8 * 32, cfo.charcount);
                        if (!fontbuf) {
                                log_oom();
                                return;
                        }
                        /* get fonts from the source console */
                        cfo.data = fontbuf;
                        r = ioctl(src_fd, KDFONTOP, &cfo);
                        if (r < 0)
                                log_warning_errno(errno, "KD_FONT_OP_GET failed while trying to read the font data: %m");
                        else {
                                unimapd.entries  = unipairs;
                                unimapd.entry_ct = USHRT_MAX;
                                r = ioctl(src_fd, GIO_UNIMAP, &unimapd);
                                if (r < 0)
                                        log_warning_errno(errno, "GIO_UNIMAP failed while trying to read unicode mappings: %m");
                                else
                                        cfo.op = KD_FONT_OP_SET;
                        }
                }
        }

        if (cfo.op != KD_FONT_OP_SET)
                log_warning("Fonts will not be copied to remaining consoles");

        for (i = 1; i <= 63; i++) {
                char ttyname[sizeof("/dev/tty63")];
                _cleanup_close_ int fd_d = -1;

                if (i == src_idx || verify_vc_allocation(i) < 0)
                        continue;

                /* try to open terminal */
                xsprintf(ttyname, "/dev/tty%u", i);
                fd_d = open_terminal(ttyname, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd_d < 0) {
                        log_warning_errno(fd_d, "Unable to open tty%u, fonts will not be copied: %m", i);
                        continue;
                }

                if (verify_vc_kbmode(fd_d) < 0)
                        continue;

                (void) toggle_utf8_vc(ttyname, fd_d, utf8);

                if (cfo.op != KD_FONT_OP_SET)
                        continue;

                r = ioctl(fd_d, KDFONTOP, &cfo);
                if (r < 0) {
                        int last_errno, mode;

                        /* The fonts couldn't have been copied. It might be due to the
                         * terminal being in graphical mode. In this case the kernel
                         * returns -EINVAL which is too generic for distinguishing this
                         * specific case. So we need to retrieve the terminal mode and if
                         * the graphical mode is in used, let's assume that something else
                         * is using the terminal and the failure was expected as we
                         * shouldn't have tried to copy the fonts. */

                        last_errno = errno;
                        if (ioctl(fd_d, KDGETMODE, &mode) >= 0 && mode != KD_TEXT)
                                log_debug("KD_FONT_OP_SET skipped: tty%u is not in text mode", i);
                        else
                                log_warning_errno(last_errno, "KD_FONT_OP_SET failed, fonts will not be copied to tty%u: %m", i);

                        continue;
                }

                /*
                 * copy unicode translation table unimapd is a ushort count and a pointer
                 * to an array of struct unipair { ushort, ushort }
                 */
                r = ioctl(fd_d, PIO_UNIMAPCLR, &adv);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAPCLR failed, unimaps might be incorrect for tty%u: %m", i);
                        continue;
                }

                r = ioctl(fd_d, PIO_UNIMAP, &unimapd);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAP failed, unimaps might be incorrect for tty%u: %m", i);
                        continue;
                }

                log_debug("Font and unimap successfully copied to %s", ttyname);
        }
}

static int find_source_vc(char **ret_path, unsigned *ret_idx) {
        _cleanup_free_ char *path = NULL;
        int r, err = 0;
        unsigned i;

        path = new(char, sizeof("/dev/tty63"));
        if (!path)
                return log_oom();

        for (i = 1; i <= 63; i++) {
                _cleanup_close_ int fd = -1;

                r = verify_vc_allocation(i);
                if (r < 0) {
                        if (!err)
                                err = -r;
                        continue;
                }

                sprintf(path, "/dev/tty%u", i);
                fd = open_terminal(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (!err)
                                err = -fd;
                        continue;
                }
                r = verify_vc_kbmode(fd);
                if (r < 0) {
                        if (!err)
                                err = -r;
                        continue;
                }

                /* all checks passed, return this one as a source console */
                *ret_idx = i;
                *ret_path = TAKE_PTR(path);
                return TAKE_FD(fd);
        }

        return log_error_errno(err, "No usable source console found: %m");
}

static int verify_source_vc(char **ret_path, const char *src_vc) {
        _cleanup_close_ int fd = -1;
        char *path;
        int r;

        fd = open_terminal(src_vc, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s: %m", src_vc);

        r = verify_vc_device(fd);
        if (r < 0)
                return log_error_errno(r, "Device %s is not a virtual console: %m", src_vc);

        r = verify_vc_allocation_byfd(fd);
        if (r < 0)
                return log_error_errno(r, "Virtual console %s is not allocated: %m", src_vc);

        r = verify_vc_kbmode(fd);
        if (r < 0)
                return log_error_errno(r, "Virtual console %s is not in K_XLATE or K_UNICODE: %m", src_vc);

        path = strdup(src_vc);
        if (!path)
                return log_oom();

        *ret_path = path;
        return TAKE_FD(fd);
}

int main(int argc, char **argv) {
        _cleanup_free_ char
                *vc = NULL,
                *vc_keymap = NULL, *vc_keymap_toggle = NULL,
                *vc_font = NULL, *vc_font_map = NULL, *vc_font_unimap = NULL;
        _cleanup_close_ int fd = -1;
        bool utf8, keyboard_ok;
        unsigned idx = 0;
        int r;

        log_setup_service();

        umask(0022);

        if (argv[1])
                fd = verify_source_vc(&vc, argv[1]);
        else
                fd = find_source_vc(&vc, &idx);
        if (fd < 0)
                return EXIT_FAILURE;

        utf8 = is_locale_utf8();

        r = parse_env_file(NULL, "/etc/vconsole.conf",
                           "KEYMAP", &vc_keymap,
                           "KEYMAP_TOGGLE", &vc_keymap_toggle,
                           "FONT", &vc_font,
                           "FONT_MAP", &vc_font_map,
                           "FONT_UNIMAP", &vc_font_unimap);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/vconsole.conf: %m");

        /* Let the kernel command line override /etc/vconsole.conf */
        r = proc_cmdline_get_key_many(
                        PROC_CMDLINE_STRIP_RD_PREFIX,
                        "vconsole.keymap", &vc_keymap,
                        "vconsole.keymap_toggle", &vc_keymap_toggle,
                        "vconsole.font", &vc_font,
                        "vconsole.font_map", &vc_font_map,
                        "vconsole.font_unimap", &vc_font_unimap,
                        /* compatibility with obsolete multiple-dot scheme */
                        "vconsole.keymap.toggle", &vc_keymap_toggle,
                        "vconsole.font.map", &vc_font_map,
                        "vconsole.font.unimap", &vc_font_unimap);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /proc/cmdline: %m");

        (void) toggle_utf8_sysfs(utf8);
        (void) toggle_utf8_vc(vc, fd, utf8);

        r = font_load_and_wait(vc, vc_font, vc_font_map, vc_font_unimap);
        keyboard_ok = keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) == 0;

        if (idx > 0) {
                if (r == 0)
                        setup_remaining_vcs(fd, idx, utf8);
                else if (r == EX_OSERR)
                        /* setfont returns EX_OSERR when ioctl(KDFONTOP/PIO_FONTX/PIO_FONTX) fails.
                         * This might mean various things, but in particular lack of a graphical
                         * console. Let's be generous and not treat this as an error. */
                        log_notice("Setting fonts failed with a \"system error\", ignoring.");
                else
                        log_warning("Setting source virtual console failed, ignoring remaining ones");
        }

        return IN_SET(r, 0, EX_OSERR) && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

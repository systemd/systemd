/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sysexits.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "dev-setup.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "virt.h"

typedef struct Context {
        char *keymap;
        char *keymap_toggle;
        char *font;
        char *font_map;
        char *font_unimap;
} Context;

static void context_done(Context *c) {
        assert(c);

        free(c->keymap);
        free(c->keymap_toggle);
        free(c->font);
        free(c->font_map);
        free(c->font_unimap);
}

#define context_merge(dst, src, src_compat, name)                      \
        ({                                                             \
                if (src->name)                                         \
                        free_and_replace(dst->name, src->name);        \
                else if (src_compat && src_compat->name)               \
                        free_and_replace(dst->name, src_compat->name); \
        })

static void context_merge_config(
                Context *dst,
                Context *src,
                Context *src_compat) {

        assert(dst);
        assert(src);

        context_merge(dst, src, src_compat, keymap);
        context_merge(dst, src, src_compat, keymap_toggle);
        context_merge(dst, src, src_compat, font);
        context_merge(dst, src, src_compat, font_map);
        context_merge(dst, src, src_compat, font_unimap);
}

static int context_read_creds(Context *c) {
        _cleanup_(context_done) Context v = {};
        int r;

        assert(c);

        r = read_credential_strings_many(
                        "vconsole.keymap",        &v.keymap,
                        "vconsole.keymap_toggle", &v.keymap_toggle,
                        "vconsole.font",          &v.font,
                        "vconsole.font_map",      &v.font_map,
                        "vconsole.font_unimap",   &v.font_unimap);
        if (r < 0)
                log_warning_errno(r, "Failed to import credentials, ignoring: %m");

        context_merge_config(c, &v, NULL);
        return 0;
}

static int context_read_env(Context *c) {
        _cleanup_(context_done) Context v = {};
        int r;

        assert(c);

        r = parse_env_file(
                        NULL, "/etc/vconsole.conf",
                        "KEYMAP",        &v.keymap,
                        "KEYMAP_TOGGLE", &v.keymap_toggle,
                        "FONT",          &v.font,
                        "FONT_MAP",      &v.font_map,
                        "FONT_UNIMAP",   &v.font_unimap);
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to read /etc/vconsole.conf, ignoring: %m");
                return r;
        }

        context_merge_config(c, &v, NULL);
        return 0;
}

static int context_read_proc_cmdline(Context *c) {
        _cleanup_(context_done) Context v = {}, w = {};
        int r;

        assert(c);

        r = proc_cmdline_get_key_many(
                        PROC_CMDLINE_STRIP_RD_PREFIX,
                        "vconsole.keymap",        &v.keymap,
                        "vconsole.keymap_toggle", &v.keymap_toggle,
                        "vconsole.font",          &v.font,
                        "vconsole.font_map",      &v.font_map,
                        "vconsole.font_unimap",   &v.font_unimap,
                        /* compatibility with obsolete multiple-dot scheme */
                        "vconsole.keymap.toggle", &w.keymap_toggle,
                        "vconsole.font.map",      &w.font_map,
                        "vconsole.font.unimap",   &w.font_unimap);
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline, ignoring: %m");
                return r;
        }

        context_merge_config(c, &v, &w);
        return 0;
}

static void context_load_config(Context *c) {
        assert(c);

        /* Load data from credentials (lowest priority) */
        (void) context_read_creds(c);

        /* Load data from configuration file (middle priority) */
        (void) context_read_env(c);

        /* Let the kernel command line override /etc/vconsole.conf (highest priority) */
        (void) context_read_proc_cmdline(c);
}

static int verify_vc_device(int fd) {
        unsigned char data[] = {
                TIOCL_GETFGCONSOLE,
        };

        return RET_NERRNO(ioctl(fd, TIOCLINUX, data));
}

static int verify_vc_allocation(unsigned idx) {
        char vcname[sizeof("/dev/vcs") + DECIMAL_STR_MAX(unsigned) - 2];

        xsprintf(vcname, "/dev/vcs%u", idx);

        return RET_NERRNO(access(vcname, F_OK));
}

static int verify_vc_allocation_byfd(int fd) {
        struct vt_stat vcs = {};

        if (ioctl(fd, VT_GETSTATE, &vcs) < 0)
                return -errno;

        return verify_vc_allocation(vcs.v_active);
}

static int verify_vc_kbmode(int fd) {
        int curr_mode;

        assert(fd >= 0);

        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * https://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */

        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
                return -errno;

        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
}

static int verify_vc_display_mode(int fd) {
        int mode;

        assert(fd >= 0);

        /* Similarly the vc is likely busy if it is in KD_GRAPHICS mode. If it's not the case and it's been
         * left in graphics mode, the kernel will refuse to operate on the font settings anyway. */

        if (ioctl(fd, KDGETMODE, &mode) < 0)
                return -errno;

        return mode != KD_TEXT ? -EBUSY : 0;
}

static int toggle_utf8_vc(const char *name, int fd, bool utf8) {
        int r;
        struct termios tc = {};

        assert(name);
        assert(fd >= 0);

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode on %s: %m", enable_disable(utf8), name);

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", SIZE_MAX);
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

/* SYSTEMD_DEFAULT_KEYMAP must not be empty */
assert_cc(STRLEN(SYSTEMD_DEFAULT_KEYMAP) > 0);

static int keyboard_load_and_wait(const char *vc, Context *c, bool utf8) {
        const char* args[8];
        unsigned i = 0;
        pid_t pid;
        int r;

        assert(vc);
        assert(c);

        const char
                *keymap = empty_to_null(c->keymap) ?: SYSTEMD_DEFAULT_KEYMAP,
                *keymap_toggle = empty_to_null(c->keymap_toggle);

        if (streq(keymap, "@kernel"))
                return 0;

        args[i++] = KBD_LOADKEYS;
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;
        if (utf8)
                args[i++] = "-u";
        args[i++] = keymap;
        if (keymap_toggle)
                args[i++] = keymap_toggle;
        args[i++] = NULL;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd = NULL;

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

static int font_load_and_wait(const char *vc, Context *c) {
        const char* args[9];
        unsigned i = 0;
        pid_t pid;
        int r;

        assert(vc);
        assert(c);

        const char
                *font = empty_to_null(c->font),
                *font_map = empty_to_null(c->font_map),
                *font_unimap = empty_to_null(c->font_unimap);

        /* Any part can be set independently */
        if (!font && !font_map && !font_unimap)
                return 0;

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        if (font_map) {
                args[i++] = "-m";
                args[i++] = font_map;
        }
        if (font_unimap) {
                args[i++] = "-u";
                args[i++] = font_unimap;
        }
        if (font)
                args[i++] = font;
        args[i++] = NULL;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd = NULL;

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

        /* setfont returns EX_OSERR when ioctl(KDFONTOP/PIO_FONTX/PIO_FONTX) fails. This might mean various
         * things, but in particular lack of a graphical console. Let's be generous and not treat this as an
         * error. */
        r = wait_for_terminate_and_check(KBD_SETFONT, pid, WAIT_LOG_ABNORMAL);
        if (r == EX_OSERR)
                log_notice(KBD_SETFONT " failed with a \"system error\" (EX_OSERR), ignoring.");
        else if (r >= 0 && r != EXIT_SUCCESS)
                log_error(KBD_SETFONT " failed with exit status %i.", r);

        return r;
}

/*
 * A newly allocated VT uses the font from the source VT. Here we update all possibly already allocated VTs
 * with the configured font. It also allows systemd-vconsole-setup.service to be restarted to apply a new
 * font to all VTs.
 *
 * We also setup per-console utf8 related stuff: kbdmode, term processing, stty iutf8.
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
        int log_level = LOG_WARNING;
        int r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs)
                return (void) log_oom();

        /* get metadata of the current font (width, height, count) */
        r = ioctl(src_fd, KDFONTOP, &cfo);
        if (r < 0) {
                /* We might be called to operate on the dummy console (to setup keymap
                 * mainly) when fbcon deferred takeover is used for example. In such case,
                 * setting font is not supported and is expected to fail. */
                if (errno == ENOSYS)
                        log_level = LOG_DEBUG;

                log_full_errno(log_level, errno,
                               "KD_FONT_OP_GET failed while trying to get the font metadata: %m");
        } else {
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
                log_full(log_level, "Fonts will not be copied to remaining consoles");

        for (unsigned i = 1; i <= 63; i++) {
                char ttyname[sizeof("/dev/tty63")];
                _cleanup_close_ int fd_d = -EBADF;

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

                r = verify_vc_display_mode(fd_d);
                if (r < 0) {
                        log_debug_errno(r, "KD_FONT_OP_SET skipped: tty%u is not in text mode", i);
                        continue;
                }

                if (ioctl(fd_d, KDFONTOP, &cfo) < 0) {
                        log_warning_errno(errno, "KD_FONT_OP_SET failed, fonts will not be copied to tty%u: %m", i);
                        continue;
                }

                /* Copy unicode translation table unimapd is a ushort count and a pointer
                 * to an array of struct unipair { ushort, ushort }. */
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
        int r, err = 0;

        assert(ret_path);
        assert(ret_idx);

        /* This function returns an fd when it finds a candidate. When it fails, it returns the first error
         * that occurred when the VC was being opened or -EBUSY when it finds some VCs but all are busy
         * otherwise -ENOENT when there is no allocated VC. */

        for (unsigned i = 1; i <= 63; i++) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *path = NULL;

                /* We save the first error but we give less importance for the case where we previously fail
                 * due to the VCs being not allocated. Similarly errors on opening a device has a higher
                 * priority than errors due to devices either not allocated or busy. */

                r = verify_vc_allocation(i);
                if (r < 0) {
                        RET_GATHER(err, log_debug_errno(r, "VC %u existence check failed, skipping: %m", i));
                        continue;
                }

                if (asprintf(&path, "/dev/tty%u", i) < 0)
                        return log_oom();

                fd = open_terminal(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        log_debug_errno(fd, "Failed to open terminal %s, ignoring: %m", path);
                        if (IN_SET(err, 0, -EBUSY, -ENOENT))
                                err = fd;
                        continue;
                }

                r = verify_vc_kbmode(fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to check VC %s keyboard mode: %m", path);
                        if (IN_SET(err, 0, -ENOENT))
                                err = r;
                        continue;
                }

                r = verify_vc_display_mode(fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to check VC %s display mode: %m", path);
                        if (IN_SET(err, 0, -ENOENT))
                                err = r;
                        continue;
                }

                log_debug("Selecting %s as source console", path);

                /* all checks passed, return this one as a source console */
                *ret_idx = i;
                *ret_path = TAKE_PTR(path);
                return TAKE_FD(fd);
        }

        return err;
}

static int verify_source_vc(char **ret_path, const char *src_vc) {
        _cleanup_close_ int fd = -EBADF;
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

        /* setfont(8) silently ignores when the font can't be applied due to the vc being in
         * KD_GRAPHICS. Hence we continue to accept this case however we now let the user know that the vc
         * will be initialized only partially. */
        r = verify_vc_display_mode(fd);
        if (r < 0)
                log_notice_errno(r, "Virtual console %s is not in KD_TEXT, font settings likely won't be applied.", src_vc);

        path = strdup(src_vc);
        if (!path)
                return log_oom();

        *ret_path = path;
        return TAKE_FD(fd);
}

static int run(int argc, char **argv) {
        _cleanup_(context_done) Context c = {};
        _cleanup_free_ char *vc = NULL;
        _cleanup_close_ int fd = -EBADF, lock_fd = -EBADF;
        bool utf8, keyboard_ok;
        unsigned idx = 0;
        int r;

        log_setup();

        umask(0022);

        if (argv[1]) {
                fd = verify_source_vc(&vc, argv[1]);
                if (fd < 0)
                        return fd;
        } else {
                fd = find_source_vc(&vc, &idx);
                if (fd < 0 && fd != -EBUSY)
                        return log_error_errno(fd, "No usable source console found: %m");
        }

        utf8 = is_locale_utf8();
        (void) toggle_utf8_sysfs(utf8);

        if (fd < 0) {
                /* We found only busy VCs, which might happen during the boot process when the boot splash is
                 * displayed on the only allocated VC. In this case we don't interfere and avoid initializing
                 * the VC partially as some operations are likely to fail. */
                log_notice("All allocated VCs are currently busy, skipping initialization of font and keyboard settings.");
                return EXIT_SUCCESS;
        }

        context_load_config(&c);

        /* Take lock around the remaining operation to avoid being interrupted by a tty reset operation
         * performed for services with TTYVHangup=yes. */
        lock_fd = lock_dev_console();
        if (ERRNO_IS_NEG_DEVICE_ABSENT(lock_fd))
                log_debug_errno(lock_fd, "Device /dev/console does not exist, proceeding without lock: %m");
        else if (lock_fd < 0)
                log_warning_errno(lock_fd, "Failed to lock /dev/console, proceeding without lock: %m");

        (void) toggle_utf8_vc(vc, fd, utf8);

        r = font_load_and_wait(vc, &c);
        keyboard_ok = keyboard_load_and_wait(vc, &c, utf8) == 0;

        if (idx > 0) {
                if (r == 0)
                        setup_remaining_vcs(fd, idx, utf8);
                else
                        log_full(r == EX_OSERR ? LOG_NOTICE : LOG_WARNING,
                                 "Setting source virtual console failed, ignoring remaining ones.");
        }

        return IN_SET(r, 0, EX_OSERR) && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);

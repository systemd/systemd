/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "ask-password-api.h"
#include "creds-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "inotify-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "keyring-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "nulstr-util.h"
#include "path-lookup.h"
#include "plymouth-util.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"

#define KEYRING_TIMEOUT_USEC ((5 * USEC_PER_MINUTE) / 2)

static const char* keyring_table[] = {
        [-KEY_SPEC_THREAD_KEYRING]       = "thread",
        [-KEY_SPEC_PROCESS_KEYRING]      = "process",
        [-KEY_SPEC_SESSION_KEYRING]      = "session",
        [-KEY_SPEC_USER_KEYRING]         = "user",
        [-KEY_SPEC_USER_SESSION_KEYRING] = "user-session",
        [-KEY_SPEC_GROUP_KEYRING]        = "group",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(keyring, int);

static int lookup_key(const char *keyname, key_serial_t *ret) {
        key_serial_t serial;

        assert(keyname);
        assert(ret);

        serial = request_key("user", keyname, /* callout_info= */ NULL, /* dest_keyring= */ 0);
        if (serial == -1)
                return negative_errno();

        *ret = serial;
        return 0;
}

static int retrieve_key(key_serial_t serial, char ***ret) {
        _cleanup_(erase_and_freep) void *p = NULL;
        char **l;
        size_t n;
        int r;

        assert(ret);

        r = keyring_read(serial, &p, &n);
        if (r < 0)
                return r;

        l = strv_parse_nulstr(p, n);
        if (!l)
                return -ENOMEM;

        *ret = l;
        return 0;
}

static int get_ask_password_directory_for_flags(AskPasswordFlags flags, char **ret) {
        if (FLAGS_SET(flags, ASK_PASSWORD_USER))
                return acquire_user_ask_password_directory(ret);

        return strdup_to_full(ret, "/run/systemd/ask-password/"); /* Returns 1, indicating there's a suitable directory */
}

static int touch_ask_password_directory(AskPasswordFlags flags) {
        int r;

        _cleanup_free_ char *p = NULL;
        r = get_ask_password_directory_for_flags(flags, &p);
        if (r <= 0)
                return r;

        _cleanup_close_ int fd = open_mkdir(p, O_CLOEXEC, 0755);
        if (fd < 0)
                return fd;

        r = touch_fd(fd, USEC_INFINITY);
        if (r < 0)
                return r;

        return 1; /* did something */
}

static usec_t keyring_cache_timeout(void) {
        static usec_t saved_timeout = KEYRING_TIMEOUT_USEC;
        static bool saved_timeout_set = false;
        int r;

        if (saved_timeout_set)
                return saved_timeout;

        const char *e = secure_getenv("SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC");
        if (e) {
                r = parse_sec(e, &saved_timeout);
                if (r < 0)
                        log_debug_errno(r, "Invalid value in $SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC, ignoring: %s", e);
        }

        saved_timeout_set = true;

        return saved_timeout;
}

static key_serial_t keyring_cache_type(void) {
        static key_serial_t saved_keyring = KEY_SPEC_USER_KEYRING;
        static bool saved_keyring_set = false;
        int r;

        if (saved_keyring_set)
                return saved_keyring;

        const char *e = secure_getenv("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE");
        if (e) {
                key_serial_t keyring;

                r = safe_atoi32(e, &keyring);
                if (r >= 0)
                        if (keyring < 0)
                                log_debug_errno(keyring, "Invalid value in $SYSTEMD_ASK_PASSWORD_KEYRING_TYPE, ignoring: %s", e);
                        else
                                saved_keyring = keyring;
                else {
                        keyring = keyring_from_string(e);
                        if (keyring < 0)
                                log_debug_errno(keyring, "Invalid value in $SYSTEMD_ASK_PASSWORD_KEYRING_TYPE, ignoring: %s", e);
                        else
                                saved_keyring = -keyring;
                }
        }

        saved_keyring_set = true;

        return saved_keyring;
}

static int add_to_keyring(const char *keyname, AskPasswordFlags flags, char **passwords) {
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_(erase_and_freep) char *p = NULL;
        key_serial_t serial;
        size_t n;
        int r;

        assert(keyname);

        if (!FLAGS_SET(flags, ASK_PASSWORD_PUSH_CACHE) || keyring_cache_timeout() == 0)
                return 0;
        if (strv_isempty(passwords))
                return 0;

        r = lookup_key(keyname, &serial);
        if (r >= 0) {
                r = retrieve_key(serial, &l);
                if (r < 0)
                        return r;
        } else if (r != -ENOKEY)
                return r;

        r = strv_extend_strv(&l, passwords, /* filter_duplicates= */ true);
        if (r <= 0)
                return r;

        r = strv_make_nulstr(l, &p, &n);
        if (r < 0)
                return r;

        /* chop off the final NUL byte. We do this because we want to use the separator NUL bytes only if we
         * have multiple passwords. */
        n = LESS_BY(n, (size_t) 1);

        serial = add_key("user", keyname, p, n, keyring_cache_type());
        if (serial == -1)
                return -errno;

        if (keyring_cache_timeout() != USEC_INFINITY &&
                keyctl(KEYCTL_SET_TIMEOUT,
                       (unsigned long) serial,
                       (unsigned long) DIV_ROUND_UP(keyring_cache_timeout(), USEC_PER_SEC), 0, 0) < 0)
                log_debug_errno(errno, "Failed to adjust kernel keyring key timeout: %m");

        /* Tell everyone to check the keyring */
        (void) touch_ask_password_directory(flags);

        log_debug("Added key to kernel keyring as %" PRIi32 ".", serial);

        return 1;
}

static int add_to_keyring_and_log(const char *keyname, AskPasswordFlags flags, char **passwords) {
        int r;

        assert(keyname);

        r = add_to_keyring(keyname, flags, passwords);
        if (r < 0)
                return log_debug_errno(r, "Failed to add password to kernel keyring: %m");

        return 0;
}

static int ask_password_keyring(const AskPasswordRequest *req, AskPasswordFlags flags, char ***ret) {
        key_serial_t serial;
        int r;

        assert(req);
        assert(ret);

        if (!FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED))
                return -EUNATCH;

        r = lookup_key(req->keyring, &serial);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || r == -EPERM)
                /* When retrieving, the distinction between "kernel or container manager don't support or
                 * allow this" and "no matching key known" doesn't matter. Note that we propagate EACCESS
                 * here (even if EPERM not) since that is used if the keyring is available, but we lack
                 * access to the key. */
                return -ENOKEY;
        if (r < 0)
                return r;

        _cleanup_strv_free_erase_ char **l = NULL;
        r = retrieve_key(serial, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOKEY), "Found an empty password from keyring.");

        *ret = TAKE_PTR(l);
        return 0;
}

static int backspace_chars(int ttyfd, size_t p) {
        if (ttyfd < 0)
                return 0;

        _cleanup_free_ char *buf = malloc_multiply(3, p);
        if (!buf)
                return log_oom();

        for (size_t i = 0; i < p; i++)
                memcpy(buf + 3 * i, "\b \b", 3);

        return loop_write(ttyfd, buf, 3 * p);
}

static int backspace_string(int ttyfd, const char *str) {
        assert(str);

        /* Backspaces through enough characters to entirely undo printing of the specified string. */

        if (ttyfd < 0)
                return 0;

        size_t m = utf8_n_codepoints(str);
        if (m == SIZE_MAX)
                m = strlen(str); /* Not a valid UTF-8 string? If so, let's backspace the number of bytes
                                  * output. Most likely this happened because we are not in a UTF-8 locale,
                                  * and in that case that is the correct thing to do. And even if it's not,
                                  * terminals tend to stop backspacing at the leftmost column, hence
                                  * backspacing too much should be mostly OK. */

        return backspace_chars(ttyfd, m);
}

int ask_password_plymouth(
                const AskPasswordRequest *req,
                AskPasswordFlags flags,
                char ***ret) {

        _cleanup_close_ int fd = -EBADF, inotify_fd = -EBADF;
        _cleanup_free_ char *packet = NULL;
        ssize_t k;
        int r, n;
        char buffer[LINE_MAX];
        size_t p = 0;

        assert(req);
        assert(ret);

        if (FLAGS_SET(flags, ASK_PASSWORD_HEADLESS))
                return -ENOEXEC;

        const char *message = req->message ?: "Password:";

        if (req->flag_file) {
                inotify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (inotify_fd < 0)
                        return -errno;

                if (inotify_add_watch(inotify_fd, req->flag_file, IN_ATTRIB) < 0) /* for the link count */
                        return -errno;
        }

        fd = plymouth_connect(SOCK_NONBLOCK);
        if (fd < 0)
                return fd;

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED)) {
                packet = strdup("c");
                n = 1;
        } else if (asprintf(&packet, "*\002%c%s%n", (int) (strlen(message) + 1), message, &n) < 0)
                packet = NULL;
        if (!packet)
                return -ENOMEM;

        r = loop_write_full(fd, packet, n + 1, USEC_INFINITY);
        if (r < 0)
                return r;

        CLEANUP_ERASE(buffer);

        enum {
                POLL_SOCKET,
                POLL_TWO,
                POLL_THREE,
                _POLL_MAX,
        };

        struct pollfd pollfd[_POLL_MAX] = {
                [POLL_SOCKET] = {
                        .fd = fd,
                        .events = POLLIN,
                },
        };
        size_t n_pollfd = POLL_SOCKET + 1, inotify_idx = SIZE_MAX, hup_fd_idx = SIZE_MAX;
        if (inotify_fd >= 0)
                pollfd[inotify_idx = n_pollfd++] = (struct pollfd) {
                        .fd = inotify_fd,
                        .events = POLLIN,
                };
        if (req->hup_fd >= 0)
                pollfd[hup_fd_idx = n_pollfd++] = (struct pollfd) {
                        .fd = req->hup_fd,
                        .events = POLLHUP,
                };

        assert(n_pollfd <= _POLL_MAX);

        for (;;) {
                usec_t timeout;

                if (req->until > 0)
                        timeout = usec_sub_unsigned(req->until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                if (req->flag_file && access(req->flag_file, F_OK) < 0)
                        return -errno;

                r = ppoll_usec(pollfd, n_pollfd, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIME;

                if (req->hup_fd >= 0 && pollfd[hup_fd_idx].revents & POLLHUP)
                        return -ECONNRESET;

                if (inotify_fd >= 0 && pollfd[inotify_idx].revents != 0)
                        (void) flush_fd(inotify_fd);

                if (pollfd[POLL_SOCKET].revents == 0)
                        continue;

                k = read(fd, buffer + p, sizeof(buffer) - p);
                if (k < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                continue;

                        return -errno;
                }
                if (k == 0)
                        return -EIO;

                p += k;

                if (buffer[0] == 5) {

                        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED)) {
                                /* Hmm, first try with cached
                                 * passwords failed, so let's retry
                                 * with a normal password request */
                                packet = mfree(packet);

                                if (asprintf(&packet, "*\002%c%s%n", (int) (strlen(message) + 1), message, &n) < 0)
                                        return -ENOMEM;

                                r = loop_write_full(fd, packet, n + 1, USEC_INFINITY);
                                if (r < 0)
                                        return r;

                                flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
                                p = 0;
                                continue;
                        }

                        /* No password, because UI not shown */
                        return -ENOENT;

                } else if (IN_SET(buffer[0], 2, 9)) {
                        _cleanup_strv_free_erase_ char **l = NULL;
                        uint32_t size;

                        /* One or more answers */
                        if (p < 5)
                                continue;

                        memcpy(&size, buffer+1, sizeof(size));
                        size = le32toh(size);
                        if (size + 5 > sizeof(buffer))
                                return -EIO;

                        if (p-5 < size)
                                continue;

                        l = strv_parse_nulstr(buffer + 5, size);
                        if (!l)
                                return -ENOMEM;

                        if (strv_isempty(l))
                                return log_debug_errno(SYNTHETIC_ERRNO(ECANCELED), "Received an empty password.");

                        *ret = TAKE_PTR(l);
                        return 0;

                } else
                        /* Unknown packet */
                        return -EIO;
        }
}

#define NO_ECHO "(no echo) "
#define PRESS_TAB "(press TAB for no echo) "
#define SKIPPED "(skipped)"

int ask_password_tty(
                const AskPasswordRequest *req,
                AskPasswordFlags flags,
                char ***ret) {

        bool reset_tty = false, dirty = false, use_color = false, press_tab_visible = false;
        _cleanup_close_ int cttyfd = -EBADF, inotify_fd = -EBADF;
        struct termios old_termios, new_termios;
        char passphrase[LINE_MAX + 1] = {}, *x;
        _cleanup_strv_free_erase_ char **l = NULL;
        size_t p = 0, codepoint = 0;
        int r;

        assert(req);
        assert(ret);

        if (FLAGS_SET(flags, ASK_PASSWORD_HEADLESS))
                return -ENOEXEC;

        if (FLAGS_SET(flags, ASK_PASSWORD_NO_TTY))
                return -EUNATCH;

        const char *message = req->message ?: "Password:";
        const char *keyring = req->keyring;

        if (!FLAGS_SET(flags, ASK_PASSWORD_HIDE_EMOJI) && emoji_enabled())
                message = strjoina(special_glyph(SPECIAL_GLYPH_LOCK_AND_KEY), " ", message);

        if (req->flag_file || (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && keyring)) {
                inotify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (inotify_fd < 0)
                        return -errno;
        }
        if (req->flag_file)
                if (inotify_add_watch(inotify_fd, req->flag_file, IN_ATTRIB /* for the link count */) < 0)
                        return -errno;
        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && keyring) {
                r = ask_password_keyring(req, flags, ret);
                if (r >= 0)
                        return 0;
                if (r != -ENOKEY)
                        return r;

                /* Let's watch the askpw directory for mtime changes, which we issue above whenever the
                 * keyring changes */
                _cleanup_free_ char *watch_path = NULL;
                r = get_ask_password_directory_for_flags(flags, &watch_path);
                if (r < 0)
                        return r;
                if (r > 0) {
                        _cleanup_close_ int watch_fd = open_mkdir(watch_path, O_CLOEXEC|O_RDONLY, 0755);
                        if (watch_fd < 0)
                                return watch_fd;

                        r = inotify_add_watch_fd(inotify_fd, watch_fd, IN_ONLYDIR|IN_ATTRIB /* for mtime */);
                        if (r < 0)
                                return r;
                }
        }

        CLEANUP_ERASE(passphrase);

        /* If the caller didn't specify a TTY, then use the controlling tty, if we can. */
        int ttyfd;
        if (req->tty_fd < 0)
                ttyfd = cttyfd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC);
        else
                ttyfd = req->tty_fd;

        if (ttyfd >= 0) {
                if (tcgetattr(ttyfd, &old_termios) < 0)
                        return -errno;

                if (FLAGS_SET(flags, ASK_PASSWORD_CONSOLE_COLOR))
                        use_color = dev_console_colors_enabled();
                else
                        use_color = colors_enabled();

                if (use_color)
                        (void) loop_write(ttyfd, ANSI_HIGHLIGHT, SIZE_MAX);

                (void) loop_write(ttyfd, message, SIZE_MAX);
                (void) loop_write(ttyfd, " ", 1);

                if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT) && !FLAGS_SET(flags, ASK_PASSWORD_ECHO)) {
                        if (use_color)
                                (void) loop_write(ttyfd, ansi_grey(), SIZE_MAX);

                        (void) loop_write(ttyfd, PRESS_TAB, SIZE_MAX);
                        press_tab_visible = true;
                }

                if (use_color)
                        (void) loop_write(ttyfd, ANSI_NORMAL, SIZE_MAX);

                new_termios = old_termios;
                termios_disable_echo(&new_termios);

                r = RET_NERRNO(tcsetattr(ttyfd, TCSADRAIN, &new_termios));
                if (r < 0)
                        goto finish;

                reset_tty = true;
        }

        enum {
                POLL_TTY,
                POLL_TWO,
                POLL_THREE,
                _POLL_MAX,
        };

        struct pollfd pollfd[_POLL_MAX] = {
                [POLL_TTY]     = {
                        .fd = ttyfd >= 0 ? ttyfd : STDIN_FILENO,
                        .events = POLLIN,
                },
        };
        size_t n_pollfd = POLL_TTY + 1, inotify_idx = SIZE_MAX, hup_fd_idx = SIZE_MAX;

        if (inotify_fd >= 0)
                pollfd[inotify_idx = n_pollfd++] = (struct pollfd) {
                        .fd = inotify_fd,
                        .events = POLLIN,
                };
        if (req->hup_fd >= 0)
                pollfd[hup_fd_idx = n_pollfd++] = (struct pollfd) {
                        .fd = req->hup_fd,
                        .events = POLLHUP,
                };

        assert(n_pollfd <= _POLL_MAX);

        for (;;) {
                _cleanup_(erase_char) char c;
                usec_t timeout;
                ssize_t n;

                if (req->until > 0)
                        timeout = usec_sub_unsigned(req->until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                if (req->flag_file) {
                        r = RET_NERRNO(access(req->flag_file, F_OK));
                        if (r < 0)
                                goto finish;
                }

                r = ppoll_usec(pollfd, n_pollfd, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (req->hup_fd >= 0 && pollfd[hup_fd_idx].revents & POLLHUP) {
                        r = -ECONNRESET;
                        goto finish;
                }

                if (inotify_fd >= 0 && pollfd[inotify_idx].revents != 0 && keyring) {
                        (void) flush_fd(inotify_fd);

                        r = ask_password_keyring(req, flags, ret);
                        if (r >= 0) {
                                r = 0;
                                goto finish;
                        } else if (r != -ENOKEY)
                                goto finish;
                }

                if (pollfd[POLL_TTY].revents == 0)
                        continue;

                n = read(ttyfd >= 0 ? ttyfd : STDIN_FILENO, &c, 1);
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                continue;

                        r = -errno;
                        goto finish;

                }

                if (press_tab_visible) {
                        assert(ttyfd >= 0);
                        backspace_chars(ttyfd, strlen(PRESS_TAB));
                        press_tab_visible = false;
                }

                /* We treat EOF, newline and NUL byte all as valid end markers */
                if (n == 0 || c == '\n' || c == 0)
                        break;

                if (c == 4) { /* C-d also known as EOT */
                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, SKIPPED, SIZE_MAX);

                        goto skipped;
                }

                if (c == 21) { /* C-u */

                        if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT))
                                (void) backspace_string(ttyfd, passphrase);

                        explicit_bzero_safe(passphrase, sizeof(passphrase));
                        p = codepoint = 0;

                } else if (IN_SET(c, '\b', 127)) {

                        if (p > 0) {
                                size_t q;

                                if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT))
                                        (void) backspace_chars(ttyfd, 1);

                                /* Remove a full UTF-8 codepoint from the end. For that, figure out where the
                                 * last one begins */
                                q = 0;
                                for (;;) {
                                        int z;

                                        z = utf8_encoded_valid_unichar(passphrase + q, SIZE_MAX);
                                        if (z <= 0) {
                                                q = SIZE_MAX; /* Invalid UTF8! */
                                                break;
                                        }

                                        if (q + z >= p) /* This one brings us over the edge */
                                                break;

                                        q += z;
                                }

                                p = codepoint = q == SIZE_MAX ? p - 1 : q;
                                explicit_bzero_safe(passphrase + p, sizeof(passphrase) - p);

                        } else if (!dirty && !FLAGS_SET(flags, ASK_PASSWORD_SILENT)) {

                                flags |= ASK_PASSWORD_SILENT;

                                /* There are two ways to enter silent mode. Either by pressing backspace as
                                 * first key (and only as first key), or ... */

                                if (ttyfd >= 0)
                                        (void) loop_write(ttyfd, NO_ECHO, SIZE_MAX);

                        } else if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1);

                } else if (c == '\t' && !FLAGS_SET(flags, ASK_PASSWORD_SILENT)) {

                        (void) backspace_string(ttyfd, passphrase);
                        flags |= ASK_PASSWORD_SILENT;

                        /* ... or by pressing TAB at any time. */

                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, NO_ECHO, SIZE_MAX);

                } else if (p >= sizeof(passphrase)-1) {

                        /* Reached the size limit */
                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1);

                } else {
                        passphrase[p++] = c;

                        if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT) && ttyfd >= 0) {
                                /* Check if we got a complete UTF-8 character now. If so, let's output one '*'. */
                                n = utf8_encoded_valid_unichar(passphrase + codepoint, SIZE_MAX);
                                if (n >= 0) {
                                        if (FLAGS_SET(flags, ASK_PASSWORD_ECHO))
                                                (void) loop_write(ttyfd, passphrase + codepoint, n);
                                        else
                                                (void) loop_write(ttyfd,
                                                                  special_glyph(SPECIAL_GLYPH_BULLET),
                                                                  SIZE_MAX);
                                        codepoint = p;
                                }
                        }

                        dirty = true;
                }
        }

        x = strndup(passphrase, p);
        if (!x) {
                r = -ENOMEM;
                goto finish;
        }

        r = strv_consume(&l, x);
        if (r < 0)
                goto finish;

skipped:
        if (strv_isempty(l))
                r = log_debug_errno(SYNTHETIC_ERRNO(ECANCELED), "Password query was cancelled.");
        else {
                if (keyring)
                        (void) add_to_keyring_and_log(keyring, flags, l);

                *ret = TAKE_PTR(l);
                r = 0;
        }

finish:
        if (ttyfd >= 0 && reset_tty) {
                (void) loop_write(ttyfd, "\n", 1);
                (void) tcsetattr(ttyfd, TCSADRAIN, &old_termios);
        }

        return r;
}

static int create_socket(const char *askpwdir, char **ret) {
        _cleanup_free_ char *path = NULL;
        union sockaddr_union sa;
        socklen_t sa_len;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(askpwdir);
        assert(ret);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        if (asprintf(&path, "%s/sck.%" PRIx64, askpwdir, random_u64()) < 0)
                return -ENOMEM;

        r = sockaddr_un_set_path(&sa.un, path);
        if (r < 0)
                return r;
        sa_len = r;

        WITH_UMASK(0177)
                if (bind(fd, &sa.sa, sa_len) < 0)
                        return -errno;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(path);
        return TAKE_FD(fd);
}

int ask_password_agent(
                const AskPasswordRequest *req,
                AskPasswordFlags flags,
                char ***ret) {

        _cleanup_close_ int socket_fd = -EBADF, signal_fd = -EBADF, inotify_fd = -EBADF, dfd = -EBADF;
        _cleanup_(unlink_and_freep) char *socket_name = NULL;
        _cleanup_free_ char *temp = NULL, *final = NULL;
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sigset_t mask, oldmask;
        int r;

        assert(req);
        assert(ret);

        if (FLAGS_SET(flags, ASK_PASSWORD_HEADLESS))
                return -ENOEXEC;

        if (FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT))
                return -EUNATCH;

        /* We don't support the flag file concept for now when querying via the agent logic */
        if (req->flag_file)
                return -EOPNOTSUPP;

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) >= 0);

        _cleanup_free_ char *askpwdir = NULL;
        r = get_ask_password_directory_for_flags(flags, &askpwdir);
        if (r < 0)
                goto finish;
        if (r == 0) {
                r = -ENXIO;
                goto finish;
        }

        dfd = open_mkdir(askpwdir, O_RDONLY|O_CLOEXEC, 0755);
        if (dfd < 0) {
                r = log_debug_errno(dfd, "Failed to open directory '%s': %m", askpwdir);
                goto finish;
        }

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && req->keyring) {
                r = ask_password_keyring(req, flags, ret);
                if (r >= 0) {
                        r = 0;
                        goto finish;
                } else if (r != -ENOKEY)
                        goto finish;

                inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
                if (inotify_fd < 0) {
                        r = -errno;
                        goto finish;
                }

                r = inotify_add_watch_fd(inotify_fd, dfd, IN_ONLYDIR|IN_ATTRIB /* for mtime */);
                if (r < 0)
                        goto finish;
        }

        if (asprintf(&final, "ask.%" PRIu64, random_u64()) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = fopen_temporary_at(dfd, final, &f, &temp);
        if (r < 0)
                goto finish;

        signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0) {
                r = -errno;
                goto finish;
        }

        socket_fd = create_socket(askpwdir, &socket_name);
        if (socket_fd < 0) {
                r = socket_fd;
                goto finish;
        }

        fprintf(f,
                "[Ask]\n"
                "PID="PID_FMT"\n"
                "Socket=%s\n"
                "AcceptCached=%i\n"
                "Echo=%i\n"
                "NotAfter="USEC_FMT"\n"
                "Silent=%i\n",
                getpid_cached(),
                socket_name,
                FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED),
                FLAGS_SET(flags, ASK_PASSWORD_ECHO),
                req->until,
                FLAGS_SET(flags, ASK_PASSWORD_SILENT));

        if (req->message)
                fprintf(f, "Message=%s\n", req->message);

        if (req->icon)
                fprintf(f, "Icon=%s\n", req->icon);

        if (req->id)
                fprintf(f, "Id=%s\n", req->id);

        if (fchmod(fileno(f), 0644) < 0) {
                r = -errno;
                goto finish;
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        if (renameat(dfd, temp, dfd, final) < 0) {
                r = -errno;
                goto finish;
        }

        temp = mfree(temp);

        enum {
                POLL_SOCKET,
                POLL_SIGNAL,
                POLL_THREE,
                POLL_FOUR,
                _POLL_MAX
        };

        struct pollfd pollfd[_POLL_MAX] = {
                [POLL_SOCKET]  = { .fd = socket_fd,  .events = POLLIN },
                [POLL_SIGNAL]  = { .fd = signal_fd,  .events = POLLIN },
        };
        size_t n_pollfd = POLL_SIGNAL + 1, inotify_idx = SIZE_MAX, hup_fd_idx = SIZE_MAX;

        if (inotify_fd >= 0)
                pollfd[inotify_idx = n_pollfd++] = (struct pollfd) {
                        .fd = inotify_fd,
                        .events = POLLIN,
                };
        if (req->hup_fd >= 0)
                pollfd[hup_fd_idx = n_pollfd ++] = (struct pollfd) {
                        .fd = req->hup_fd,
                        .events = POLLHUP,
                };

        assert(n_pollfd <= _POLL_MAX);

        for (;;) {
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
                char passphrase[LINE_MAX+1];
                struct iovec iovec;
                struct ucred *ucred;
                usec_t timeout;
                ssize_t n;

                if (req->until > 0)
                        timeout = usec_sub_unsigned(req->until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                r = ppoll_usec(pollfd, n_pollfd, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (pollfd[POLL_SIGNAL].revents & POLLIN) {
                        r = -EINTR;
                        goto finish;
                }

                if (req->hup_fd >= 0 && pollfd[hup_fd_idx].revents & POLLHUP)
                        return -ECONNRESET;

                if (inotify_fd >= 0 && pollfd[inotify_idx].revents != 0) {
                        (void) flush_fd(inotify_fd);

                        if (req->keyring) {
                                r = ask_password_keyring(req, flags, ret);
                                if (r >= 0) {
                                        r = 0;
                                        goto finish;
                                } else if (r != -ENOKEY)
                                        goto finish;
                        }
                }

                if (pollfd[POLL_SOCKET].revents == 0)
                        continue;

                if (pollfd[POLL_SOCKET].revents != POLLIN) {
                        r = -EIO;
                        goto finish;
                }

                iovec = IOVEC_MAKE(passphrase, sizeof(passphrase));

                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };

                n = recvmsg_safe(socket_fd, &msghdr, 0);
                if (ERRNO_IS_NEG_TRANSIENT(n))
                        continue;
                if (n == -ECHRNG) {
                        log_debug_errno(n, "Got message with truncated control data (unexpected fds sent?), ignoring.");
                        continue;
                }
                if (n == -EXFULL) {
                        log_debug_errno(n, "Got message with truncated payload data, ignoring.");
                        continue;
                }
                if (n < 0) {
                        r = (int) n;
                        goto finish;
                }

                CLEANUP_ERASE(passphrase);

                cmsg_close_all(&msghdr);

                if (n == 0) {
                        log_debug("Message too short");
                        continue;
                }

                ucred = CMSG_FIND_DATA(&msghdr, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
                if (!ucred) {
                        log_debug("Received message without credentials. Ignoring.");
                        continue;
                }

                if (ucred->uid != getuid() && ucred->uid != 0) {
                        log_debug("Got response from bad user. Ignoring.");
                        continue;
                }

                if (passphrase[0] == '+') {
                        /* An empty message refers to the empty password */
                        if (n == 1)
                                l = strv_new("");
                        else
                                l = strv_parse_nulstr(passphrase+1, n-1);
                        if (!l) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (strv_isempty(l)) {
                                l = strv_free(l);
                                log_debug("Invalid packet");
                                continue;
                        }

                        break;
                }

                if (passphrase[0] == '-') {
                        r = -ECANCELED;
                        goto finish;
                }

                log_debug("Invalid packet");
        }

        if (req->keyring)
                (void) add_to_keyring_and_log(req->keyring, flags, l);

        *ret = TAKE_PTR(l);
        r = 0;

finish:
        if (temp) {
                assert(dfd >= 0);
                (void) unlinkat(dfd, temp, 0);
        } else if (final) {
                assert(dfd >= 0);
                (void) unlinkat(dfd, final, 0);
        }

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);
        return r;
}

static int ask_password_credential(const AskPasswordRequest *req, AskPasswordFlags flags, char ***ret) {
        _cleanup_(erase_and_freep) char *buffer = NULL;
        _cleanup_strv_free_erase_ char **l = NULL;
        size_t size;
        int r;

        assert(req);
        assert(req->credential);
        assert(ret);

        r = read_credential(req->credential, (void**) &buffer, &size);
        if (IN_SET(r, -ENXIO, -ENOENT)) /* No credentials passed or this credential not defined? */
                return -ENOKEY;

        l = strv_parse_nulstr(buffer, size);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOKEY), "Found an empty password in credential.");

        *ret = TAKE_PTR(l);
        return 0;
}

int ask_password_auto(
                const AskPasswordRequest *req,
                AskPasswordFlags flags,
                char ***ret) {

        int r;

        assert(req);
        assert(ret);

        /* Returns the following well-known errors:
         *
         *      -ETIME → a timeout was specified and hit
         *    -EUNATCH → couldn't ask interactively and no cached password available either
         *     -ENOENT → the specified flag file disappeared
         *  -ECANCELED → the user explicitly cancelled the request
         *      -EINTR → SIGINT/SIGTERM where received during the query
         *    -ENOEXEC → headless mode was requested but no password could be acquired non-interactively
         * -ECONNRESET → a POLLHUP has been seen on the specified hup_fd
         */

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_CREDENTIAL) && req->credential) {
                r = ask_password_credential(req, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) &&
            req->keyring &&
            (FLAGS_SET(flags, ASK_PASSWORD_NO_TTY) || !isatty_safe(STDIN_FILENO)) &&
            FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT)) {
                r = ask_password_keyring(req, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_TTY) && isatty_safe(STDIN_FILENO))
                return ask_password_tty(req, flags, ret);

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT))
                return ask_password_agent(req, flags, ret);

        return -EUNATCH;
}

int acquire_user_ask_password_directory(char **ret) {
        int r;

        r = xdg_user_runtime_dir("systemd/ask-password", ret);
        if (r == -ENXIO) {
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        return 1;
}

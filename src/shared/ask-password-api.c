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
#include "ask-password-api.h"
#include "creds-util.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "io-util.h"
#include "keyring-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"

#define KEYRING_TIMEOUT_USEC ((5 * USEC_PER_MINUTE) / 2)

static int lookup_key(const char *keyname, key_serial_t *ret) {
        key_serial_t serial;

        assert(keyname);
        assert(ret);

        serial = request_key("user", keyname, NULL, 0);
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

static int add_to_keyring(const char *keyname, AskPasswordFlags flags, char **passwords) {
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_(erase_and_freep) char *p = NULL;
        key_serial_t serial;
        size_t n;
        int r;

        assert(keyname);

        if (!FLAGS_SET(flags, ASK_PASSWORD_PUSH_CACHE))
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

        r = strv_extend_strv(&l, passwords, true);
        if (r <= 0)
                return r;

        r = strv_make_nulstr(l, &p, &n);
        if (r < 0)
                return r;

        serial = add_key("user", keyname, p, n, KEY_SPEC_USER_KEYRING);
        if (serial == -1)
                return -errno;

        if (keyctl(KEYCTL_SET_TIMEOUT,
                   (unsigned long) serial,
                   (unsigned long) DIV_ROUND_UP(KEYRING_TIMEOUT_USEC, USEC_PER_SEC), 0, 0) < 0)
                log_debug_errno(errno, "Failed to adjust kernel keyring key timeout: %m");

        /* Tell everyone to check the keyring */
        (void) touch("/run/systemd/ask-password");

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

static int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret) {

        key_serial_t serial;
        int r;

        assert(keyname);
        assert(ret);

        if (!FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED))
                return -EUNATCH;

        r = lookup_key(keyname, &serial);
        if (r < 0) {
                /* when retrieving the distinction between "kernel or container manager don't support
                 * or allow this" and "no matching key known" doesn't matter. Note that we propagate
                 * EACCESS here (even if EPERM not) since that is used if the keyring is available but
                 * we lack access to the key. */
                if (ERRNO_IS_NOT_SUPPORTED(r) || r == -EPERM)
                        return -ENOKEY;

                return r;
        }

        return retrieve_key(serial, ret);
}

static int backspace_chars(int ttyfd, size_t p) {
        if (ttyfd < 0)
                return 0;

        _cleanup_free_ char *buf = malloc_multiply(3, p);
        if (!buf)
                return log_oom();

        for (size_t i = 0; i < p; i++)
                memcpy(buf + 3 * i, "\b \b", 3);

        return loop_write(ttyfd, buf, 3*p, false);
}

static int backspace_string(int ttyfd, const char *str) {
        assert(str);

        /* Backspaces through enough characters to entirely undo printing of the specified string. */

        if (ttyfd < 0)
                return 0;

        size_t m = utf8_n_codepoints(str);
        if (m == SIZE_MAX)
                m = strlen(str); /* Not a valid UTF-8 string? If so, let's backspace the number of bytes
                                  * output. Most likely this happened because we are not in an UTF-8 locale,
                                  * and in that case that is the correct thing to do. And even if it's not,
                                  * terminals tend to stop backspacing at the leftmost column, hence
                                  * backspacing too much should be mostly OK. */

        return backspace_chars(ttyfd, m);
}

int ask_password_plymouth(
                const char *message,
                usec_t until,
                AskPasswordFlags flags,
                const char *flag_file,
                char ***ret) {

        static const union sockaddr_union sa = PLYMOUTH_SOCKET;
        _cleanup_close_ int fd = -1, notify = -1;
        _cleanup_free_ char *packet = NULL;
        ssize_t k;
        int r, n;
        struct pollfd pollfd[2] = {};
        char buffer[LINE_MAX];
        size_t p = 0;
        enum {
                POLL_SOCKET,
                POLL_INOTIFY
        };

        assert(ret);

        if (!message)
                message = "Password:";

        if (flag_file) {
                notify = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (notify < 0)
                        return -errno;

                r = inotify_add_watch(notify, flag_file, IN_ATTRIB); /* for the link count */
                if (r < 0)
                        return -errno;
        }

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        r = connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0)
                return -errno;

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED)) {
                packet = strdup("c");
                n = 1;
        } else if (asprintf(&packet, "*\002%c%s%n", (int) (strlen(message) + 1), message, &n) < 0)
                packet = NULL;
        if (!packet)
                return -ENOMEM;

        r = loop_write(fd, packet, n + 1, true);
        if (r < 0)
                return r;

        pollfd[POLL_SOCKET].fd = fd;
        pollfd[POLL_SOCKET].events = POLLIN;
        pollfd[POLL_INOTIFY].fd = notify;
        pollfd[POLL_INOTIFY].events = POLLIN;

        for (;;) {
                usec_t timeout;

                if (until > 0)
                        timeout = usec_sub_unsigned(until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                if (flag_file && access(flag_file, F_OK) < 0) {
                        r = -errno;
                        goto finish;
                }

                r = ppoll_usec(pollfd, notify >= 0 ? 2 : 1, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (notify >= 0 && pollfd[POLL_INOTIFY].revents != 0)
                        (void) flush_fd(notify);

                if (pollfd[POLL_SOCKET].revents == 0)
                        continue;

                k = read(fd, buffer + p, sizeof(buffer) - p);
                if (k < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                continue;

                        r = -errno;
                        goto finish;
                }
                if (k == 0) {
                        r = -EIO;
                        goto finish;
                }

                p += k;

                if (buffer[0] == 5) {

                        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED)) {
                                /* Hmm, first try with cached
                                 * passwords failed, so let's retry
                                 * with a normal password request */
                                packet = mfree(packet);

                                if (asprintf(&packet, "*\002%c%s%n", (int) (strlen(message) + 1), message, &n) < 0) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                r = loop_write(fd, packet, n+1, true);
                                if (r < 0)
                                        goto finish;

                                flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
                                p = 0;
                                continue;
                        }

                        /* No password, because UI not shown */
                        r = -ENOENT;
                        goto finish;

                } else if (IN_SET(buffer[0], 2, 9)) {
                        uint32_t size;
                        char **l;

                        /* One or more answers */
                        if (p < 5)
                                continue;

                        memcpy(&size, buffer+1, sizeof(size));
                        size = le32toh(size);
                        if (size + 5 > sizeof(buffer)) {
                                r = -EIO;
                                goto finish;
                        }

                        if (p-5 < size)
                                continue;

                        l = strv_parse_nulstr(buffer + 5, size);
                        if (!l) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        *ret = l;
                        break;

                } else {
                        /* Unknown packet */
                        r = -EIO;
                        goto finish;
                }
        }

        r = 0;

finish:
        explicit_bzero_safe(buffer, sizeof(buffer));
        return r;
}

#define NO_ECHO "(no echo) "
#define PRESS_TAB "(press TAB for no echo) "
#define SKIPPED "(skipped)"

int ask_password_tty(
                int ttyfd,
                const char *message,
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                const char *flag_file,
                char ***ret) {

        enum {
                POLL_TTY,
                POLL_INOTIFY,
                _POLL_MAX,
        };

        bool reset_tty = false, dirty = false, use_color = false, press_tab_visible = false;
        _cleanup_close_ int cttyfd = -1, notify = -1;
        struct termios old_termios, new_termios;
        char passphrase[LINE_MAX + 1] = {}, *x;
        _cleanup_strv_free_erase_ char **l = NULL;
        struct pollfd pollfd[_POLL_MAX];
        size_t p = 0, codepoint = 0;
        int r;

        assert(ret);

        if (FLAGS_SET(flags, ASK_PASSWORD_NO_TTY))
                return -EUNATCH;

        if (!message)
                message = "Password:";

        if (!FLAGS_SET(flags, ASK_PASSWORD_HIDE_EMOJI) && emoji_enabled())
                message = strjoina(special_glyph(SPECIAL_GLYPH_LOCK_AND_KEY), " ", message);

        if (flag_file || (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && keyname)) {
                notify = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (notify < 0)
                        return -errno;
        }
        if (flag_file) {
                if (inotify_add_watch(notify, flag_file, IN_ATTRIB /* for the link count */) < 0)
                        return -errno;
        }
        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && keyname) {
                r = ask_password_keyring(keyname, flags, ret);
                if (r >= 0)
                        return 0;
                else if (r != -ENOKEY)
                        return r;

                if (inotify_add_watch(notify, "/run/systemd/ask-password", IN_ATTRIB /* for mtime */) < 0)
                        return -errno;
        }

        /* If the caller didn't specify a TTY, then use the controlling tty, if we can. */
        if (ttyfd < 0)
                ttyfd = cttyfd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC);

        if (ttyfd >= 0) {
                if (tcgetattr(ttyfd, &old_termios) < 0)
                        return -errno;

                if (FLAGS_SET(flags, ASK_PASSWORD_CONSOLE_COLOR))
                        use_color = dev_console_colors_enabled();
                else
                        use_color = colors_enabled();

                if (use_color)
                        (void) loop_write(ttyfd, ANSI_HIGHLIGHT, STRLEN(ANSI_HIGHLIGHT), false);

                (void) loop_write(ttyfd, message, strlen(message), false);
                (void) loop_write(ttyfd, " ", 1, false);

                if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT) && !FLAGS_SET(flags, ASK_PASSWORD_ECHO)) {
                        if (use_color)
                                (void) loop_write(ttyfd, ansi_grey(), strlen(ansi_grey()), false);
                        (void) loop_write(ttyfd, PRESS_TAB, strlen(PRESS_TAB), false);
                        press_tab_visible = true;
                }

                if (use_color)
                        (void) loop_write(ttyfd, ANSI_NORMAL, STRLEN(ANSI_NORMAL), false);

                new_termios = old_termios;
                new_termios.c_lflag &= ~(ICANON|ECHO);
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(ttyfd, TCSADRAIN, &new_termios) < 0) {
                        r = -errno;
                        goto finish;
                }

                reset_tty = true;
        }

        pollfd[POLL_TTY] = (struct pollfd) {
                .fd = ttyfd >= 0 ? ttyfd : STDIN_FILENO,
                .events = POLLIN,
        };
        pollfd[POLL_INOTIFY] = (struct pollfd) {
                .fd = notify,
                .events = POLLIN,
        };

        for (;;) {
                _cleanup_(erase_char) char c;
                usec_t timeout;
                ssize_t n;

                if (until > 0)
                        timeout = usec_sub_unsigned(until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                if (flag_file)
                        if (access(flag_file, F_OK) < 0) {
                                r = -errno;
                                goto finish;
                        }

                r = ppoll_usec(pollfd, notify >= 0 ? 2 : 1, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (notify >= 0 && pollfd[POLL_INOTIFY].revents != 0 && keyname) {
                        (void) flush_fd(notify);

                        r = ask_password_keyring(keyname, flags, ret);
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
                                (void) loop_write(ttyfd, SKIPPED, strlen(SKIPPED), false);

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
                                        (void) loop_write(ttyfd, NO_ECHO, strlen(NO_ECHO), false);

                        } else if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1, false);

                } else if (c == '\t' && !FLAGS_SET(flags, ASK_PASSWORD_SILENT)) {

                        (void) backspace_string(ttyfd, passphrase);
                        flags |= ASK_PASSWORD_SILENT;

                        /* ... or by pressing TAB at any time. */

                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, NO_ECHO, strlen(NO_ECHO), false);

                } else if (p >= sizeof(passphrase)-1) {

                        /* Reached the size limit */
                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1, false);

                } else {
                        passphrase[p++] = c;

                        if (!FLAGS_SET(flags, ASK_PASSWORD_SILENT) && ttyfd >= 0) {
                                /* Check if we got a complete UTF-8 character now. If so, let's output one '*'. */
                                n = utf8_encoded_valid_unichar(passphrase + codepoint, SIZE_MAX);
                                if (n >= 0) {
                                        if (FLAGS_SET(flags, ASK_PASSWORD_ECHO))
                                                (void) loop_write(ttyfd, passphrase + codepoint, n, false);
                                        else
                                                (void) loop_write(ttyfd, "*", 1, false);
                                        codepoint = p;
                                }
                        }

                        dirty = true;
                }
        }

        x = strndup(passphrase, p);
        explicit_bzero_safe(passphrase, sizeof(passphrase));
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
                if (keyname)
                        (void) add_to_keyring_and_log(keyname, flags, l);

                *ret = TAKE_PTR(l);
                r = 0;
        }

finish:
        if (ttyfd >= 0 && reset_tty) {
                (void) loop_write(ttyfd, "\n", 1, false);
                (void) tcsetattr(ttyfd, TCSADRAIN, &old_termios);
        }

        return r;
}

static int create_socket(char **ret) {
        _cleanup_free_ char *path = NULL;
        union sockaddr_union sa;
        socklen_t sa_len;
        _cleanup_close_ int fd = -1;
        int r;

        assert(ret);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        if (asprintf(&path, "/run/systemd/ask-password/sck.%" PRIx64, random_u64()) < 0)
                return -ENOMEM;

        r = sockaddr_un_set_path(&sa.un, path);
        if (r < 0)
                return r;
        sa_len = r;

        RUN_WITH_UMASK(0177)
                if (bind(fd, &sa.sa, sa_len) < 0)
                        return -errno;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(path);
        return TAKE_FD(fd);
}

int ask_password_agent(
                const char *message,
                const char *icon,
                const char *id,
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                char ***ret) {

        enum {
                FD_SOCKET,
                FD_SIGNAL,
                FD_INOTIFY,
                _FD_MAX
        };

        _cleanup_close_ int socket_fd = -1, signal_fd = -1, notify = -1, fd = -1;
        char temp[] = "/run/systemd/ask-password/tmp.XXXXXX";
        char final[sizeof(temp)] = "";
        _cleanup_free_ char *socket_name = NULL;
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct pollfd pollfd[_FD_MAX];
        sigset_t mask, oldmask;
        int r;

        assert(ret);

        if (FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT))
                return -EUNATCH;

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM, -1) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) >= 0);

        (void) mkdir_p_label("/run/systemd/ask-password", 0755);

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) && keyname) {
                r = ask_password_keyring(keyname, flags, ret);
                if (r >= 0) {
                        r = 0;
                        goto finish;
                } else if (r != -ENOKEY)
                        goto finish;

                notify = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
                if (notify < 0) {
                        r = -errno;
                        goto finish;
                }
                if (inotify_add_watch(notify, "/run/systemd/ask-password", IN_ATTRIB /* for mtime */) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        fd = mkostemp_safe(temp);
        if (fd < 0) {
                r = fd;
                goto finish;
        }

        (void) fchmod(fd, 0644);

        f = take_fdopen(&fd, "w");
        if (!f) {
                r = -errno;
                goto finish;
        }

        signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0) {
                r = -errno;
                goto finish;
        }

        socket_fd = create_socket(&socket_name);
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
                until,
                FLAGS_SET(flags, ASK_PASSWORD_SILENT));

        if (message)
                fprintf(f, "Message=%s\n", message);

        if (icon)
                fprintf(f, "Icon=%s\n", icon);

        if (id)
                fprintf(f, "Id=%s\n", id);

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        memcpy(final, temp, sizeof(temp));

        final[sizeof(final)-11] = 'a';
        final[sizeof(final)-10] = 's';
        final[sizeof(final)-9] = 'k';

        if (rename(temp, final) < 0) {
                r = -errno;
                goto finish;
        }

        zero(pollfd);
        pollfd[FD_SOCKET].fd = socket_fd;
        pollfd[FD_SOCKET].events = POLLIN;
        pollfd[FD_SIGNAL].fd = signal_fd;
        pollfd[FD_SIGNAL].events = POLLIN;
        pollfd[FD_INOTIFY].fd = notify;
        pollfd[FD_INOTIFY].events = POLLIN;

        for (;;) {
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
                char passphrase[LINE_MAX+1];
                struct iovec iovec;
                struct ucred *ucred;
                usec_t timeout;
                ssize_t n;

                if (until > 0)
                        timeout = usec_sub_unsigned(until, now(CLOCK_MONOTONIC));
                else
                        timeout = USEC_INFINITY;

                r = ppoll_usec(pollfd, notify >= 0 ? _FD_MAX : _FD_MAX - 1, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (pollfd[FD_SIGNAL].revents & POLLIN) {
                        r = -EINTR;
                        goto finish;
                }

                if (notify >= 0 && pollfd[FD_INOTIFY].revents != 0) {
                        (void) flush_fd(notify);

                        r = ask_password_keyring(keyname, flags, ret);
                        if (r >= 0) {
                                r = 0;
                                goto finish;
                        } else if (r != -ENOKEY)
                                goto finish;
                }

                if (pollfd[FD_SOCKET].revents == 0)
                        continue;

                if (pollfd[FD_SOCKET].revents != POLLIN) {
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
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(n))
                                continue;
                        if (n == -EXFULL) {
                                log_debug("Got message with truncated control data, ignoring.");
                                continue;
                        }

                        r = (int) n;
                        goto finish;
                }

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

                if (ucred->uid != 0) {
                        log_debug("Got request from unprivileged user. Ignoring.");
                        continue;
                }

                if (passphrase[0] == '+') {
                        /* An empty message refers to the empty password */
                        if (n == 1)
                                l = strv_new("");
                        else
                                l = strv_parse_nulstr(passphrase+1, n-1);
                        explicit_bzero_safe(passphrase, n);
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

        if (keyname)
                (void) add_to_keyring_and_log(keyname, flags, l);

        *ret = TAKE_PTR(l);
        r = 0;

finish:
        if (socket_name)
                (void) unlink(socket_name);

        (void) unlink(temp);

        if (final[0])
                (void) unlink(final);

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);
        return r;
}

static int ask_password_credential(const char *credential_name, AskPasswordFlags flags, char ***ret) {
        _cleanup_(erase_and_freep) char *buffer = NULL;
        size_t size;
        char **l;
        int r;

        assert(credential_name);
        assert(ret);

        r = read_credential(credential_name, (void**) &buffer, &size);
        if (IN_SET(r, -ENXIO, -ENOENT)) /* No credentials passed or this credential not defined? */
                return -ENOKEY;

        l = strv_parse_nulstr(buffer, size);
        if (!l)
                return -ENOMEM;

        *ret = l;
        return 0;
}

int ask_password_auto(
                const char *message,
                const char *icon,
                const char *id,                /* id in "ask-password" protocol */
                const char *key_name,          /* name in kernel keyring */
                const char *credential_name,   /* name in $CREDENTIALS_DIRECTORY directory */
                usec_t until,
                AskPasswordFlags flags,
                char ***ret) {

        int r;

        assert(ret);

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_CREDENTIAL) && credential_name) {
                r = ask_password_credential(credential_name, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (FLAGS_SET(flags, ASK_PASSWORD_ACCEPT_CACHED) &&
            key_name &&
            (FLAGS_SET(flags, ASK_PASSWORD_NO_TTY) || !isatty(STDIN_FILENO)) &&
            FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT)) {
                r = ask_password_keyring(key_name, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_TTY) && isatty(STDIN_FILENO))
                return ask_password_tty(-1, message, key_name, until, flags, NULL, ret);

        if (!FLAGS_SET(flags, ASK_PASSWORD_NO_AGENT))
                return ask_password_agent(message, icon, id, key_name, until, flags, ret);

        return -EUNATCH;
}

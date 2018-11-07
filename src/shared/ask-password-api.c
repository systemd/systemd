/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "umask-util.h"
#include "utf8.h"
#include "util.h"

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
        _cleanup_free_ char *p = NULL;
        long m = 100, n;
        char **l;

        assert(ret);

        for (;;) {
                p = new(char, m);
                if (!p)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) p, (unsigned long) m, 0);
                if (n < 0)
                        return -errno;

                if (n < m)
                        break;

                explicit_bzero_safe(p, n);
                free(p);
                m *= 2;
        }

        l = strv_parse_nulstr(p, n);
        if (!l)
                return -ENOMEM;

        explicit_bzero_safe(p, n);

        *ret = l;
        return 0;
}

static int add_to_keyring(const char *keyname, AskPasswordFlags flags, char **passwords) {
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_free_ char *p = NULL;
        key_serial_t serial;
        size_t n;
        int r;

        assert(keyname);
        assert(passwords);

        if (!(flags & ASK_PASSWORD_PUSH_CACHE))
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
        explicit_bzero_safe(p, n);
        if (serial == -1)
                return -errno;

        if (keyctl(KEYCTL_SET_TIMEOUT,
                   (unsigned long) serial,
                   (unsigned long) DIV_ROUND_UP(KEYRING_TIMEOUT_USEC, USEC_PER_SEC), 0, 0) < 0)
                log_debug_errno(errno, "Failed to adjust timeout: %m");

        /* Tell everyone to check the keyring */
        (void) touch("/run/systemd/ask-password");

        log_debug("Added key to keyring as %" PRIi32 ".", serial);

        return 1;
}

static int add_to_keyring_and_log(const char *keyname, AskPasswordFlags flags, char **passwords) {
        int r;

        assert(keyname);
        assert(passwords);

        r = add_to_keyring(keyname, flags, passwords);
        if (r < 0)
                return log_debug_errno(r, "Failed to add password to keyring: %m");

        return 0;
}

int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret) {

        key_serial_t serial;
        int r;

        assert(keyname);
        assert(ret);

        if (!(flags & ASK_PASSWORD_ACCEPT_CACHED))
                return -EUNATCH;

        r = lookup_key(keyname, &serial);
        if (r == -ENOSYS) /* when retrieving the distinction doesn't matter */
                return -ENOKEY;
        if (r < 0)
                return r;

        return retrieve_key(serial, ret);
}

static void backspace_chars(int ttyfd, size_t p) {

        if (ttyfd < 0)
                return;

        while (p > 0) {
                p--;

                loop_write(ttyfd, "\b \b", 3, false);
        }
}

static void backspace_string(int ttyfd, const char *str) {
        size_t m;

        assert(str);

        if (ttyfd < 0)
                return;

        /* Backspaces through enough characters to entirely undo printing of the specified string. */

        m = utf8_n_codepoints(str);
        if (m == (size_t) -1)
                m = strlen(str); /* Not a valid UTF-8 string? If so, let's backspace the number of bytes output. Most
                                  * likely this happened because we are not in an UTF-8 locale, and in that case that
                                  * is the correct thing to do. And even if it's not, terminals tend to stop
                                  * backspacing at the leftmost column, hence backspacing too much should be mostly
                                  * OK. */

        backspace_chars(ttyfd, m);
}

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

        bool reset_tty = false, dirty = false, use_color = false;
        _cleanup_close_ int cttyfd = -1, notify = -1;
        struct termios old_termios, new_termios;
        char passphrase[LINE_MAX + 1] = {}, *x;
        _cleanup_strv_free_erase_ char **l = NULL;
        struct pollfd pollfd[_POLL_MAX];
        size_t p = 0, codepoint = 0;
        int r;

        assert(ret);

        if (flags & ASK_PASSWORD_NO_TTY)
                return -EUNATCH;

        if (!message)
                message = "Password:";

        if (flag_file || ((flags & ASK_PASSWORD_ACCEPT_CACHED) && keyname)) {
                notify = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (notify < 0)
                        return -errno;
        }
        if (flag_file) {
                if (inotify_add_watch(notify, flag_file, IN_ATTRIB /* for the link count */) < 0)
                        return -errno;
        }
        if ((flags & ASK_PASSWORD_ACCEPT_CACHED) && keyname) {
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

                if (flags & ASK_PASSWORD_CONSOLE_COLOR)
                        use_color = dev_console_colors_enabled();
                else
                        use_color = colors_enabled();

                if (use_color)
                        (void) loop_write(ttyfd, ANSI_HIGHLIGHT, STRLEN(ANSI_HIGHLIGHT), false);

                (void) loop_write(ttyfd, message, strlen(message), false);
                (void) loop_write(ttyfd, " ", 1, false);

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
                int sleep_for = -1, k;
                ssize_t n;
                char c;

                if (until > 0) {
                        usec_t y;

                        y = now(CLOCK_MONOTONIC);

                        if (y > until) {
                                r = -ETIME;
                                goto finish;
                        }

                        sleep_for = (int) DIV_ROUND_UP(until - y, USEC_PER_MSEC);
                }

                if (flag_file)
                        if (access(flag_file, F_OK) < 0) {
                                r = -errno;
                                goto finish;
                        }

                k = poll(pollfd, notify >= 0 ? 2 : 1, sleep_for);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                } else if (k == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (notify >= 0 && pollfd[POLL_INOTIFY].revents != 0) {
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
                        if (IN_SET(errno, EINTR, EAGAIN))
                                continue;

                        r = -errno;
                        goto finish;

                }

                /* We treat EOF, newline and NUL byte all as valid end markers */
                if (n == 0 || c == '\n' || c == 0)
                        break;

                if (c == 21) { /* C-u */

                        if (!(flags & ASK_PASSWORD_SILENT))
                                backspace_string(ttyfd, passphrase);

                        explicit_bzero_safe(passphrase, sizeof(passphrase));
                        p = codepoint = 0;

                } else if (IN_SET(c, '\b', 127)) {

                        if (p > 0) {
                                size_t q;

                                if (!(flags & ASK_PASSWORD_SILENT))
                                        backspace_chars(ttyfd, 1);

                                /* Remove a full UTF-8 codepoint from the end. For that, figure out where the last one
                                 * begins */
                                q = 0;
                                for (;;) {
                                        size_t z;

                                        z = utf8_encoded_valid_unichar(passphrase + q);
                                        if (z == 0) {
                                                q = (size_t) -1; /* Invalid UTF8! */
                                                break;
                                        }

                                        if (q + z >= p) /* This one brings us over the edge */
                                                break;

                                        q += z;
                                }

                                p = codepoint = q == (size_t) -1 ? p - 1 : q;
                                explicit_bzero_safe(passphrase + p, sizeof(passphrase) - p);

                        } else if (!dirty && !(flags & ASK_PASSWORD_SILENT)) {

                                flags |= ASK_PASSWORD_SILENT;

                                /* There are two ways to enter silent mode. Either by pressing backspace as first key
                                 * (and only as first key), or ... */

                                if (ttyfd >= 0)
                                        (void) loop_write(ttyfd, "(no echo) ", 10, false);

                        } else if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1, false);

                } else if (c == '\t' && !(flags & ASK_PASSWORD_SILENT)) {

                        backspace_string(ttyfd, passphrase);
                        flags |= ASK_PASSWORD_SILENT;

                        /* ... or by pressing TAB at any time. */

                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "(no echo) ", 10, false);

                } else if (p >= sizeof(passphrase)-1) {

                        /* Reached the size limit */
                        if (ttyfd >= 0)
                                (void) loop_write(ttyfd, "\a", 1, false);

                } else {
                        passphrase[p++] = c;

                        if (!(flags & ASK_PASSWORD_SILENT) && ttyfd >= 0) {
                                /* Check if we got a complete UTF-8 character now. If so, let's output one '*'. */
                                n = utf8_encoded_valid_unichar(passphrase + codepoint);
                                if (n >= 0) {
                                        codepoint = p;
                                        (void) loop_write(ttyfd, (flags & ASK_PASSWORD_ECHO) ? &c : "*", 1, false);
                                }
                        }

                        dirty = true;
                }

                /* Let's forget this char, just to not keep needlessly copies of key material around */
                c = 'x';
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

        if (keyname)
                (void) add_to_keyring_and_log(keyname, flags, l);

        *ret = TAKE_PTR(l);
        r = 0;

finish:
        if (ttyfd >= 0 && reset_tty) {
                (void) loop_write(ttyfd, "\n", 1, false);
                (void) tcsetattr(ttyfd, TCSADRAIN, &old_termios);
        }

        return r;
}

static int create_socket(char **ret) {
        _cleanup_free_ char *path = NULL;
        union sockaddr_union sa = {};
        _cleanup_close_ int fd = -1;
        int salen, r;

        assert(ret);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        if (asprintf(&path, "/run/systemd/ask-password/sck.%" PRIx64, random_u64()) < 0)
                return -ENOMEM;

        salen = sockaddr_un_set_path(&sa.un, path);
        if (salen < 0)
                return salen;

        RUN_WITH_UMASK(0177) {
                if (bind(fd, &sa.sa, salen) < 0)
                        return -errno;
        }

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

        if (flags & ASK_PASSWORD_NO_AGENT)
                return -EUNATCH;

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM, -1) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) >= 0);

        (void) mkdir_p_label("/run/systemd/ask-password", 0755);

        if ((flags & ASK_PASSWORD_ACCEPT_CACHED) && keyname) {
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

        f = fdopen(fd, "w");
        if (!f) {
                r = -errno;
                goto finish;
        }

        fd = -1;

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
                "NotAfter="USEC_FMT"\n",
                getpid_cached(),
                socket_name,
                (flags & ASK_PASSWORD_ACCEPT_CACHED) ? 1 : 0,
                (flags & ASK_PASSWORD_ECHO) ? 1 : 0,
                until);

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
                char passphrase[LINE_MAX+1];
                struct msghdr msghdr;
                struct iovec iovec;
                struct ucred *ucred;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control;
                ssize_t n;
                int k;
                usec_t t;

                t = now(CLOCK_MONOTONIC);

                if (until > 0 && until <= t) {
                        r = -ETIME;
                        goto finish;
                }

                k = poll(pollfd, notify >= 0 ? _FD_MAX : _FD_MAX - 1, until > 0 ? (int) ((until-t)/USEC_PER_MSEC) : -1);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                }

                if (k <= 0) {
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

                zero(iovec);
                iovec.iov_base = passphrase;
                iovec.iov_len = sizeof(passphrase);

                zero(control);
                zero(msghdr);
                msghdr.msg_iov = &iovec;
                msghdr.msg_iovlen = 1;
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                n = recvmsg(socket_fd, &msghdr, 0);
                if (n < 0) {
                        if (IN_SET(errno, EAGAIN, EINTR))
                                continue;

                        r = -errno;
                        goto finish;
                }

                cmsg_close_all(&msghdr);

                if (n <= 0) {
                        log_debug("Message too short");
                        continue;
                }

                if (msghdr.msg_controllen < CMSG_LEN(sizeof(struct ucred)) ||
                    control.cmsghdr.cmsg_level != SOL_SOCKET ||
                    control.cmsghdr.cmsg_type != SCM_CREDENTIALS ||
                    control.cmsghdr.cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                        log_debug("Received message without credentials. Ignoring.");
                        continue;
                }

                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
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

int ask_password_auto(
                const char *message,
                const char *icon,
                const char *id,
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                char ***ret) {

        int r;

        assert(ret);

        if ((flags & ASK_PASSWORD_ACCEPT_CACHED) &&
            keyname &&
            ((flags & ASK_PASSWORD_NO_TTY) || !isatty(STDIN_FILENO)) &&
            (flags & ASK_PASSWORD_NO_AGENT)) {
                r = ask_password_keyring(keyname, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (!(flags & ASK_PASSWORD_NO_TTY) && isatty(STDIN_FILENO))
                return ask_password_tty(-1, message, keyname, until, flags, NULL, ret);

        if (!(flags & ASK_PASSWORD_NO_AGENT))
                return ask_password_agent(message, icon, id, keyname, until, flags, ret);

        return -EUNATCH;
}

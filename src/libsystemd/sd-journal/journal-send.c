/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <printf.h>
#include <stddef.h>
#include <sys/un.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#define SD_JOURNAL_SUPPRESS_LOCATION

#include "sd-journal.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-send.h"
#include "memfd-util.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

#define SNDBUF_SIZE (8*1024*1024)

#define ALLOCA_CODE_FUNC(f, func)                 \
        do {                                      \
                size_t _fl;                       \
                const char *_func = (func);       \
                char **_f = &(f);                 \
                _fl = strlen(_func) + 1;          \
                *_f = newa(char, _fl + 10);       \
                memcpy(*_f, "CODE_FUNC=", 10);    \
                memcpy(*_f + 10, _func, _fl);     \
        } while (false)

/* We open a single fd, and we'll share it with the current process,
 * all its threads, and all its subprocesses. This means we need to
 * initialize it atomically, and need to operate on it atomically
 * never assuming we are the only user */
static int fd_plus_one = 0;

static int journal_fd(void) {
        int fd, fd_plus_one_local;

        fd_plus_one_local = __atomic_load_n(&fd_plus_one, __ATOMIC_ACQUIRE);
        if (fd_plus_one_local > 0)
                return fd_plus_one_local - 1;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        fd_plus_one_local = 0;
        if (!__atomic_compare_exchange_n(&fd_plus_one, &fd_plus_one_local, fd+1,
                false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
                safe_close(fd);
                fd = fd_plus_one_local - 1;
        }

        return fd;
}

int journal_fd_nonblock(bool nonblock) {
        int r;

        r = journal_fd();
        if (r < 0)
                return r;

        return fd_nonblock(r, nonblock);
}

void close_journal_fd(void) {
#if HAVE_VALGRIND_VALGRIND_H
        /* Be nice to valgrind. This is not atomic, so it is useful mainly for debugging. */

        if (!RUNNING_ON_VALGRIND)
                return;

        if (getpid_cached() != gettid())
                return;

        if (fd_plus_one <= 0)
                return;

        safe_close(fd_plus_one - 1);
        fd_plus_one = 0;
#endif
}

_public_ int sd_journal_print(int priority, const char *format, ...) {
        int r;
        va_list ap;

        va_start(ap, format);
        r = sd_journal_printv(priority, format, ap);
        va_end(ap);

        return r;
}

_public_ int sd_journal_printv(int priority, const char *format, va_list ap) {
        char p[STRLEN("PRIORITY=") + DECIMAL_STR_MAX(int) + 1];
        char sbuf[LINE_MAX + 8] = "MESSAGE=";
        struct iovec iov[2];
        int len;
        va_list aq;
        char *buffer = sbuf;

        assert_return(priority >= 0, -EINVAL);
        assert_return(priority <= 7, -EINVAL);
        assert_return(format, -EINVAL);

        xsprintf(p, "PRIORITY=%i", priority & LOG_PRIMASK);

        va_copy(aq, ap);
        len = vsnprintf(buffer + 8, LINE_MAX, format, aq);
        va_end(aq);

        if (len >= (int)LONG_LINE_MAX - 8)
                return -ENOBUFS;

        /* Allocate large buffer to accommodate big message */
        if (len >= LINE_MAX) {
                buffer = alloca_safe(len + 9);
                memcpy(buffer, "MESSAGE=", 8);
                assert_se(vsnprintf(buffer + 8, len + 1, format, ap) == len);
        }

        /* Strip trailing whitespace, keep prefix whitespace. */
        (void) strstrip(buffer);

        /* Suppress empty lines */
        if (isempty(buffer + 8))
                return 0;

        iov[0] = IOVEC_MAKE_STRING(buffer);
        iov[1] = IOVEC_MAKE_STRING(p);

        return sd_journal_sendv(iov, 2);
}

_printf_(1, 0) static int fill_iovec_sprintf(
                const char *format,
                va_list ap,
                size_t extra,
                struct iovec **ret_iov,
                size_t *ret_n_iov) {

        PROTECT_ERRNO;
        struct iovec *iov = NULL;
        size_t n = 0;

        assert(ret_iov);
        assert(ret_n_iov);

        if (extra > 0) {
                if (!GREEDY_REALLOC0(iov, extra))
                        return -ENOMEM;

                n = extra;
        }

        CLEANUP_ARRAY(iov, n, iovec_array_free);

        while (format) {
                _cleanup_free_ char *buffer = NULL;
                va_list aq;

                va_copy(aq, ap);
                if (vasprintf(&buffer, format, aq) < 0) {
                        va_end(aq);
                        return -ENOMEM;
                }
                va_end(aq);

                VA_FORMAT_ADVANCE(format, ap);
                format = va_arg(ap, char *);

                if (!GREEDY_REALLOC(iov, n + 1))
                        return -ENOMEM;

                /* strip trailing whitespace, keep prefixing whitespace */
                iov[n++] = IOVEC_MAKE_STRING(delete_trailing_chars(TAKE_PTR(buffer), NULL));
        }

        *ret_iov = TAKE_PTR(iov);
        *ret_n_iov = n;
        return 0;
}

_public_ int sd_journal_send(const char *format, ...) {
        struct iovec *iov = NULL;
        size_t n_iov = 0;
        va_list ap;
        int r;

        CLEANUP_ARRAY(iov, n_iov, iovec_array_free);

        va_start(ap, format);
        r = fill_iovec_sprintf(format, ap, 0, &iov, &n_iov);
        va_end(ap);
        if (r < 0)
                return r;

        return sd_journal_sendv(iov, n_iov);
}

_public_ int sd_journal_sendv(const struct iovec *iov, int n) {
        PROTECT_ERRNO;
        int fd, r;
        _cleanup_close_ int buffer_fd = -EBADF;
        struct iovec *w;
        uint64_t *l;
        int i, j = 0;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/socket",
        };
        struct msghdr mh = {
                .msg_name = (struct sockaddr*) &sa.sa,
                .msg_namelen = SOCKADDR_UN_LEN(sa.un),
        };
        ssize_t k;
        bool have_syslog_identifier = false;
        bool seal = true;

        assert_return(iov, -EINVAL);
        assert_return(n > 0, -EINVAL);

        w = newa(struct iovec, n * 5 + 3);
        l = newa(uint64_t, n);

        for (i = 0; i < n; i++) {
                char *c, *nl;

                if (_unlikely_(!iov[i].iov_base || iov[i].iov_len <= 1))
                        return -EINVAL;

                c = memchr(iov[i].iov_base, '=', iov[i].iov_len);
                if (_unlikely_(!c || c == iov[i].iov_base))
                        return -EINVAL;

                have_syslog_identifier = have_syslog_identifier ||
                        (c == (char *) iov[i].iov_base + 17 &&
                         startswith(iov[i].iov_base, "SYSLOG_IDENTIFIER"));

                nl = memchr(iov[i].iov_base, '\n', iov[i].iov_len);
                if (nl) {
                        if (_unlikely_(nl < c))
                                return -EINVAL;

                        /* Already includes a newline? Bummer, then
                         * let's write the variable name, then a
                         * newline, then the size (64-bit LE), followed
                         * by the data and a final newline */

                        w[j++] = IOVEC_MAKE(iov[i].iov_base, c - (char*) iov[i].iov_base);
                        w[j++] = IOVEC_MAKE_STRING("\n");

                        l[i] = htole64(iov[i].iov_len - (c - (char*) iov[i].iov_base) - 1);
                        w[j++] = IOVEC_MAKE(&l[i], sizeof(uint64_t));

                        w[j++] = IOVEC_MAKE(c + 1, iov[i].iov_len - (c - (char*) iov[i].iov_base) - 1);
                } else
                        /* Nothing special? Then just add the line and
                         * append a newline */
                        w[j++] = iov[i];

                w[j++] = IOVEC_MAKE_STRING("\n");
        }

        if (!have_syslog_identifier &&
            string_is_safe(program_invocation_short_name)) {

                /* Implicitly add program_invocation_short_name, if it
                 * is not set explicitly. We only do this for
                 * program_invocation_short_name, and nothing else
                 * since everything else is much nicer to retrieve
                 * from the outside. */

                w[j++] = IOVEC_MAKE_STRING("SYSLOG_IDENTIFIER=");
                w[j++] = IOVEC_MAKE_STRING(program_invocation_short_name);
                w[j++] = IOVEC_MAKE_STRING("\n");
        }

        fd = journal_fd();
        if (_unlikely_(fd < 0))
                return fd;

        mh.msg_iov = w;
        mh.msg_iovlen = j;

        k = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (k >= 0)
                return 0;

        /* Fail silently if the journal is not available */
        if (errno == ENOENT)
                return 0;

        if (!IN_SET(errno, EMSGSIZE, ENOBUFS, EAGAIN))
                return -errno;

        /* Message doesn't fit... Let's dump the data in a memfd or
         * temporary file and just pass a file descriptor of it to the
         * other side.
         *
         * For the temporary files we use /dev/shm instead of /tmp
         * here, since we want this to be a tmpfs, and one that is
         * available from early boot on and where unprivileged users
         * can create files. */
        buffer_fd = memfd_new(NULL);
        if (buffer_fd < 0) {
                if (buffer_fd == -ENOSYS) {
                        buffer_fd = open_tmpfile_unlinkable("/dev/shm", O_RDWR | O_CLOEXEC);
                        if (buffer_fd < 0)
                                return buffer_fd;

                        seal = false;
                } else
                        return buffer_fd;
        }

        n = writev(buffer_fd, w, j);
        if (n < 0)
                return -errno;

        if (seal) {
                r = memfd_set_sealed(buffer_fd);
                if (r < 0)
                        return r;
        }

        r = send_one_fd_sa(fd, buffer_fd, mh.msg_name, mh.msg_namelen, 0);
        if (r == -ENOENT)
                /* Fail silently if the journal is not available */
                return 0;
        return r;
}

static int fill_iovec_perror_and_send(const char *message, int skip, struct iovec iov[]) {
        PROTECT_ERRNO;
        size_t n, k;

        k = isempty(message) ? 0 : strlen(message) + 2;
        n = 8 + k + 256 + 1;

        for (;;) {
                char buffer[n];
                char* j;

                errno = 0;
                j = strerror_r(_saved_errno_, buffer + 8 + k, n - 8 - k);
                if (errno == 0) {
                        char error[STRLEN("ERRNO=") + DECIMAL_STR_MAX(int) + 1];

                        if (j != buffer + 8 + k)
                                memmove(buffer + 8 + k, j, strlen(j)+1);

                        memcpy(buffer, "MESSAGE=", 8);

                        if (k > 0) {
                                memcpy(buffer + 8, message, k - 2);
                                memcpy(buffer + 8 + k - 2, ": ", 2);
                        }

                        xsprintf(error, "ERRNO=%i", _saved_errno_);

                        assert_cc(3 == LOG_ERR);
                        iov[skip+0] = IOVEC_MAKE_STRING("PRIORITY=3");
                        iov[skip+1] = IOVEC_MAKE_STRING(buffer);
                        iov[skip+2] = IOVEC_MAKE_STRING(error);

                        return sd_journal_sendv(iov, skip + 3);
                }

                if (errno != ERANGE)
                        return -errno;

                n *= 2;
        }
}

_public_ int sd_journal_perror(const char *message) {
        struct iovec iovec[3];

        return fill_iovec_perror_and_send(message, 0, iovec);
}

_public_ int sd_journal_stream_fd(const char *identifier, int priority, int level_prefix) {
        _cleanup_close_ int fd = -EBADF;
        char *header;
        size_t l;
        int r;

        assert_return(priority >= 0, -EINVAL);
        assert_return(priority <= 7, -EINVAL);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        r = connect_unix_path(fd, AT_FDCWD, "/run/systemd/journal/stdout");
        if (r < 0)
                return r;

        if (shutdown(fd, SHUT_RD) < 0)
                return -errno;

        (void) fd_inc_sndbuf(fd, SNDBUF_SIZE);

        identifier = strempty(identifier);

        l = strlen(identifier);
        header = newa(char, l + 1 + 1 + 2 + 2 + 2 + 2 + 2);

        memcpy(header, identifier, l);
        header[l++] = '\n';
        header[l++] = '\n'; /* unit id */
        header[l++] = '0' + priority;
        header[l++] = '\n';
        header[l++] = '0' + !!level_prefix;
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';

        r = loop_write(fd, header, l);
        if (r < 0)
                return r;

        return TAKE_FD(fd);
}

_public_ int sd_journal_print_with_location(int priority, const char *file, const char *line, const char *func, const char *format, ...) {
        int r;
        va_list ap;

        va_start(ap, format);
        r = sd_journal_printv_with_location(priority, file, line, func, format, ap);
        va_end(ap);

        return r;
}

_public_ int sd_journal_printv_with_location(int priority, const char *file, const char *line, const char *func, const char *format, va_list ap) {
        char p[STRLEN("PRIORITY=") + DECIMAL_STR_MAX(int) + 1];
        char sbuf[LINE_MAX + 8] = "MESSAGE=";
        struct iovec iov[5];
        char *f;
        int len;
        char *buffer = sbuf;
        va_list aq;

        assert_return(priority >= 0, -EINVAL);
        assert_return(priority <= 7, -EINVAL);
        assert_return(format, -EINVAL);

        xsprintf(p, "PRIORITY=%i", priority & LOG_PRIMASK);

        va_copy(aq, ap);
        len = vsnprintf(buffer + 8, LINE_MAX, format, aq);
        va_end(aq);

        if (len >= (int)LONG_LINE_MAX - 8)
                return -ENOBUFS;

        /* Allocate large buffer to accommodate big message */
        if (len >= LINE_MAX) {
                buffer = alloca_safe(len + 9);
                memcpy(buffer, "MESSAGE=", 8);
                assert_se(vsnprintf(buffer + 8, len + 1, format, ap) == len);
        }

        /* Strip trailing whitespace, keep prefixing whitespace */
        (void) strstrip(buffer);

        /* Suppress empty lines */
        if (isempty(buffer + 8))
                return 0;

        /* func is initialized from __func__ which is not a macro, but
         * a static const char[], hence cannot easily be prefixed with
         * CODE_FUNC=, hence let's do it manually here. */
        ALLOCA_CODE_FUNC(f, func);

        iov[0] = IOVEC_MAKE_STRING(buffer);
        iov[1] = IOVEC_MAKE_STRING(p);
        iov[2] = IOVEC_MAKE_STRING(file);
        iov[3] = IOVEC_MAKE_STRING(line);
        iov[4] = IOVEC_MAKE_STRING(f);

        return sd_journal_sendv(iov, ELEMENTSOF(iov));
}

_public_ int sd_journal_send_with_location(const char *file, const char *line, const char *func, const char *format, ...) {
        struct iovec *iov = NULL;
        size_t n_iov = 0;
        va_list ap;
        char *f;
        int r;

        CLEANUP_ARRAY(iov, n_iov, iovec_array_free);

        va_start(ap, format);
        r = fill_iovec_sprintf(format, ap, 3, &iov, &n_iov);
        va_end(ap);
        if (r < 0)
                return r;

        ALLOCA_CODE_FUNC(f, func);

        iov[0] = IOVEC_MAKE_STRING(file);
        iov[1] = IOVEC_MAKE_STRING(line);
        iov[2] = IOVEC_MAKE_STRING(f);

        r = sd_journal_sendv(iov, n_iov);

        iov[0] = iov[1] = iov[2] = (struct iovec) {};

        return r;
}

_public_ int sd_journal_sendv_with_location(
                const char *file, const char *line,
                const char *func,
                const struct iovec *iov, int n) {

        struct iovec *niov;
        char *f;

        assert_return(iov, -EINVAL);
        assert_return(n > 0, -EINVAL);

        niov = newa(struct iovec, n + 3);
        memcpy(niov, iov, sizeof(struct iovec) * n);

        ALLOCA_CODE_FUNC(f, func);

        niov[n++] = IOVEC_MAKE_STRING(file);
        niov[n++] = IOVEC_MAKE_STRING(line);
        niov[n++] = IOVEC_MAKE_STRING(f);

        return sd_journal_sendv(niov, n);
}

_public_ int sd_journal_perror_with_location(
                const char *file, const char *line,
                const char *func,
                const char *message) {

        struct iovec iov[6];
        char *f;

        ALLOCA_CODE_FUNC(f, func);

        iov[0] = IOVEC_MAKE_STRING(file);
        iov[1] = IOVEC_MAKE_STRING(line);
        iov[2] = IOVEC_MAKE_STRING(f);

        return fill_iovec_perror_and_send(message, 3, iov);
}

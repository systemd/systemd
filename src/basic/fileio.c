/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

#define READ_FULL_BYTES_MAX (4U*1024U*1024U)

int fopen_unlocked(const char *path, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fopen(path, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

int fdopen_unlocked(int fd, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fdopen(fd, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc) {
        FILE *f = open_memstream(ptr, sizeloc);
        if (!f)
                return NULL;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return f;
}

FILE* fmemopen_unlocked(void *buf, size_t size, const char *mode) {
        FILE *f = fmemopen(buf, size, mode);
        if (!f)
                return NULL;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return f;
}

int write_string_stream_ts(
                FILE *f,
                const char *line,
                WriteStringFileFlags flags,
                struct timespec *ts) {

        bool needs_nl;
        int r;

        assert(f);
        assert(line);

        if (ferror(f))
                return -EIO;

        needs_nl = !(flags & WRITE_STRING_FILE_AVOID_NEWLINE) && !endswith(line, "\n");

        if (needs_nl && (flags & WRITE_STRING_FILE_DISABLE_BUFFER)) {
                /* If STDIO buffering was disabled, then let's append the newline character to the string itself, so
                 * that the write goes out in one go, instead of two */

                line = strjoina(line, "\n");
                needs_nl = false;
        }

        if (fputs(line, f) == EOF)
                return -errno;

        if (needs_nl)
                if (fputc('\n', f) == EOF)
                        return -errno;

        if (flags & WRITE_STRING_FILE_SYNC)
                r = fflush_sync_and_check(f);
        else
                r = fflush_and_check(f);
        if (r < 0)
                return r;

        if (ts) {
                struct timespec twice[2] = {*ts, *ts};

                if (futimens(fileno(f), twice) < 0)
                        return -errno;
        }

        return 0;
}

static int write_string_file_atomic(
                const char *fn,
                const char *line,
                WriteStringFileFlags flags,
                struct timespec *ts) {

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(fn);
        assert(line);

        r = fopen_temporary(fn, &f, &p);
        if (r < 0)
                return r;

        (void) fchmod_umask(fileno(f), 0644);

        r = write_string_stream_ts(f, line, flags, ts);
        if (r < 0)
                goto fail;

        if (rename(p, fn) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(p);
        return r;
}

int write_string_file_ts(
                const char *fn,
                const char *line,
                WriteStringFileFlags flags,
                struct timespec *ts) {

        _cleanup_fclose_ FILE *f = NULL;
        int q, r;

        assert(fn);
        assert(line);

        /* We don't know how to verify whether the file contents was already on-disk. */
        assert(!((flags & WRITE_STRING_FILE_VERIFY_ON_FAILURE) && (flags & WRITE_STRING_FILE_SYNC)));

        if (flags & WRITE_STRING_FILE_MKDIR_0755) {
                r = mkdir_parents(fn, 0755);
                if (r < 0)
                        return r;
        }

        if (flags & WRITE_STRING_FILE_ATOMIC) {
                assert(flags & WRITE_STRING_FILE_CREATE);

                r = write_string_file_atomic(fn, line, flags, ts);
                if (r < 0)
                        goto fail;

                return r;
        } else
                assert(!ts);

        if (flags & WRITE_STRING_FILE_CREATE) {
                r = fopen_unlocked(fn, "we", &f);
                if (r < 0)
                        goto fail;
        } else {
                int fd;

                /* We manually build our own version of fopen(..., "we") that
                 * works without O_CREAT */
                fd = open(fn, O_WRONLY|O_CLOEXEC|O_NOCTTY | ((flags & WRITE_STRING_FILE_NOFOLLOW) ? O_NOFOLLOW : 0));
                if (fd < 0) {
                        r = -errno;
                        goto fail;
                }

                r = fdopen_unlocked(fd, "w", &f);
                if (r < 0) {
                        safe_close(fd);
                        goto fail;
                }
        }

        if (flags & WRITE_STRING_FILE_DISABLE_BUFFER)
                setvbuf(f, NULL, _IONBF, 0);

        r = write_string_stream_ts(f, line, flags, ts);
        if (r < 0)
                goto fail;

        return 0;

fail:
        if (!(flags & WRITE_STRING_FILE_VERIFY_ON_FAILURE))
                return r;

        f = safe_fclose(f);

        /* OK, the operation failed, but let's see if the right
         * contents in place already. If so, eat up the error. */

        q = verify_file(fn, line, !(flags & WRITE_STRING_FILE_AVOID_NEWLINE));
        if (q <= 0)
                return r;

        return 0;
}

int write_string_filef(
                const char *fn,
                WriteStringFileFlags flags,
                const char *format, ...) {

        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return write_string_file(fn, p, flags);
}

int read_one_line_file(const char *fn, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(fn);
        assert(line);

        r = fopen_unlocked(fn, "re", &f);
        if (r < 0)
                return r;

        return read_line(f, LONG_LINE_MAX, line);
}

int verify_file(const char *fn, const char *blob, bool accept_extra_nl) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *buf = NULL;
        size_t l, k;
        int r;

        assert(fn);
        assert(blob);

        l = strlen(blob);

        if (accept_extra_nl && endswith(blob, "\n"))
                accept_extra_nl = false;

        buf = malloc(l + accept_extra_nl + 1);
        if (!buf)
                return -ENOMEM;

        r = fopen_unlocked(fn, "re", &f);
        if (r < 0)
                return r;

        /* We try to read one byte more than we need, so that we know whether we hit eof */
        errno = 0;
        k = fread(buf, 1, l + accept_extra_nl + 1, f);
        if (ferror(f))
                return errno_or_else(EIO);

        if (k != l && k != l + accept_extra_nl)
                return 0;
        if (memcmp(buf, blob, l) != 0)
                return 0;
        if (k > l && buf[l] != '\n')
                return 0;

        return 1;
}

int read_full_stream_full(
                FILE *f,
                const char *filename,
                ReadFullFileFlags flags,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_free_ char *buf = NULL;
        struct stat st;
        size_t n, n_next, l;
        int fd, r;

        assert(f);
        assert(ret_contents);
        assert(!FLAGS_SET(flags, READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX));
        assert(!(flags & (READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX)) || ret_size);

        n_next = LINE_MAX; /* Start size */

        fd = fileno(f);
        if (fd >= 0) { /* If the FILE* object is backed by an fd (as opposed to memory or such, see fmemopen(), let's
                        * optimize our buffering) */

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (S_ISREG(st.st_mode)) {

                        /* Safety check */
                        if (st.st_size > READ_FULL_BYTES_MAX)
                                return -E2BIG;

                        /* Start with the right file size, but be prepared for files from /proc which generally report a file
                         * size of 0. Note that we increase the size to read here by one, so that the first read attempt
                         * already makes us notice the EOF. */
                        if (st.st_size > 0)
                                n_next = st.st_size + 1;

                        if (flags & READ_FULL_FILE_SECURE)
                                (void) warn_file_is_world_accessible(filename, &st, NULL, 0);
                }
        }

        n = l = 0;
        for (;;) {
                char *t;
                size_t k;

                if (flags & READ_FULL_FILE_SECURE) {
                        t = malloc(n_next + 1);
                        if (!t) {
                                r = -ENOMEM;
                                goto finalize;
                        }
                        memcpy_safe(t, buf, n);
                        explicit_bzero_safe(buf, n);
                        buf = mfree(buf);
                } else {
                        t = realloc(buf, n_next + 1);
                        if (!t)
                                return -ENOMEM;
                }

                buf = t;
                n = n_next;

                errno = 0;
                k = fread(buf + l, 1, n - l, f);
                if (k > 0)
                        l += k;

                if (ferror(f)) {
                        r = errno_or_else(EIO);
                        goto finalize;
                }

                if (feof(f))
                        break;

                /* We aren't expecting fread() to return a short read outside
                 * of (error && eof), assert buffer is full and enlarge buffer.
                 */
                assert(l == n);

                /* Safety check */
                if (n >= READ_FULL_BYTES_MAX) {
                        r = -E2BIG;
                        goto finalize;
                }

                n_next = MIN(n * 2, READ_FULL_BYTES_MAX);
        }

        if (flags & (READ_FULL_FILE_UNBASE64 | READ_FULL_FILE_UNHEX)) {
                buf[l++] = 0;
                if (flags & READ_FULL_FILE_UNBASE64)
                        r = unbase64mem_full(buf, l, flags & READ_FULL_FILE_SECURE, (void **) ret_contents, ret_size);
                else
                        r = unhexmem_full(buf, l, flags & READ_FULL_FILE_SECURE, (void **) ret_contents, ret_size);
                goto finalize;
        }

        if (!ret_size) {
                /* Safety check: if the caller doesn't want to know the size of what we just read it will rely on the
                 * trailing NUL byte. But if there's an embedded NUL byte, then we should refuse operation as otherwise
                 * there'd be ambiguity about what we just read. */

                if (memchr(buf, 0, l)) {
                        r = -EBADMSG;
                        goto finalize;
                }
        }

        buf[l] = 0;
        *ret_contents = TAKE_PTR(buf);

        if (ret_size)
                *ret_size = l;

        return 0;

finalize:
        if (flags & READ_FULL_FILE_SECURE)
                explicit_bzero_safe(buf, n);

        return r;
}

int read_full_file_full(const char *filename, ReadFullFileFlags flags, char **contents, size_t *size) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(filename);
        assert(contents);

        r = fopen_unlocked(filename, "re", &f);
        if (r < 0)
                return r;

        return read_full_stream_full(f, filename, flags, contents, size);
}

int executable_is_script(const char *path, char **interpreter) {
        _cleanup_free_ char *line = NULL;
        size_t len;
        char *ans;
        int r;

        assert(path);

        r = read_one_line_file(path, &line);
        if (r == -ENOBUFS) /* First line overly long? if so, then it's not a script */
                return 0;
        if (r < 0)
                return r;

        if (!startswith(line, "#!"))
                return 0;

        ans = strstrip(line + 2);
        len = strcspn(ans, " \t");

        if (len == 0)
                return 0;

        ans = strndup(ans, len);
        if (!ans)
                return -ENOMEM;

        *interpreter = ans;
        return 1;
}

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should not include whitespace or the delimiter (':'). pattern matches only
 * the beginning of a line. Whitespace before ':' is skipped. Whitespace and
 * zeros after the ':' will be skipped. field must be freed afterwards.
 * terminator specifies the terminating characters of the field value (not
 * included in the value).
 */
int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field) {
        _cleanup_free_ char *status = NULL;
        char *t, *f;
        size_t len;
        int r;

        assert(terminator);
        assert(filename);
        assert(pattern);
        assert(field);

        r = read_full_file(filename, &status, NULL);
        if (r < 0)
                return r;

        t = status;

        do {
                bool pattern_ok;

                do {
                        t = strstr(t, pattern);
                        if (!t)
                                return -ENOENT;

                        /* Check that pattern occurs in beginning of line. */
                        pattern_ok = (t == status || t[-1] == '\n');

                        t += strlen(pattern);

                } while (!pattern_ok);

                t += strspn(t, " \t");
                if (!*t)
                        return -ENOENT;

        } while (*t != ':');

        t++;

        if (*t) {
                t += strspn(t, " \t");

                /* Also skip zeros, because when this is used for
                 * capabilities, we don't want the zeros. This way the
                 * same capability set always maps to the same string,
                 * irrespective of the total capability set size. For
                 * other numbers it shouldn't matter. */
                t += strspn(t, "0");
                /* Back off one char if there's nothing but whitespace
                   and zeros */
                if (!*t || isspace(*t))
                        t--;
        }

        len = strcspn(t, terminator);

        f = strndup(t, len);
        if (!f)
                return -ENOMEM;

        *field = f;
        return 0;
}

DIR *xopendirat(int fd, const char *name, int flags) {
        int nfd;
        DIR *d;

        assert(!(flags & O_CREAT));

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags, 0);
        if (nfd < 0)
                return NULL;

        d = fdopendir(nfd);
        if (!d) {
                safe_close(nfd);
                return NULL;
        }

        return d;
}

static int search_and_fopen_internal(const char *path, const char *mode, const char *root, char **search, FILE **_f) {
        char **i;

        assert(path);
        assert(mode);
        assert(_f);

        if (!path_strv_resolve_uniq(search, root))
                return -ENOMEM;

        STRV_FOREACH(i, search) {
                _cleanup_free_ char *p = NULL;
                FILE *f;

                p = path_join(root, *i, path);
                if (!p)
                        return -ENOMEM;

                f = fopen(p, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                if (errno != ENOENT)
                        return -errno;
        }

        return -ENOENT;
}

int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **_f) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(path);
        assert(mode);
        assert(_f);

        if (path_is_absolute(path)) {
                FILE *f;

                f = fopen(path, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                return -errno;
        }

        copy = strv_copy((char**) search);
        if (!copy)
                return -ENOMEM;

        return search_and_fopen_internal(path, mode, root, copy, _f);
}

int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **_f) {
        _cleanup_strv_free_ char **s = NULL;

        if (path_is_absolute(path)) {
                FILE *f;

                f = fopen(path, mode);
                if (f) {
                        *_f = f;
                        return 0;
                }

                return -errno;
        }

        s = strv_split_nulstr(search);
        if (!s)
                return -ENOMEM;

        return search_and_fopen_internal(path, mode, root, s, _f);
}

int fflush_and_check(FILE *f) {
        assert(f);

        errno = 0;
        fflush(f);

        if (ferror(f))
                return errno_or_else(EIO);

        return 0;
}

int fflush_sync_and_check(FILE *f) {
        int r;

        assert(f);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        if (fsync(fileno(f)) < 0)
                return -errno;

        r = fsync_directory_of_file(fileno(f));
        if (r < 0)
                return r;

        return 0;
}

int write_timestamp_file_atomic(const char *fn, usec_t n) {
        char ln[DECIMAL_STR_MAX(n)+2];

        /* Creates a "timestamp" file, that contains nothing but a
         * usec_t timestamp, formatted in ASCII. */

        if (n <= 0 || n >= USEC_INFINITY)
                return -ERANGE;

        xsprintf(ln, USEC_FMT "\n", n);

        return write_string_file(fn, ln, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
}

int read_timestamp_file(const char *fn, usec_t *ret) {
        _cleanup_free_ char *ln = NULL;
        uint64_t t;
        int r;

        r = read_one_line_file(fn, &ln);
        if (r < 0)
                return r;

        r = safe_atou64(ln, &t);
        if (r < 0)
                return r;

        if (t <= 0 || t >= (uint64_t) USEC_INFINITY)
                return -ERANGE;

        *ret = (usec_t) t;
        return 0;
}

int fputs_with_space(FILE *f, const char *s, const char *separator, bool *space) {
        int r;

        assert(s);

        /* Outputs the specified string with fputs(), but optionally prefixes it with a separator. The *space parameter
         * when specified shall initially point to a boolean variable initialized to false. It is set to true after the
         * first invocation. This call is supposed to be use in loops, where a separator shall be inserted between each
         * element, but not before the first one. */

        if (!f)
                f = stdout;

        if (space) {
                if (!separator)
                        separator = " ";

                if (*space) {
                        r = fputs(separator, f);
                        if (r < 0)
                                return r;
                }

                *space = true;
        }

        return fputs(s, f);
}

/* A bitmask of the EOL markers we know */
typedef enum EndOfLineMarker {
        EOL_NONE     = 0,
        EOL_ZERO     = 1 << 0,  /* \0 (aka NUL) */
        EOL_TEN      = 1 << 1,  /* \n (aka NL, aka LF)  */
        EOL_THIRTEEN = 1 << 2,  /* \r (aka CR)  */
} EndOfLineMarker;

static EndOfLineMarker categorize_eol(char c, ReadLineFlags flags) {

        if (!IN_SET(flags, READ_LINE_ONLY_NUL)) {
                if (c == '\n')
                        return EOL_TEN;
                if (c == '\r')
                        return EOL_THIRTEEN;
        }

        if (c == '\0')
                return EOL_ZERO;

        return EOL_NONE;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, funlockfile);

int read_line_full(FILE *f, size_t limit, ReadLineFlags flags, char **ret) {
        size_t n = 0, allocated = 0, count = 0;
        _cleanup_free_ char *buffer = NULL;
        int r, tty = -1;

        assert(f);

        /* Something like a bounded version of getline().
         *
         * Considers EOF, \n, \r and \0 end of line delimiters (or combinations of these), and does not include these
         * delimiters in the string returned. Specifically, recognizes the following combinations of markers as line
         * endings:
         *
         *     • \n        (UNIX)
         *     • \r        (old MacOS)
         *     • \0        (C strings)
         *     • \n\0
         *     • \r\0
         *     • \r\n      (Windows)
         *     • \n\r
         *     • \r\n\0
         *     • \n\r\0
         *
         * Returns the number of bytes read from the files (i.e. including delimiters — this hence usually differs from
         * the number of characters in the returned string). When EOF is hit, 0 is returned.
         *
         * The input parameter limit is the maximum numbers of characters in the returned string, i.e. excluding
         * delimiters. If the limit is hit we fail and return -ENOBUFS.
         *
         * If a line shall be skipped ret may be initialized as NULL. */

        if (ret) {
                if (!GREEDY_REALLOC(buffer, allocated, 1))
                        return -ENOMEM;
        }

        {
                _unused_ _cleanup_(funlockfilep) FILE *flocked = f;
                EndOfLineMarker previous_eol = EOL_NONE;
                flockfile(f);

                for (;;) {
                        EndOfLineMarker eol;
                        char c;

                        if (n >= limit)
                                return -ENOBUFS;

                        if (count >= INT_MAX) /* We couldn't return the counter anymore as "int", hence refuse this */
                                return -ENOBUFS;

                        r = safe_fgetc(f, &c);
                        if (r < 0)
                                return r;
                        if (r == 0) /* EOF is definitely EOL */
                                break;

                        eol = categorize_eol(c, flags);

                        if (FLAGS_SET(previous_eol, EOL_ZERO) ||
                            (eol == EOL_NONE && previous_eol != EOL_NONE) ||
                            (eol != EOL_NONE && (previous_eol & eol) != 0)) {
                                /* Previous char was a NUL? This is not an EOL, but the previous char was? This type of
                                 * EOL marker has been seen right before?  In either of these three cases we are
                                 * done. But first, let's put this character back in the queue. (Note that we have to
                                 * cast this to (unsigned char) here as ungetc() expects a positive 'int', and if we
                                 * are on an architecture where 'char' equals 'signed char' we need to ensure we don't
                                 * pass a negative value here. That said, to complicate things further ungetc() is
                                 * actually happy with most negative characters and implicitly casts them back to
                                 * positive ones as needed, except for \xff (aka -1, aka EOF), which it refuses. What a
                                 * godawful API!) */
                                assert_se(ungetc((unsigned char) c, f) != EOF);
                                break;
                        }

                        count++;

                        if (eol != EOL_NONE) {
                                /* If we are on a tty, we can't wait for more input. But we expect only
                                 * \n as the single EOL marker, so there is no need to wait. We check
                                 * this condition last to avoid isatty() check if not necessary. */

                                if (tty < 0)
                                        tty = isatty(fileno(f));
                                if (tty > 0)
                                        break;
                        }

                        if (eol != EOL_NONE) {
                                previous_eol |= eol;
                                continue;
                        }

                        if (ret) {
                                if (!GREEDY_REALLOC(buffer, allocated, n + 2))
                                        return -ENOMEM;

                                buffer[n] = c;
                        }

                        n++;
                }
        }

        if (ret) {
                buffer[n] = 0;

                *ret = TAKE_PTR(buffer);
        }

        return (int) count;
}

int safe_fgetc(FILE *f, char *ret) {
        int k;

        assert(f);

        /* A safer version of plain fgetc(): let's propagate the error that happened while reading as such, and
         * separate the EOF condition from the byte read, to avoid those confusion signed/unsigned issues fgetc()
         * has. */

        errno = 0;
        k = fgetc(f);
        if (k == EOF) {
                if (ferror(f))
                        return errno_or_else(EIO);

                if (ret)
                        *ret = 0;

                return 0;
        }

        if (ret)
                *ret = k;

        return 1;
}

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line) {
        struct stat _st;

        if (!filename)
                return 0;

        if (!st) {
                if (stat(filename, &_st) < 0)
                        return -errno;
                st = &_st;
        }

        if ((st->st_mode & S_IRWXO) == 0)
                return 0;

        if (unit)
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
                           filename, st->st_mode & 07777);
        else
                log_warning("%s has %04o mode that is too permissive, please adjust the ownership and access mode.",
                            filename, st->st_mode & 07777);
        return 0;
}

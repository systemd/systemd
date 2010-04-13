/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <sched.h>
#include <sys/resource.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/vt.h>
#include <linux/tiocl.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/inotify.h>
#include <sys/poll.h>

#include "macro.h"
#include "util.h"
#include "ioprio.h"
#include "missing.h"
#include "log.h"
#include "strv.h"

bool streq_ptr(const char *a, const char *b) {

        /* Like streq(), but tries to make sense of NULL pointers */

        if (a && b)
                return streq(a, b);

        if (!a && !b)
                return true;

        return false;
}

usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(clock_id, &ts) == 0);

        return timespec_load(&ts);
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

struct timespec *timespec_store(struct timespec *ts, usec_t u)  {
        assert(ts);

        ts->tv_sec = (time_t) (u / USEC_PER_SEC);
        ts->tv_nsec = (long int) ((u % USEC_PER_SEC) * NSEC_PER_USEC);

        return ts;
}

usec_t timeval_load(const struct timeval *tv) {
        assert(tv);

        return
                (usec_t) tv->tv_sec * USEC_PER_SEC +
                (usec_t) tv->tv_usec;
}

struct timeval *timeval_store(struct timeval *tv, usec_t u) {
        assert(tv);

        tv->tv_sec = (time_t) (u / USEC_PER_SEC);
        tv->tv_usec = (suseconds_t) (u % USEC_PER_SEC);

        return tv;
}

bool endswith(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (sl < pl)
                return false;

        return memcmp(s + sl - pl, postfix, pl) == 0;
}

bool startswith(const char *s, const char *prefix) {
        size_t sl, pl;

        assert(s);
        assert(prefix);

        sl = strlen(s);
        pl = strlen(prefix);

        if (sl < pl)
                return false;

        return memcmp(s, prefix, pl) == 0;
}

bool first_word(const char *s, const char *word) {
        size_t sl, wl;

        assert(s);
        assert(word);

        sl = strlen(s);
        wl = strlen(word);

        if (sl < wl)
                return false;

        if (memcmp(s, word, wl) != 0)
                return false;

        return (s[wl] == 0 ||
                strchr(WHITESPACE, s[wl]));
}

int close_nointr(int fd) {
        assert(fd >= 0);

        for (;;) {
                int r;

                if ((r = close(fd)) >= 0)
                        return r;

                if (errno != EINTR)
                        return r;
        }
}

void close_nointr_nofail(int fd) {
        int saved_errno = errno;

        /* like close_nointr() but cannot fail, and guarantees errno
         * is unchanged */

        assert_se(close_nointr(fd) == 0);

        errno = saved_errno;
}

int parse_boolean(const char *v) {
        assert(v);

        if (streq(v, "1") || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T' || !strcasecmp(v, "on"))
                return 1;
        else if (streq(v, "0") || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F' || !strcasecmp(v, "off"))
                return 0;

        return -EINVAL;
}

int safe_atou(const char *s, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(ret_u);

        errno = 0;
        l = strtoul(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        *ret_u = (unsigned) l;
        return 0;
}

int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        long l;

        assert(s);
        assert(ret_i);

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((long) (int) l != l)
                return -ERANGE;

        *ret_i = (int) l;
        return 0;
}

int safe_atolu(const char *s, long unsigned *ret_lu) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(ret_lu);

        errno = 0;
        l = strtoul(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_lu = l;
        return 0;
}

int safe_atoli(const char *s, long int *ret_li) {
        char *x = NULL;
        long l;

        assert(s);
        assert(ret_li);

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_li = l;
        return 0;
}

int safe_atollu(const char *s, long long unsigned *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);
        assert(ret_llu);

        errno = 0;
        l = strtoull(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_llu = l;
        return 0;
}

int safe_atolli(const char *s, long long int *ret_lli) {
        char *x = NULL;
        long long l;

        assert(s);
        assert(ret_lli);

        errno = 0;
        l = strtoll(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        *ret_lli = l;
        return 0;
}

/* Split a string into words. */
char *split(const char *c, size_t *l, const char *separator, char **state) {
        char *current;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, separator);
        *l = strcspn(current, separator);
        *state = current+*l;

        return (char*) current;
}

/* Split a string into words, but consider strings enclosed in '' and
 * "" as words even if they include spaces. */
char *split_quoted(const char *c, size_t *l, char **state) {
        char *current;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, WHITESPACE);

        if (*current == '\'') {
                current ++;
                *l = strcspn(current, "'");
                *state = current+*l;

                if (**state == '\'')
                        (*state)++;
        } else if (*current == '\"') {
                current ++;
                *l = strcspn(current, "\"");
                *state = current+*l;

                if (**state == '\"')
                        (*state)++;
        } else {
                *l = strcspn(current, WHITESPACE);
                *state = current+*l;
        }

        /* FIXME: Cannot deal with strings that have spaces AND ticks
         * in them */

        return (char*) current;
}

char **split_path_and_make_absolute(const char *p) {
        char **l;
        assert(p);

        if (!(l = strv_split(p, ":")))
                return NULL;

        if (!strv_path_make_absolute_cwd(l)) {
                strv_free(l);
                return NULL;
        }

        return l;
}

int get_parent_of_pid(pid_t pid, pid_t *_ppid) {
        int r;
        FILE *f;
        char fn[132], line[256], *p;
        long long unsigned ppid;

        assert(pid >= 0);
        assert(_ppid);

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu/stat", (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if (!(f = fopen(fn, "r")))
                return -errno;

        if (!(fgets(line, sizeof(line), f))) {
                r = -errno;
                fclose(f);
                return r;
        }

        fclose(f);

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        if (!(p = strrchr(line, ')')))
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%llu ", /* ppid */
                   &ppid) != 1)
                return -EIO;

        if ((long long unsigned) (pid_t) ppid != ppid)
                return -ERANGE;

        *_ppid = (pid_t) ppid;

        return 0;
}

int write_one_line_file(const char *fn, const char *line) {
        FILE *f;
        int r;

        assert(fn);
        assert(line);

        if (!(f = fopen(fn, "we")))
                return -errno;

        if (fputs(line, f) < 0) {
                r = -errno;
                goto finish;
        }

        r = 0;
finish:
        fclose(f);
        return r;
}

int read_one_line_file(const char *fn, char **line) {
        FILE *f;
        int r;
        char t[2048], *c;

        assert(fn);
        assert(line);

        if (!(f = fopen(fn, "re")))
                return -errno;

        if (!(fgets(t, sizeof(t), f))) {
                r = -errno;
                goto finish;
        }

        if (!(c = strdup(t))) {
                r = -ENOMEM;
                goto finish;
        }

        *line = c;
        r = 0;

finish:
        fclose(f);
        return r;
}

char *truncate_nl(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
}

int get_process_name(pid_t pid, char **name) {
        char *p;
        int r;

        assert(pid >= 1);
        assert(name);

        if (asprintf(&p, "/proc/%llu/comm", (unsigned long long) pid) < 0)
                return -ENOMEM;

        r = read_one_line_file(p, name);
        free(p);

        if (r < 0)
                return r;

        truncate_nl(*name);
        return 0;
}

char *strappend(const char *s, const char *suffix) {
        size_t a, b;
        char *r;

        assert(s);
        assert(suffix);

        a = strlen(s);
        b = strlen(suffix);

        if (!(r = new(char, a+b+1)))
                return NULL;

        memcpy(r, s, a);
        memcpy(r+a, suffix, b);
        r[a+b] = 0;

        return r;
}

int readlink_malloc(const char *p, char **r) {
        size_t l = 100;

        assert(p);
        assert(r);

        for (;;) {
                char *c;
                ssize_t n;

                if (!(c = new(char, l)))
                        return -ENOMEM;

                if ((n = readlink(p, c, l-1)) < 0) {
                        int ret = -errno;
                        free(c);
                        return ret;
                }

                if ((size_t) n < l-1) {
                        c[n] = 0;
                        *r = c;
                        return 0;
                }

                free(c);
                l *= 2;
        }
}

char *file_name_from_path(const char *p) {
        char *r;

        assert(p);

        if ((r = strrchr(p, '/')))
                return r + 1;

        return (char*) p;
}

bool path_is_absolute(const char *p) {
        assert(p);

        return p[0] == '/';
}

bool is_path(const char *p) {

        return !!strchr(p, '/');
}

char *path_make_absolute(const char *p, const char *prefix) {
        char *r;

        assert(p);

        /* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

        if (path_is_absolute(p) || !prefix)
                return strdup(p);

        if (asprintf(&r, "%s/%s", prefix, p) < 0)
                return NULL;

        return r;
}

char *path_make_absolute_cwd(const char *p) {
        char *cwd, *r;

        assert(p);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                return strdup(p);

        if (!(cwd = get_current_dir_name()))
                return NULL;

        r = path_make_absolute(p, cwd);
        free(cwd);

        return r;
}

char **strv_path_make_absolute_cwd(char **l) {
        char **s;

        /* Goes through every item in the string list and makes it
         * absolute. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t;

                if (!(t = path_make_absolute_cwd(*s)))
                        return NULL;

                free(*s);
                *s = t;
        }

        return l;
}

int reset_all_signal_handlers(void) {
        int sig;

        for (sig = 1; sig < _NSIG; sig++) {
                struct sigaction sa;

                if (sig == SIGKILL || sig == SIGSTOP)
                        continue;

                zero(sa);
                sa.sa_handler = SIG_DFL;
                sa.sa_flags = SA_RESTART;

                /* On Linux the first two RT signals are reserved by
                 * glibc, and sigaction() will return EINVAL for them. */
                if ((sigaction(sig, &sa, NULL) < 0))
                        if (errno != EINVAL)
                                return -errno;
        }

        return 0;
}

char *strstrip(char *s) {
        char *e, *l = NULL;

        /* Drops trailing whitespace. Modifies the string in
         * place. Returns pointer to first non-space character */

        s += strspn(s, WHITESPACE);

        for (e = s; *e; e++)
                if (!strchr(WHITESPACE, *e))
                        l = e;

        if (l)
                *(l+1) = 0;
        else
                *s = 0;

        return s;
}

char *delete_chars(char *s, const char *bad) {
        char *f, *t;

        /* Drops all whitespace, regardless where in the string */

        for (f = s, t = s; *f; f++) {
                if (strchr(bad, *f))
                        continue;

                *(t++) = *f;
        }

        *t = 0;

        return s;
}

char *file_in_same_dir(const char *path, const char *filename) {
        char *e, *r;
        size_t k;

        assert(path);
        assert(filename);

        /* This removes the last component of path and appends
         * filename, unless the latter is absolute anyway or the
         * former isn't */

        if (path_is_absolute(filename))
                return strdup(filename);

        if (!(e = strrchr(path, '/')))
                return strdup(filename);

        k = strlen(filename);
        if (!(r = new(char, e-path+1+k+1)))
                return NULL;

        memcpy(r, path, e-path+1);
        memcpy(r+(e-path)+1, filename, k+1);

        return r;
}

int mkdir_parents(const char *path, mode_t mode) {
        const char *p, *e;

        assert(path);

        /* Creates every parent directory in the path except the last
         * component. */

        p = path + strspn(path, "/");
        for (;;) {
                int r;
                char *t;

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're
                 * done */
                if (*p == 0)
                        return 0;

                if (!(t = strndup(path, e - path)))
                        return -ENOMEM;

                r = mkdir(t, mode);

                free(t);

                if (r < 0 && errno != EEXIST)
                        return -errno;
        }
}

int mkdir_p(const char *path, mode_t mode) {
        int r;

        /* Like mkdir -p */

        if ((r = mkdir_parents(path, mode)) < 0)
                return r;

        if (mkdir(path, mode) < 0)
                return -errno;

        return 0;
}

char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

int unhexchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -1;
}

char octchar(int x) {
        return '0' + (x & 7);
}

int unoctchar(char c) {

        if (c >= '0' && c <= '7')
                return c - '0';

        return -1;
}

char decchar(int x) {
        return '0' + (x % 10);
}

int undecchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        return -1;
}

char *cescape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Does C style string escaping. */

        if (!(r = new(char, strlen(s)*4 + 1)))
                return NULL;

        for (f = s, t = r; *f; f++)

                switch (*f) {

                case '\a':
                        *(t++) = '\\';
                        *(t++) = 'a';
                        break;
                case '\b':
                        *(t++) = '\\';
                        *(t++) = 'b';
                        break;
                case '\f':
                        *(t++) = '\\';
                        *(t++) = 'f';
                        break;
                case '\n':
                        *(t++) = '\\';
                        *(t++) = 'n';
                        break;
                case '\r':
                        *(t++) = '\\';
                        *(t++) = 'r';
                        break;
                case '\t':
                        *(t++) = '\\';
                        *(t++) = 't';
                        break;
                case '\v':
                        *(t++) = '\\';
                        *(t++) = 'v';
                        break;
                case '\\':
                        *(t++) = '\\';
                        *(t++) = '\\';
                        break;
                case '"':
                        *(t++) = '\\';
                        *(t++) = '"';
                        break;
                case '\'':
                        *(t++) = '\\';
                        *(t++) = '\'';
                        break;

                default:
                        /* For special chars we prefer octal over
                         * hexadecimal encoding, simply because glib's
                         * g_strescape() does the same */
                        if ((*f < ' ') || (*f >= 127)) {
                                *(t++) = '\\';
                                *(t++) = octchar((unsigned char) *f >> 6);
                                *(t++) = octchar((unsigned char) *f >> 3);
                                *(t++) = octchar((unsigned char) *f);
                        } else
                                *(t++) = *f;
                        break;
                }

        *t = 0;

        return r;
}

char *cunescape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Undoes C style string escaping */

        if (!(r = new(char, strlen(s)+1)))
                return r;

        for (f = s, t = r; *f; f++) {

                if (*f != '\\') {
                        *(t++) = *f;
                        continue;
                }

                f++;

                switch (*f) {

                case 'a':
                        *(t++) = '\a';
                        break;
                case 'b':
                        *(t++) = '\b';
                        break;
                case 'f':
                        *(t++) = '\f';
                        break;
                case 'n':
                        *(t++) = '\n';
                        break;
                case 'r':
                        *(t++) = '\r';
                        break;
                case 't':
                        *(t++) = '\t';
                        break;
                case 'v':
                        *(t++) = '\v';
                        break;
                case '\\':
                        *(t++) = '\\';
                        break;
                case '"':
                        *(t++) = '"';
                        break;
                case '\'':
                        *(t++) = '\'';
                        break;

                case 'x': {
                        /* hexadecimal encoding */
                        int a, b;

                        if ((a = unhexchar(f[1])) < 0 ||
                            (b = unhexchar(f[2])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                *(t++) = 'x';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                f += 2;
                        }

                        break;
                }

                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7': {
                        /* octal encoding */
                        int a, b, c;

                        if ((a = unoctchar(f[0])) < 0 ||
                            (b = unoctchar(f[1])) < 0 ||
                            (c = unoctchar(f[2])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                *(t++) = f[0];
                        } else {
                                *(t++) = (char) ((a << 6) | (b << 3) | c);
                                f += 2;
                        }

                        break;
                }

                case 0:
                        /* premature end of string.*/
                        *(t++) = '\\';
                        goto finish;

                default:
                        /* Invalid escape code, let's take it literal then */
                        *(t++) = '\\';
                        *(t++) = 'f';
                        break;
                }
        }

finish:
        *t = 0;
        return r;
}


char *xescape(const char *s, const char *bad) {
        char *r, *t;
        const char *f;

        /* Escapes all chars in bad, in addition to \ and all special
         * chars, in \xFF style escaping. May be reversed with
         * cunescape. */

        if (!(r = new(char, strlen(s)*4+1)))
                return NULL;

        for (f = s, t = r; *f; f++) {

                if ((*f < ' ') || (*f >= 127) ||
                    (*f == '\\') || strchr(bad, *f)) {
                        *(t++) = '\\';
                        *(t++) = 'x';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *bus_path_escape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        /* Escapes all chars that D-Bus' object path cannot deal
         * with. Can be reverse with bus_path_unescape() */

        if (!(r = new(char, strlen(s)*3+1)))
                return NULL;

        for (f = s, t = r; *f; f++) {

                if (!(*f >= 'A' && *f <= 'Z') &&
                    !(*f >= 'a' && *f <= 'z') &&
                    !(*f >= '0' && *f <= '9')) {
                        *(t++) = '_';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *bus_path_unescape(const char *s) {
        char *r, *t;
        const char *f;

        assert(s);

        if (!(r = new(char, strlen(s)+1)))
                return NULL;

        for (f = s, t = r; *f; f++) {

                if (*f == '_') {
                        int a, b;

                        if ((a = unhexchar(f[1])) < 0 ||
                            (b = unhexchar(f[2])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '_';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                f += 2;
                        }
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *path_kill_slashes(char *path) {
        char *f, *t;
        bool slash = false;

        /* Removes redundant inner and trailing slashes. Modifies the
         * passed string in-place.
         *
         * ///foo///bar/ becomes /foo/bar
         */

        for (f = path, t = path; *f; f++) {

                if (*f == '/') {
                        slash = true;
                        continue;
                }

                if (slash) {
                        slash = false;
                        *(t++) = '/';
                }

                *(t++) = *f;
        }

        /* Special rule, if we are talking of the root directory, a
        trailing slash is good */

        if (t == path && slash)
                *(t++) = '/';

        *t = 0;
        return path;
}

bool path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        if ((path[0] == '/') != (prefix[0] == '/'))
                return false;

        for (;;) {
                size_t a, b;

                path += strspn(path, "/");
                prefix += strspn(prefix, "/");

                if (*prefix == 0)
                        return true;

                if (*path == 0)
                        return false;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");

                if (a != b)
                        return false;

                if (memcmp(path, prefix, a) != 0)
                        return false;

                path += a;
                prefix += b;
        }
}

char *ascii_strlower(char *t) {
        char *p;

        assert(t);

        for (p = t; *p; p++)
                if (*p >= 'A' && *p <= 'Z')
                        *p = *p - 'A' + 'a';

        return t;
}

bool ignore_file(const char *filename) {
        assert(filename);

        return
                filename[0] == '.' ||
                endswith(filename, "~") ||
                endswith(filename, ".rpmnew") ||
                endswith(filename, ".rpmsave") ||
                endswith(filename, ".rpmorig") ||
                endswith(filename, ".dpkg-old") ||
                endswith(filename, ".dpkg-new") ||
                endswith(filename, ".swp");
}

int fd_nonblock(int fd, bool nonblock) {
        int flags;

        assert(fd >= 0);

        if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
                return -errno;

        if (nonblock)
                flags |= O_NONBLOCK;
        else
                flags &= ~O_NONBLOCK;

        if (fcntl(fd, F_SETFL, flags) < 0)
                return -errno;

        return 0;
}

int fd_cloexec(int fd, bool cloexec) {
        int flags;

        assert(fd >= 0);

        if ((flags = fcntl(fd, F_GETFD, 0)) < 0)
                return -errno;

        if (cloexec)
                flags |= FD_CLOEXEC;
        else
                flags &= ~FD_CLOEXEC;

        if (fcntl(fd, F_SETFD, flags) < 0)
                return -errno;

        return 0;
}

int close_all_fds(const int except[], unsigned n_except) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        if (!(d = opendir("/proc/self/fd")))
                return -errno;

        while ((de = readdir(d))) {
                int fd = -1;

                if (de->d_name[0] == '.')
                        continue;

                if ((r = safe_atoi(de->d_name, &fd)) < 0)
                        goto finish;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if (except) {
                        bool found;
                        unsigned i;

                        found = false;
                        for (i = 0; i < n_except; i++)
                                if (except[i] == fd) {
                                        found = true;
                                        break;
                                }

                        if (found)
                                continue;
                }

                if ((r = close_nointr(fd)) < 0) {
                        /* Valgrind has its own FD and doesn't want to have it closed */
                        if (errno != EBADF)
                                goto finish;
                }
        }

        r = 0;

finish:
        closedir(d);
        return r;
}

bool chars_intersect(const char *a, const char *b) {
        const char *p;

        /* Returns true if any of the chars in a are in b. */
        for (p = a; *p; p++)
                if (strchr(b, *p))
                        return true;

        return false;
}

char *format_timestamp(char *buf, size_t l, usec_t t) {
        struct tm tm;
        time_t sec;

        assert(buf);
        assert(l > 0);

        if (t <= 0)
                return NULL;

        sec = (time_t) t / USEC_PER_SEC;

        if (strftime(buf, l, "%a, %d %b %Y %H:%M:%S %z", localtime_r(&sec, &tm)) <= 0)
                return NULL;

        return buf;
}

bool fstype_is_network(const char *fstype) {
        static const char * const table[] = {
                "cifs",
                "smbfs",
                "ncpfs",
                "nfs",
                "nfs4"
        };

        unsigned i;

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (streq(table[i], fstype))
                        return true;

        return false;
}

int chvt(int vt) {
        int fd, r = 0;

        if ((fd = open("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC)) < 0)
                return -errno;

        if (vt < 0) {
                int tiocl[2] = {
                        TIOCL_GETKMSGREDIRECT,
                        0
                };

                if (ioctl(fd, TIOCLINUX, tiocl) < 0)
                        return -errno;

                vt = tiocl[0] <= 0 ? 1 : tiocl[0];
        }

        if (ioctl(fd, VT_ACTIVATE, vt) < 0)
                r = -errno;

        close_nointr(r);
        return r;
}

int read_one_char(FILE *f, char *ret, bool *need_nl) {
        struct termios old_termios, new_termios;
        char c;
        char line[1024];

        assert(f);
        assert(ret);

        if (tcgetattr(fileno(f), &old_termios) >= 0) {
                new_termios = old_termios;

                new_termios.c_lflag &= ~ICANON;
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(fileno(f), TCSADRAIN, &new_termios) >= 0) {
                        size_t k;

                        k = fread(&c, 1, 1, f);

                        tcsetattr(fileno(f), TCSADRAIN, &old_termios);

                        if (k <= 0)
                                return -EIO;

                        if (need_nl)
                                *need_nl = c != '\n';

                        *ret = c;
                        return 0;
                }
        }

        if (!(fgets(line, sizeof(line), f)))
                return -EIO;

        truncate_nl(line);

        if (strlen(line) != 1)
                return -EBADMSG;

        if (need_nl)
                *need_nl = false;

        *ret = line[0];
        return 0;
}

int ask(char *ret, const char *replies, const char *text, ...) {
        assert(ret);
        assert(replies);
        assert(text);

        for (;;) {
                va_list ap;
                char c;
                int r;
                bool need_nl = true;

                va_start(ap, text);
                vprintf(text, ap);
                va_end(ap);

                fflush(stdout);

                if ((r = read_one_char(stdin, &c, &need_nl)) < 0) {

                        if (r == -EBADMSG) {
                                puts("Bad input, please try again.");
                                continue;
                        }

                        putchar('\n');
                        return r;
                }

                if (need_nl)
                        putchar('\n');

                if (strchr(replies, c)) {
                        *ret = c;
                        return 0;
                }

                puts("Read unexpected character, please try again.");
        }
}

int reset_terminal(int fd) {
        struct termios termios;
        int r = 0;

        assert(fd >= 0);

        /* Set terminal to some sane defaults */

        if (tcgetattr(fd, &termios) < 0) {
                r = -errno;
                goto finish;
        }

        /* We only reset the stuff that matters to the software. How
         * hardware is set up we don't touch assuming that somebody
         * else will do that for us */

        termios.c_iflag &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | IUCLC);
        termios.c_iflag |= ICRNL | IMAXBEL | IUTF8;
        termios.c_oflag |= ONLCR;
        termios.c_cflag |= CREAD;
        termios.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOPRT | ECHOKE;

        termios.c_cc[VINTR]    =   03;  /* ^C */
        termios.c_cc[VQUIT]    =  034;  /* ^\ */
        termios.c_cc[VERASE]   = 0177;
        termios.c_cc[VKILL]    =  025;  /* ^X */
        termios.c_cc[VEOF]     =   04;  /* ^D */
        termios.c_cc[VSTART]   =  021;  /* ^Q */
        termios.c_cc[VSTOP]    =  023;  /* ^S */
        termios.c_cc[VSUSP]    =  032;  /* ^Z */
        termios.c_cc[VLNEXT]   =  026;  /* ^V */
        termios.c_cc[VWERASE]  =  027;  /* ^W */
        termios.c_cc[VREPRINT] =  022;  /* ^R */
        termios.c_cc[VEOL]     =    0;
        termios.c_cc[VEOL2]    =    0;

        termios.c_cc[VTIME]  = 0;
        termios.c_cc[VMIN]   = 1;

        if (tcsetattr(fd, TCSANOW, &termios) < 0)
                r = -errno;

finish:
        /* Just in case, flush all crap out */
        tcflush(fd, TCIOFLUSH);

        return r;
}

int open_terminal(const char *name, int mode) {
        int fd, r;

        if ((fd = open(name, mode)) < 0)
                return -errno;

        if ((r = isatty(fd)) < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        if (!r) {
                close_nointr_nofail(fd);
                return -ENOTTY;
        }

        return fd;
}

int flush_fd(int fd) {
        struct pollfd pollfd;

        zero(pollfd);
        pollfd.fd = fd;
        pollfd.events = POLLIN;

        for (;;) {
                char buf[1024];
                ssize_t l;
                int r;

                if ((r = poll(&pollfd, 1, 0)) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (r == 0)
                        return 0;

                if ((l = read(fd, buf, sizeof(buf))) < 0) {

                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                if (l <= 0)
                        return 0;
        }
}

int acquire_terminal(const char *name, bool fail, bool force) {
        int fd = -1, notify = -1, r, wd;

        assert(name);

        /* We use inotify to be notified when the tty is closed. We
         * create the watch before checking if we can actually acquire
         * it, so that we don't lose any event.
         *
         * Note: strictly speaking this actually watches for the
         * device being closed, it does *not* really watch whether a
         * tty loses its controlling process. However, unless some
         * rogue process uses TIOCNOTTY on /dev/tty *after* closing
         * its tty otherwise this will not become a problem. As long
         * as the administrator makes sure not configure any service
         * on the same tty as an untrusted user this should not be a
         * problem. (Which he probably should not do anyway.) */

        if (!fail && !force) {
                if ((notify = inotify_init1(IN_CLOEXEC)) < 0) {
                        r = -errno;
                        goto fail;
                }

                if ((wd = inotify_add_watch(notify, name, IN_CLOSE)) < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        for (;;) {
                if ((r = flush_fd(notify)) < 0)
                        goto fail;

                /* We pass here O_NOCTTY only so that we can check the return
                 * value TIOCSCTTY and have a reliable way to figure out if we
                 * successfully became the controlling process of the tty */
                if ((fd = open_terminal(name, O_RDWR|O_NOCTTY)) < 0)
                        return -errno;

                /* First, try to get the tty */
                if ((r = ioctl(fd, TIOCSCTTY, force)) < 0 &&
                    (force || fail || errno != EPERM)) {
                        r = -errno;
                        goto fail;
                }

                if (r >= 0)
                        break;

                assert(!fail);
                assert(!force);
                assert(notify >= 0);

                for (;;) {
                        struct inotify_event e;
                        ssize_t l;

                        if ((l = read(notify, &e, sizeof(e))) != sizeof(e)) {

                                if (l < 0) {

                                        if (errno == EINTR)
                                                continue;

                                        r = -errno;
                                } else
                                        r = -EIO;

                                goto fail;
                        }

                        if (e.wd != wd || !(e.mask & IN_CLOSE)) {
                                r = -errno;
                                goto fail;
                        }

                        break;
                }

                /* We close the tty fd here since if the old session
                 * ended our handle will be dead. It's important that
                 * we do this after sleeping, so that we don't enter
                 * an endless loop. */
                close_nointr_nofail(fd);
        }

        if (notify >= 0)
                close_nointr(notify);

        if ((r = reset_terminal(fd)) < 0)
                log_warning("Failed to reset terminal: %s", strerror(-r));

        return fd;

fail:
        if (fd >= 0)
                close_nointr(fd);

        if (notify >= 0)
                close_nointr(notify);

        return r;
}

int release_terminal(void) {
        int r = 0, fd;

        if ((fd = open("/dev/tty", O_RDWR)) < 0)
                return -errno;

        if (ioctl(fd, TIOCNOTTY) < 0)
                r = -errno;

        close_nointr_nofail(fd);
        return r;
}

int ignore_signal(int sig) {
        struct sigaction sa;

        zero(sa);
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_RESTART;

        return sigaction(sig, &sa, NULL);
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP(ioprio_class, int);

static const char *const sigchld_code_table[] = {
        [CLD_EXITED] = "exited",
        [CLD_KILLED] = "killed",
        [CLD_DUMPED] = "dumped",
        [CLD_TRAPPED] = "trapped",
        [CLD_STOPPED] = "stopped",
        [CLD_CONTINUED] = "continued",
};

DEFINE_STRING_TABLE_LOOKUP(sigchld_code, int);

static const char *const log_facility_table[LOG_NFACILITIES] = {
        [LOG_FAC(LOG_KERN)] = "kern",
        [LOG_FAC(LOG_USER)] = "user",
        [LOG_FAC(LOG_MAIL)] = "mail",
        [LOG_FAC(LOG_DAEMON)] = "daemon",
        [LOG_FAC(LOG_AUTH)] = "auth",
        [LOG_FAC(LOG_SYSLOG)] = "syslog",
        [LOG_FAC(LOG_LPR)] = "lpr",
        [LOG_FAC(LOG_NEWS)] = "news",
        [LOG_FAC(LOG_UUCP)] = "uucp",
        [LOG_FAC(LOG_CRON)] = "cron",
        [LOG_FAC(LOG_AUTHPRIV)] = "authpriv",
        [LOG_FAC(LOG_FTP)] = "ftp",
        [LOG_FAC(LOG_LOCAL0)] = "local0",
        [LOG_FAC(LOG_LOCAL1)] = "local1",
        [LOG_FAC(LOG_LOCAL2)] = "local2",
        [LOG_FAC(LOG_LOCAL3)] = "local3",
        [LOG_FAC(LOG_LOCAL4)] = "local4",
        [LOG_FAC(LOG_LOCAL5)] = "local5",
        [LOG_FAC(LOG_LOCAL6)] = "local6",
        [LOG_FAC(LOG_LOCAL7)] = "local7"
};

DEFINE_STRING_TABLE_LOOKUP(log_facility, int);

static const char *const log_level_table[] = {
        [LOG_EMERG] = "emerg",
        [LOG_ALERT] = "alert",
        [LOG_CRIT] = "crit",
        [LOG_ERR] = "err",
        [LOG_WARNING] = "warning",
        [LOG_NOTICE] = "notice",
        [LOG_INFO] = "info",
        [LOG_DEBUG] = "debug"
};

DEFINE_STRING_TABLE_LOOKUP(log_level, int);

static const char* const sched_policy_table[] = {
        [SCHED_OTHER] = "other",
        [SCHED_BATCH] = "batch",
        [SCHED_IDLE] = "idle",
        [SCHED_FIFO] = "fifo",
        [SCHED_RR] = "rr"
};

DEFINE_STRING_TABLE_LOOKUP(sched_policy, int);

static const char* const rlimit_table[] = {
        [RLIMIT_CPU] = "LimitCPU",
        [RLIMIT_FSIZE] = "LimitFSIZE",
        [RLIMIT_DATA] = "LimitDATA",
        [RLIMIT_STACK] = "LimitSTACK",
        [RLIMIT_CORE] = "LimitCORE",
        [RLIMIT_RSS] = "LimitRSS",
        [RLIMIT_NOFILE] = "LimitNOFILE",
        [RLIMIT_AS] = "LimitAS",
        [RLIMIT_NPROC] = "LimitNPROC",
        [RLIMIT_MEMLOCK] = "LimitMEMLOCK",
        [RLIMIT_LOCKS] = "LimitLOCKS",
        [RLIMIT_SIGPENDING] = "LimitSIGPENDING",
        [RLIMIT_MSGQUEUE] = "LimitMSGQUEUE",
        [RLIMIT_NICE] = "LimitNICE",
        [RLIMIT_RTPRIO] = "LimitRTPRIO",
        [RLIMIT_RTTIME] = "LimitRTTIME"
};

DEFINE_STRING_TABLE_LOOKUP(rlimit, int);

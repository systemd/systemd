/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

#include "macro.h"
#include "util.h"

usec_t now(clockid_t clock) {
        struct timespec ts;

        assert_se(clock_gettime(clock, &ts) == 0);

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
char *split_spaces(const char *c, size_t *l, char **state) {
        char *current;

        current = *state ? *state : (char*) c;

        if (!*current || *c == 0)
                return NULL;

        current += strspn(current, WHITESPACE);
        *l = strcspn(current, WHITESPACE);
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
                *l = strcspn(current+1, "\"");
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

const char *sigchld_code(int code) {

        if (code == CLD_EXITED)
                return "exited";
        else if (code == CLD_KILLED)
                return "killed";
        else if (code == CLD_DUMPED)
                return "dumped";
        else if (code == CLD_TRAPPED)
                return "trapped";
        else if (code == CLD_STOPPED)
                return "stopped";
        else if (code == CLD_CONTINUED)
                return "continued";

        return "unknown";
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
        char t[64], *c;

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

        if (path_is_absolute(p) || !prefix)
                return strdup(p);

        if (asprintf(&r, "%s/%s", prefix, p) < 0)
                return NULL;

        return r;
}

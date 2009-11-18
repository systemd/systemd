/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

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

int nointr_close(int fd) {
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

        if (!strcmp(v, "1") || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T' || !strcasecmp(v, "on"))
                return 1;
        else if (!strcmp(v, "0") || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F' || !strcasecmp(v, "off"))
                return 0;

        return -EINVAL;
}

int safe_atou(const char *s, unsigned *ret_u) {
        char *x = NULL;
        unsigned l;

        assert(s);
        assert(ret_u);

        errno = 0;
        l = strtoul(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((unsigned) l != l)
                return -ERANGE;

        *ret_u = (unsigned) l;
        return 0;
}

int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        int l;

        assert(s);
        assert(ret_i);

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || *x || errno)
                return errno ? -errno : -EINVAL;

        if ((int) l != l)
                return -ERANGE;

        *ret_i = (unsigned) l;
        return 0;
}

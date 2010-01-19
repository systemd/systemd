/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooutilhfoo
#define fooutilhfoo

#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>

typedef uint64_t usec_t;

#define USEC_PER_SEC 1000000ULL
#define NSEC_PER_USEC 1000ULL

usec_t now(clockid_t clock);

usec_t timespec_load(const struct timespec *ts);
struct timespec *timespec_store(struct timespec *ts, usec_t u);

usec_t timeval_load(const struct timeval *tv);
struct timeval *timeval_store(struct timeval *tv, usec_t u);

#define streq(a,b) (strcmp((a),(b)) == 0)

#define new(t, n) ((t*) malloc(sizeof(t)*(n)))

#define new0(t, n) ((t*) calloc((n), sizeof(t)))

#define malloc0(n) (calloc((n), 1))

static inline const char* yes_no(bool b) {
        return b ? "yes" : "no";
}

static inline const char* strempty(const char *s) {
        return s ? s : "";
}

static inline const char* strnull(const char *s) {
        return s ? s : "(null)";
}

static inline const char *strna(const char *s) {
        return s ? s : "n/a";
}

static inline bool is_path_absolute(const char *p) {
        return *p == '/';
}

bool endswith(const char *s, const char *postfix);
bool startswith(const char *s, const char *prefix);

int close_nointr(int fd);

int parse_boolean(const char *v);

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

char *split_spaces(const char *c, size_t *l, char **state);

#define FOREACH_WORD(word, length, s, state)    \
        for ((state) = NULL, (word) = split_spaces((s), &(l), &(state)); (word); (word) = split_spaces((s), &(l), &(state)))

#endif

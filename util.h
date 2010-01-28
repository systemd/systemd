/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooutilhfoo
#define fooutilhfoo

#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdlib.h>

typedef uint64_t usec_t;

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  1000000ULL
#define USEC_PER_MSEC 1000ULL
#define NSEC_PER_SEC  1000000000ULL
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_USEC 1000ULL

/* What is interpreted as whitespace? */
#define WHITESPACE " \t\n\r"

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
void close_nointr_nofail(int fd);

int parse_boolean(const char *v);

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

int safe_atolu(const char *s, unsigned long *ret_u);
int safe_atoli(const char *s, long int *ret_i);

int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

char *split_spaces(const char *c, size_t *l, char **state);
char *split_quoted(const char *c, size_t *l, char **state);

#define FOREACH_WORD(word, length, s, state)                            \
        for ((state) = NULL, (word) = split_spaces((s), &(l), &(state)); (word); (word) = split_spaces((s), &(l), &(state)))

#define FOREACH_WORD_QUOTED(word, length, s, state)                     \
        for ((state) = NULL, (word) = split_quoted((s), &(l), &(state)); (word); (word) = split_quoted((s), &(l), &(state)))

const char *sigchld_code(int code);

pid_t get_parent_of_pid(pid_t pid, pid_t *ppid);

int write_one_line_file(const char *fn, const char *line);
int read_one_line_file(const char *fn, char **line);

char *strappend(const char *s, const char *suffix);

int readlink_malloc(const char *p, char **r);

char *file_name_from_path(const char *p);
bool is_path(const char *p);

bool path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);

int reset_all_signal_handlers(void);

char *strstrip(char *s);
char *file_in_same_dir(const char *path, const char *filename);

#endif

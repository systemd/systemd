/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooutilhfoo
#define fooutilhfoo

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

#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

typedef uint64_t usec_t;

typedef struct timestamp {
        usec_t realtime;
        usec_t monotonic;
} timestamp;

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  1000000ULL
#define USEC_PER_MSEC 1000ULL
#define NSEC_PER_SEC  1000000000ULL
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_USEC 1000ULL

#define USEC_PER_MINUTE (60ULL*USEC_PER_SEC)
#define USEC_PER_HOUR (60ULL*USEC_PER_MINUTE)
#define USEC_PER_DAY (24ULL*USEC_PER_HOUR)
#define USEC_PER_WEEK (7ULL*USEC_PER_DAY)

/* What is interpreted as whitespace? */
#define WHITESPACE " \t\n\r"
#define NEWLINE "\n\r"

#define FORMAT_TIMESTAMP_MAX 64
#define FORMAT_TIMESPAN_MAX 64

usec_t now(clockid_t clock);

timestamp* timestamp_get(timestamp *ts);

usec_t timespec_load(const struct timespec *ts);
struct timespec *timespec_store(struct timespec *ts, usec_t u);

usec_t timeval_load(const struct timeval *tv);
struct timeval *timeval_store(struct timeval *tv, usec_t u);

#define streq(a,b) (strcmp((a),(b)) == 0)

bool streq_ptr(const char *a, const char *b);

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
bool startswith_no_case(const char *s, const char *prefix);

bool first_word(const char *s, const char *word);

int close_nointr(int fd);
void close_nointr_nofail(int fd);

int parse_boolean(const char *v);
int parse_usec(const char *t, usec_t *usec);

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

int safe_atolu(const char *s, unsigned long *ret_u);
int safe_atoli(const char *s, long int *ret_i);

int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

char *split(const char *c, size_t *l, const char *separator, char **state);
char *split_quoted(const char *c, size_t *l, char **state);

#define FOREACH_WORD(word, length, s, state)                            \
        for ((state) = NULL, (word) = split((s), &(length), WHITESPACE, &(state)); (word); (word) = split((s), &(length), WHITESPACE, &(state)))

#define FOREACH_WORD_SEPARATOR(word, length, s, separator, state)       \
        for ((state) = NULL, (word) = split((s), &(length), (separator), &(state)); (word); (word) = split((s), &(length), (separator), &(state)))

#define FOREACH_WORD_QUOTED(word, length, s, state)                     \
        for ((state) = NULL, (word) = split_quoted((s), &(length), &(state)); (word); (word) = split_quoted((s), &(length), &(state)))

char **split_path_and_make_absolute(const char *p);

pid_t get_parent_of_pid(pid_t pid, pid_t *ppid);

int write_one_line_file(const char *fn, const char *line);
int read_one_line_file(const char *fn, char **line);

char *strappend(const char *s, const char *suffix);

int readlink_malloc(const char *p, char **r);

char *file_name_from_path(const char *p);
bool is_path(const char *p);

bool path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);
char *path_make_absolute_cwd(const char *p);

char **strv_path_make_absolute_cwd(char **l);
char **strv_path_canonicalize(char **l);

int reset_all_signal_handlers(void);

char *strstrip(char *s);
char *delete_chars(char *s, const char *bad);
char *truncate_nl(char *s);

char *file_in_same_dir(const char *path, const char *filename);
int mkdir_parents(const char *path, mode_t mode);
int mkdir_p(const char *path, mode_t mode);

int get_process_name(pid_t pid, char **name);

char hexchar(int x);
int unhexchar(char c);
char octchar(int x);
int unoctchar(char c);
char decchar(int x);
int undecchar(char c);

char *cescape(const char *s);
char *cunescape(const char *s);

char *path_kill_slashes(char *path);

bool path_startswith(const char *path, const char *prefix);
bool path_equal(const char *a, const char *b);

char *ascii_strlower(char *path);

char *xescape(const char *s, const char *bad);

char *bus_path_escape(const char *s);
char *bus_path_unescape(const char *s);

bool ignore_file(const char *filename);

bool chars_intersect(const char *a, const char *b);

char *format_timestamp(char *buf, size_t l, usec_t t);
char *format_timespan(char *buf, size_t l, usec_t t);

int make_stdio(int fd);

bool is_clean_exit(int code, int status);

#define DEFINE_STRING_TABLE_LOOKUP(name,type)                           \
        const char *name##_to_string(type i) {                          \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }                                                               \
        type name##_from_string(const char *s) {                        \
                type i;                                                 \
                unsigned u = 0;                                         \
                assert(s);                                              \
                for (i = 0; i < (type)ELEMENTSOF(name##_table); i++)    \
                        if (streq(name##_table[i], s))                  \
                                return i;                               \
                if (safe_atou(s, &u) >= 0 &&                            \
                    u < ELEMENTSOF(name##_table))                       \
                        return (type) u;                                \
                return (type) -1;                                       \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__


int fd_nonblock(int fd, bool nonblock);
int fd_cloexec(int fd, bool cloexec);

int close_all_fds(const int except[], unsigned n_except);

bool fstype_is_network(const char *fstype);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, bool *need_nl);
int ask(char *ret, const char *replies, const char *text, ...);

int reset_terminal(int fd);
int open_terminal(const char *name, int mode);
int acquire_terminal(const char *name, bool fail, bool force, bool ignore_tiocstty_eperm);
int release_terminal(void);

int flush_fd(int fd);

int ignore_signals(int sig, ...);
int default_signals(int sig, ...);
int sigaction_many(const struct sigaction *sa, ...);

int close_pipe(int p[]);

ssize_t loop_read(int fd, void *buf, size_t nbytes);

int path_is_mount_point(const char *path);

bool is_device_path(const char *path);

int dir_is_empty(const char *path);

extern char * __progname;

const char *ioprio_class_to_string(int i);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i);
int sigchld_code_from_string(const char *s);

const char *log_facility_to_string(int i);
int log_facility_from_string(const char *s);

const char *log_level_to_string(int i);
int log_level_from_string(const char *s);

const char *sched_policy_to_string(int i);
int sched_policy_from_string(const char *s);

const char *rlimit_to_string(int i);
int rlimit_from_string(const char *s);

#endif

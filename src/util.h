/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>

#include "macro.h"

typedef uint64_t usec_t;

typedef struct dual_timestamp {
        usec_t realtime;
        usec_t monotonic;
} dual_timestamp;

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
#define USEC_PER_MONTH (2629800ULL*USEC_PER_SEC)
#define USEC_PER_YEAR (31557600ULL*USEC_PER_SEC)

/* What is interpreted as whitespace? */
#define WHITESPACE " \t\n\r"
#define NEWLINE "\n\r"
#define QUOTES "\"\'"
#define COMMENTS "#;\n"

#define FORMAT_TIMESTAMP_MAX 64
#define FORMAT_TIMESTAMP_PRETTY_MAX 256
#define FORMAT_TIMESPAN_MAX 64
#define FORMAT_BYTES_MAX 8

#define ANSI_HIGHLIGHT_ON "\x1B[1;39m"
#define ANSI_HIGHLIGHT_RED_ON "\x1B[1;31m"
#define ANSI_HIGHLIGHT_GREEN_ON "\x1B[1;32m"
#define ANSI_HIGHLIGHT_OFF "\x1B[0m"

usec_t now(clockid_t clock);

dual_timestamp* dual_timestamp_get(dual_timestamp *ts);
dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u);

#define dual_timestamp_is_set(ts) ((ts)->realtime > 0)

usec_t timespec_load(const struct timespec *ts);
struct timespec *timespec_store(struct timespec *ts, usec_t u);

usec_t timeval_load(const struct timeval *tv);
struct timeval *timeval_store(struct timeval *tv, usec_t u);

size_t page_size(void);
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)

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

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

bool endswith(const char *s, const char *postfix);
bool startswith(const char *s, const char *prefix);
bool startswith_no_case(const char *s, const char *prefix);

bool first_word(const char *s, const char *word);

int close_nointr(int fd);
void close_nointr_nofail(int fd);
void close_many(const int fds[], unsigned n_fd);

int parse_boolean(const char *v);
int parse_usec(const char *t, usec_t *usec);
int parse_bytes(const char *t, off_t *bytes);
int parse_pid(const char *s, pid_t* ret_pid);
int parse_uid(const char *s, uid_t* ret_uid);
#define parse_gid(s, ret_uid) parse_uid(s, ret_uid)

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

#if __WORDSIZE == 32
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(int));
        return safe_atoi(s, (int*) ret_u);
}
#else
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_u);
}
#endif

static inline int safe_atou32(const char *s, uint32_t *ret_u) {
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}

static inline int safe_atoi32(const char *s, int32_t *ret_i) {
        assert_cc(sizeof(int32_t) == sizeof(int));
        return safe_atoi(s, (int*) ret_i);
}

static inline int safe_atou64(const char *s, uint64_t *ret_u) {
        assert_cc(sizeof(uint64_t) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}

static inline int safe_atoi64(const char *s, int64_t *ret_i) {
        assert_cc(sizeof(int64_t) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_i);
}

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
int get_starttime_of_pid(pid_t pid, unsigned long long *st);

int write_one_line_file(const char *fn, const char *line);
int write_one_line_file_atomic(const char *fn, const char *line);
int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);

int parse_env_file(const char *fname, const char *separator, ...) _sentinel_;
int load_env_file(const char *fname, char ***l);
int write_env_file(const char *fname, char **l);

char *strappend(const char *s, const char *suffix);
char *strnappend(const char *s, const char *suffix, size_t length);

char *replace_env(const char *format, char **env);
char **replace_env_argv(char **argv, char **env);

int readlink_malloc(const char *p, char **r);
int readlink_and_make_absolute(const char *p, char **r);
int readlink_and_canonicalize(const char *p, char **r);

char *file_name_from_path(const char *p);
bool is_path(const char *p);

bool path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);
char *path_make_absolute_cwd(const char *p);

char **strv_path_make_absolute_cwd(char **l);
char **strv_path_canonicalize(char **l);
char **strv_path_remove_empty(char **l);

int reset_all_signal_handlers(void);

char *strstrip(char *s);
char *delete_chars(char *s, const char *bad);
char *truncate_nl(char *s);

char *file_in_same_dir(const char *path, const char *filename);
int safe_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_parents(const char *path, mode_t mode);
int mkdir_p(const char *path, mode_t mode);

int parent_of_path(const char *path, char **parent);

int rmdir_parents(const char *path, const char *stop);

int get_process_comm(pid_t pid, char **name);
int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line);
int get_process_exe(pid_t pid, char **name);
int get_process_uid(pid_t pid, uid_t *uid);

char hexchar(int x);
int unhexchar(char c);
char octchar(int x);
int unoctchar(char c);
char decchar(int x);
int undecchar(char c);

char *cescape(const char *s);
char *cunescape(const char *s);
char *cunescape_length(const char *s, size_t length);

char *xescape(const char *s, const char *bad);

char *bus_path_escape(const char *s);
char *bus_path_unescape(const char *s);

char *path_kill_slashes(char *path);

bool path_startswith(const char *path, const char *prefix);
bool path_equal(const char *a, const char *b);

char *ascii_strlower(char *path);

bool dirent_is_file(const struct dirent *de);
bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix);

bool ignore_file(const char *filename);

bool chars_intersect(const char *a, const char *b);

char *format_timestamp(char *buf, size_t l, usec_t t);
char *format_timestamp_pretty(char *buf, size_t l, usec_t t);
char *format_timespan(char *buf, size_t l, usec_t t);

int make_stdio(int fd);
int make_null_stdio(void);

unsigned long long random_ull(void);

#define __DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                   \
        scope const char *name##_to_string(type i) {                    \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }                                                               \
        scope type name##_from_string(const char *s) {                  \
                type i;                                                 \
                unsigned u = 0;                                         \
                assert(s);                                              \
                for (i = 0; i < (type)ELEMENTSOF(name##_table); i++)    \
                        if (name##_table[i] &&                          \
                            streq(name##_table[i], s))                  \
                                return i;                               \
                if (safe_atou(s, &u) >= 0 &&                            \
                    u < ELEMENTSOF(name##_table))                       \
                        return (type) u;                                \
                return (type) -1;                                       \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define DEFINE_STRING_TABLE_LOOKUP(name,type) __DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) __DEFINE_STRING_TABLE_LOOKUP(name,type,static)

int fd_nonblock(int fd, bool nonblock);
int fd_cloexec(int fd, bool cloexec);

int close_all_fds(const int except[], unsigned n_except);

bool fstype_is_network(const char *fstype);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool *need_nl);
int ask(char *ret, const char *replies, const char *text, ...);

int reset_terminal_fd(int fd, bool switch_to_text);
int reset_terminal(const char *name);

int open_terminal(const char *name, int mode);
int acquire_terminal(const char *name, bool fail, bool force, bool ignore_tiocstty_eperm);
int release_terminal(void);

int flush_fd(int fd);

int ignore_signals(int sig, ...);
int default_signals(int sig, ...);
int sigaction_many(const struct sigaction *sa, ...);

int close_pipe(int p[]);
int fopen_temporary(const char *path, FILE **_f, char **_temp_path);

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
ssize_t loop_write(int fd, const void *buf, size_t nbytes, bool do_poll);

int path_is_mount_point(const char *path, bool allow_symlink);

bool is_device_path(const char *path);

int dir_is_empty(const char *path);

void rename_process(const char name[8]);

void sigset_add_many(sigset_t *ss, ...);

char* gethostname_malloc(void);
char* getlogname_malloc(void);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
int fchmod_and_fchown(int fd, mode_t mode, uid_t uid, gid_t gid);

int rm_rf(const char *path, bool only_dirs, bool delete_root, bool honour_sticky);

int pipe_eof(int fd);

cpu_set_t* cpu_set_malloc(unsigned *ncpus);

void status_vprintf(const char *status, bool ellipse, const char *format, va_list ap);
void status_printf(const char *status, bool ellipse, const char *format, ...);
void status_welcome(void);

int fd_columns(int fd);
unsigned columns(void);

int fd_lines(int fd);
unsigned lines(void);

int running_in_chroot(void);

char *ellipsize(const char *s, size_t length, unsigned percent);
char *ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent);

int touch(const char *path);

char *unquote(const char *s, const char *quotes);
char *normalize_env_assignment(const char *s);

int wait_for_terminate(pid_t pid, siginfo_t *status);
int wait_for_terminate_and_warn(const char *name, pid_t pid);

_noreturn_ void freeze(void);

bool null_or_empty(struct stat *st);
int null_or_empty_path(const char *fn);

DIR *xopendirat(int dirfd, const char *name, int flags);

void dual_timestamp_serialize(FILE *f, const char *name, dual_timestamp *t);
void dual_timestamp_deserialize(const char *value, dual_timestamp *t);

char *fstab_node_to_udev_node(const char *p);

void filter_environ(const char *prefix);

bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
int vtnr_from_tty(const char *tty);
const char *default_term_for_tty(const char *tty);

void execute_directory(const char *directory, DIR *_d, char *argv[]);

int kill_and_sigcont(pid_t pid, int sig);

bool nulstr_contains(const char*nulstr, const char *needle);

bool plymouth_running(void);

void parse_syslog_priority(char **p, int *priority);
void skip_syslog_pid(char **buf);
void skip_syslog_date(char **buf);

int have_effective_cap(int value);

bool hostname_is_valid(const char *s);
char* hostname_cleanup(char *s);

char* strshorten(char *s, size_t l);

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *name);

int vt_disallocate(const char *name);

int copy_file(const char *from, const char *to);
int symlink_or_copy(const char *from, const char *to);
int symlink_or_copy_atomic(const char *from, const char *to);

int fchmod_umask(int fd, mode_t mode);

int conf_files_list(char ***strv, const char *suffix, const char *dir, ...);

int hwclock_is_localtime(void);
int hwclock_apply_localtime_delta(int *min);
int hwclock_reset_localtime_delta(void);
int hwclock_get_time(struct tm *tm);
int hwclock_set_time(const struct tm *tm);

int audit_session_from_pid(pid_t pid, uint32_t *id);
int audit_loginuid_from_pid(pid_t pid, uid_t *uid);

bool display_is_local(const char *display);
int socket_from_display(const char *display, char **path);

int get_user_creds(const char **username, uid_t *uid, gid_t *gid, const char **home);
int get_group_creds(const char **groupname, gid_t *gid);

int in_group(const char *name);

int glob_exists(const char *path);

int dirent_ensure_type(DIR *d, struct dirent *de);

int in_search_path(const char *path, char **search);
int get_files_in_directory(const char *path, char ***list);

char *join(const char *x, ...) _sentinel_;

bool is_main_thread(void);

bool in_charset(const char *s, const char* charset);

int block_get_whole_disk(dev_t d, dev_t *ret);

int file_is_priv_sticky(const char *p);

int strdup_or_null(const char *a, char **b);

#define NULSTR_FOREACH(i, l)                                    \
        for ((i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for ((i) = (l), (j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

const char *ioprio_class_to_string(int i);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i);
int sigchld_code_from_string(const char *s);

const char *log_facility_unshifted_to_string(int i);
int log_facility_unshifted_from_string(const char *s);

const char *log_level_to_string(int i);
int log_level_from_string(const char *s);

const char *sched_policy_to_string(int i);
int sched_policy_from_string(const char *s);

const char *rlimit_to_string(int i);
int rlimit_from_string(const char *s);

const char *ip_tos_to_string(int i);
int ip_tos_from_string(const char *s);

const char *signal_to_string(int i);
int signal_from_string(const char *s);

int signal_from_string_try_harder(const char *s);

extern int saved_argc;
extern char **saved_argv;

bool kexec_loaded(void);

int prot_from_flags(int flags);

unsigned long cap_last_cap(void);

char *format_bytes(char *buf, size_t l, off_t t);

int fd_wait_for_event(int fd, int event, usec_t timeout);

void* memdup(const void *p, size_t l);

int rtc_open(int flags);

int is_kernel_thread(pid_t pid);

int fd_inc_sndbuf(int fd, size_t n);
int fd_inc_rcvbuf(int fd, size_t n);

#endif

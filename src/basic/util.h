/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <alloca.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <mntent.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "formats-util.h"
#include "macro.h"
#include "missing.h"
#include "time-util.h"

/* What is interpreted as whitespace? */
#define WHITESPACE " \t\n\r"
#define NEWLINE    "\n\r"
#define QUOTES     "\"\'"
#define COMMENTS   "#;"
#define GLOB_CHARS "*?["

size_t page_size(void) _pure_;
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

#define new(t, n) ((t*) malloc_multiply(sizeof(t), (n)))

#define new0(t, n) ((t*) calloc((n), sizeof(t)))

#define newa(t, n) ((t*) alloca(sizeof(t)*(n)))

#define newa0(t, n) ((t*) alloca0(sizeof(t)*(n)))

#define newdup(t, p, n) ((t*) memdup_multiply(p, sizeof(t), (n)))

#define malloc0(n) (calloc(1, (n)))

static inline void *mfree(void *memory) {
        free(memory);
        return NULL;
}

static inline const char* yes_no(bool b) {
        return b ? "yes" : "no";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **r);
int readlink_value(const char *p, char **ret);
int readlink_and_make_absolute(const char *p, char **r);
int readlink_and_canonicalize(const char *p, char **r);

char *file_in_same_dir(const char *path, const char *filename);

int rmdir_parents(const char *path, const char *stop);

char hexchar(int x) _const_;
int unhexchar(char c) _const_;
char octchar(int x) _const_;
int unoctchar(char c) _const_;
char decchar(int x) _const_;
int undecchar(char c) _const_;
char base32hexchar(int x) _const_;
int unbase32hexchar(char c) _const_;
char base64char(int x) _const_;
int unbase64char(char c) _const_;

bool dirent_is_file(const struct dirent *de) _pure_;
bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) _pure_;

bool hidden_file(const char *filename) _pure_;

/* For basic lookup tables with strictly enumerated entries */
#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        scope const char *name##_to_string(type i) {                    \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }

ssize_t string_table_lookup(const char * const *table, size_t len, const char *key);

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        scope type name##_from_string(const char *s) {                  \
                return (type) string_table_lookup(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        struct __useless_struct_to_allow_trailing_semicolon__

#define DEFINE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,static)

/* For string conversions where numbers are also acceptable */
#define DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(name,type,max)         \
        int name##_to_string_alloc(type i, char **str) {                \
                char *s;                                                \
                if (i < 0 || i > max)                                   \
                        return -ERANGE;                                 \
                if (i < (type) ELEMENTSOF(name##_table)) {              \
                        s = strdup(name##_table[i]);                    \
                        if (!s)                                         \
                                return -ENOMEM;                         \
                } else {                                                \
                        if (asprintf(&s, "%i", i) < 0)                  \
                                return -ENOMEM;                         \
                }                                                       \
                *str = s;                                               \
                return 0;                                               \
        }                                                               \
        type name##_from_string(const char *s) {                        \
                type i;                                                 \
                unsigned u = 0;                                         \
                if (!s)                                                 \
                        return (type) -1;                               \
                for (i = 0; i < (type) ELEMENTSOF(name##_table); i++)   \
                        if (streq_ptr(name##_table[i], s))              \
                                return i;                               \
                if (safe_atou(s, &u) >= 0 && u <= max)                  \
                        return (type) u;                                \
                return (type) -1;                                       \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

bool fstype_is_network(const char *fstype);

int fopen_temporary(const char *path, FILE **_f, char **_temp_path);

bool is_device_path(const char *path);

int dir_is_empty(const char *path);
char* dirname_malloc(const char *path);

static inline int dir_is_populated(const char *path) {
        int r;
        r = dir_is_empty(path);
        if (r < 0)
                return r;
        return !r;
}

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
int fchmod_and_fchown(int fd, mode_t mode, uid_t uid, gid_t gid);

typedef long statfs_f_type_t;

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) _pure_;
int fd_check_fstype(int fd, statfs_f_type_t magic_value);
int path_check_fstype(const char *path, statfs_f_type_t magic_value);

bool is_temporary_fs(const struct statfs *s) _pure_;
int fd_is_temporary_fs(int fd);

#define xsprintf(buf, fmt, ...) \
        assert_message_se((size_t) snprintf(buf, ELEMENTSOF(buf), fmt, __VA_ARGS__) < ELEMENTSOF(buf), \
                          "xsprintf: " #buf "[] must be big enough")

int files_same(const char *filea, const char *fileb);

int running_in_chroot(void);

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode);
int touch(const char *path);

noreturn void freeze(void);

bool null_or_empty(struct stat *st) _pure_;
int null_or_empty_path(const char *fn);
int null_or_empty_fd(int fd);

DIR *xopendirat(int dirfd, const char *name, int flags);

char *fstab_node_to_udev_node(const char *p);

void execute_directories(const char* const* directories, usec_t timeout, char *argv[]);

bool plymouth_running(void);

int symlink_idempotent(const char *from, const char *to);

int symlink_atomic(const char *from, const char *to);
int mknod_atomic(const char *path, mode_t mode, dev_t dev);
int mkfifo_atomic(const char *path, mode_t mode);

int fchmod_umask(int fd, mode_t mode);

bool display_is_local(const char *display) _pure_;
int socket_from_display(const char *display, char **path);

int glob_exists(const char *path);
int glob_extend(char ***strv, const char *path);

int dirent_ensure_type(DIR *d, struct dirent *de);

int get_files_in_directory(const char *path, char ***list);

bool is_main_thread(void);

int block_get_whole_disk(dev_t d, dev_t *ret);

#define NULSTR_FOREACH(i, l)                                    \
        for ((i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for ((i) = (l), (j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i) _const_;
int sigchld_code_from_string(const char *s) _pure_;

int log_facility_unshifted_to_string_alloc(int i, char **s);
int log_facility_unshifted_from_string(const char *s);
bool log_facility_unshifted_is_valid(int faciliy);

int log_level_to_string_alloc(int i, char **s);
int log_level_from_string(const char *s);
bool log_level_is_valid(int level);

int sched_policy_to_string_alloc(int i, char **s);
int sched_policy_from_string(const char *s);

const char *rlimit_to_string(int i) _const_;
int rlimit_from_string(const char *s) _pure_;

extern int saved_argc;
extern char **saved_argv;

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

void* memdup(const void *p, size_t l) _alloc_(2);

int fork_agent(pid_t *pid, const int except[], unsigned n_except, const char *path, ...);

int setrlimit_closest(int resource, const struct rlimit *rlim);

bool http_url_is_valid(const char *url) _pure_;
bool documentation_url_is_valid(const char *url) _pure_;

bool http_etag_is_valid(const char *etag);

bool in_initrd(void);

static inline void freep(void *p) {
        free(*(void**) p);
}

static inline void umaskp(mode_t *u) {
        umask(*u);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, endmntent);

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_umask_ _cleanup_(umaskp)
#define _cleanup_globfree_ _cleanup_(globfree)
#define _cleanup_endmntent_ _cleanup_(endmntentp)

_malloc_  _alloc_(1, 2) static inline void *malloc_multiply(size_t a, size_t b) {
        if (_unlikely_(b != 0 && a > ((size_t) -1) / b))
                return NULL;

        return malloc(a * b);
}

_alloc_(2, 3) static inline void *realloc_multiply(void *p, size_t a, size_t b) {
        if (_unlikely_(b != 0 && a > ((size_t) -1) / b))
                return NULL;

        return realloc(p, a * b);
}

_alloc_(2, 3) static inline void *memdup_multiply(const void *p, size_t a, size_t b) {
        if (_unlikely_(b != 0 && a > ((size_t) -1) / b))
                return NULL;

        return memdup(p, a * b);
}

bool filename_is_valid(const char *p) _pure_;
bool path_is_safe(const char *p) _pure_;
bool string_is_safe(const char *p) _pure_;

/**
 * Check if a string contains any glob patterns.
 */
_pure_ static inline bool string_is_glob(const char *p) {
        return !!strpbrk(p, GLOB_CHARS);
}

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 int (*compar) (const void *, const void *, void *),
                 void *arg);

#define _(String) gettext (String)
#define N_(String) String
void init_gettext(void);
bool is_locale_utf8(void);

typedef enum DrawSpecialChar {
        DRAW_TREE_VERTICAL,
        DRAW_TREE_BRANCH,
        DRAW_TREE_RIGHT,
        DRAW_TREE_SPACE,
        DRAW_TRIANGULAR_BULLET,
        DRAW_BLACK_CIRCLE,
        DRAW_ARROW,
        DRAW_DASH,
        _DRAW_SPECIAL_CHAR_MAX
} DrawSpecialChar;

const char *draw_special_char(DrawSpecialChar ch);

int on_ac_power(void);

int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **_f);
int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **_f);

#define FOREACH_LINE(line, f, on_error)                         \
        for (;;)                                                \
                if (!fgets(line, sizeof(line), f)) {            \
                        if (ferror(f)) {                        \
                                on_error;                       \
                        }                                       \
                        break;                                  \
                } else

#define FOREACH_DIRENT(de, d, on_error)                                 \
        for (errno = 0, de = readdir(d);; errno = 0, de = readdir(d))   \
                if (!de) {                                              \
                        if (errno > 0) {                                \
                                on_error;                               \
                        }                                               \
                        break;                                          \
                } else if (hidden_file((de)->d_name))                   \
                        continue;                                       \
                else

#define FOREACH_DIRENT_ALL(de, d, on_error)                             \
        for (errno = 0, de = readdir(d);; errno = 0, de = readdir(d))   \
                if (!de) {                                              \
                        if (errno > 0) {                                \
                                on_error;                               \
                        }                                               \
                        break;                                          \
                } else

static inline void *mempset(void *s, int c, size_t n) {
        memset(s, c, n);
        return (uint8_t*)s + n;
}

char *hexmem(const void *p, size_t l);
int unhexmem(const char *p, size_t l, void **mem, size_t *len);

char *base32hexmem(const void *p, size_t l, bool padding);
int unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *len);

char *base64mem(const void *p, size_t l);
int unbase64mem(const char *p, size_t l, void **mem, size_t *len);

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size);
void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size);
#define GREEDY_REALLOC(array, allocated, need)                          \
        greedy_realloc((void**) &(array), &(allocated), (need), sizeof((array)[0]))

#define GREEDY_REALLOC0(array, allocated, need)                         \
        greedy_realloc0((void**) &(array), &(allocated), (need), sizeof((array)[0]))

static inline void _reset_errno_(int *saved_errno) {
        errno = *saved_errno;
}

#define PROTECT_ERRNO _cleanup_(_reset_errno_) __attribute__((unused)) int _saved_errno_ = errno

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

struct _umask_struct_ {
        mode_t mask;
        bool quit;
};

static inline void _reset_umask_(struct _umask_struct_ *s) {
        umask(s->mask);
};

#define RUN_WITH_UMASK(mask)                                            \
        for (_cleanup_(_reset_umask_) struct _umask_struct_ _saved_umask_ = { umask(mask), false }; \
             !_saved_umask_.quit ;                                      \
             _saved_umask_.quit = true)

static inline unsigned u64log2(uint64_t n) {
#if __SIZEOF_LONG_LONG__ == 8
        return (n > 1) ? (unsigned) __builtin_clzll(n) ^ 63U : 0;
#else
#error "Wut?"
#endif
}

static inline unsigned u32ctz(uint32_t n) {
#if __SIZEOF_INT__ == 4
        return __builtin_ctz(n);
#else
#error "Wut?"
#endif
}

static inline unsigned log2i(int x) {
        assert(x > 0);

        return __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return sizeof(unsigned) * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

#define DECIMAL_STR_WIDTH(x)                            \
        ({                                              \
                typeof(x) _x_ = (x);                    \
                unsigned ans = 1;                       \
                while (_x_ /= 10)                       \
                        ans++;                          \
                ans;                                    \
        })

int unlink_noerrno(const char *path);

#define alloca0(n)                                      \
        ({                                              \
                char *_new_;                            \
                size_t _len_ = n;                       \
                _new_ = alloca(_len_);                  \
                (void *) memset(_new_, 0, _len_);       \
        })

/* It's not clear what alignment glibc/gcc alloca() guarantee, hence provide a guaranteed safe version */
#define alloca_align(size, align)                                       \
        ({                                                              \
                void *_ptr_;                                            \
                size_t _mask_ = (align) - 1;                            \
                _ptr_ = alloca((size) + _mask_);                        \
                (void*)(((uintptr_t)_ptr_ + _mask_) & ~_mask_);         \
        })

#define alloca0_align(size, align)                                      \
        ({                                                              \
                void *_new_;                                            \
                size_t _size_ = (size);                                 \
                _new_ = alloca_align(_size_, (align));                  \
                (void*)memset(_new_, 0, _size_);                        \
        })

bool id128_is_valid(const char *s) _pure_;

int shall_restore_state(void);

/**
 * Normal qsort requires base to be nonnull. Here were require
 * that only if nmemb > 0.
 */
static inline void qsort_safe(void *base, size_t nmemb, size_t size, comparison_fn_t compar) {
        if (nmemb <= 1)
                return;

        assert(base);
        qsort(base, nmemb, size, compar);
}

int proc_cmdline(char **ret);
int parse_proc_cmdline(int (*parse_word)(const char *key, const char *value));
int get_proc_cmdline_key(const char *parameter, char **value);

int container_get_leader(const char *machine, pid_t *pid);

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);

int mkostemp_safe(char *pattern, int flags);
int open_tmpfile(const char *path, int flags);

int fd_warn_permissions(const char *path, int fd);

#ifndef PERSONALITY_INVALID
/* personality(7) documents that 0xffffffffUL is used for querying the
 * current personality, hence let's use that here as error
 * indicator. */
#define PERSONALITY_INVALID 0xffffffffLU
#endif

unsigned long personality_from_string(const char *p);
const char *personality_to_string(unsigned long);

uint64_t physical_memory(void);

void hexdump(FILE *f, const void *p, size_t s);

union file_handle_union {
        struct file_handle handle;
        char padding[sizeof(struct file_handle) + MAX_HANDLE_SZ];
};
#define FILE_HANDLE_INIT { .handle.handle_bytes = MAX_HANDLE_SZ }

int update_reboot_param_file(const char *param);

int umount_recursive(const char *target, int flags);

int bind_remount_recursive(const char *prefix, bool ro);

int fflush_and_check(FILE *f);

int tempfn_xxxxxx(const char *p, const char *extra, char **ret);
int tempfn_random(const char *p, const char *extra, char **ret);
int tempfn_random_child(const char *p, const char *extra, char **ret);

int take_password_lock(const char *root);

int is_symlink(const char *path);
int is_dir(const char *path, bool follow);
int is_device_node(const char *path);

#define INOTIFY_EVENT_MAX (sizeof(struct inotify_event) + NAME_MAX + 1)

#define FOREACH_INOTIFY_EVENT(e, buffer, sz) \
        for ((e) = &buffer.ev;                                \
             (uint8_t*) (e) < (uint8_t*) (buffer.raw) + (sz); \
             (e) = (struct inotify_event*) ((uint8_t*) (e) + sizeof(struct inotify_event) + (e)->len))

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

#define laccess(path, mode) faccessat(AT_FDCWD, (path), (mode), AT_SYMLINK_NOFOLLOW)

ssize_t fgetxattrat_fake(int dirfd, const char *filename, const char *attribute, void *value, size_t size, int flags);

int fd_setcrtime(int fd, usec_t usec);
int fd_getcrtime(int fd, usec_t *usec);
int path_getcrtime(const char *p, usec_t *usec);
int fd_getcrtime_at(int dirfd, const char *name, usec_t *usec, int flags);

int chattr_fd(int fd, unsigned value, unsigned mask);
int chattr_path(const char *p, unsigned value, unsigned mask);

int read_attr_fd(int fd, unsigned *ret);
int read_attr_path(const char *p, unsigned *ret);

#define RLIMIT_MAKE_CONST(lim) ((struct rlimit) { lim, lim })

int syslog_parse_priority(const char **p, int *priority, bool with_facility);

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int mount_move_root(const char *path);

int getxattr_malloc(const char *path, const char *name, char **value, bool allow_symlink);
int fgetxattr_malloc(int fd, const char *name, char **value);

int version(void);

bool fdname_is_valid(const char *s);

bool oom_score_adjust_is_valid(int oa);

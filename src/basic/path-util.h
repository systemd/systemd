/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define PATH_SPLIT_BIN(x) x "sbin:" x "bin"
#define PATH_SPLIT_BIN_NULSTR(x) x "sbin\0" x "bin\0"

#define PATH_MERGED_BIN(x) x "bin"
#define PATH_MERGED_BIN_NULSTR(x) x "bin\0"

#define DEFAULT_PATH_WITH_SBIN PATH_SPLIT_BIN("/usr/local/") ":" PATH_SPLIT_BIN("/usr/")
#define DEFAULT_PATH_WITHOUT_SBIN PATH_MERGED_BIN("/usr/local/") ":" PATH_MERGED_BIN("/usr/")

#define DEFAULT_PATH_COMPAT PATH_SPLIT_BIN("/usr/local/") ":" PATH_SPLIT_BIN("/usr/") ":" PATH_SPLIT_BIN("/")

const char* default_PATH(void);

static inline const char* default_user_PATH(void) {
#ifdef DEFAULT_USER_PATH
        return DEFAULT_USER_PATH;
#else
        return default_PATH();
#endif
}

bool is_path(const char *p) _pure_;

static inline bool path_is_absolute(const char *p) {
        if (!p) /* A NULL pointer is definitely not an absolute path */
                return false;

        return p[0] == '/';
}

int path_split_and_make_absolute(const char *p, char ***ret);
char* path_make_absolute(const char *p, const char *prefix);
int safe_getcwd(char **ret);
int path_make_absolute_cwd(const char *p, char **ret);
int path_make_relative(const char *from, const char *to, char **ret);
int path_make_relative_parent(const char *from_child, const char *to, char **ret);

typedef enum PathStartWithFlags {
        PATH_STARTSWITH_REFUSE_DOT_DOT       = 1U << 0,
        PATH_STARTSWITH_RETURN_LEADING_SLASH = 1U << 1,
} PathStartWithFlags;

char* path_startswith_full(const char *path, const char *prefix, PathStartWithFlags flags) _pure_;
static inline char* path_startswith(const char *path, const char *prefix) {
        return path_startswith_full(path, prefix, 0);
}

int path_compare(const char *a, const char *b) _pure_;
static inline bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

int path_compare_filename(const char *a, const char *b);
static inline bool path_equal_filename(const char *a, const char *b) {
        return path_compare_filename(a, b) == 0;
}

int path_equal_or_inode_same_full(const char *a, const char *b, int flags);
static inline bool path_equal_or_inode_same(const char *a, const char *b, int flags) {
        return path_equal_or_inode_same_full(a, b, flags) > 0;
}

char* path_extend_internal(char **x, ...);
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, POINTER_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, POINTER_MAX)

char* skip_leading_slash(const char *p) _pure_;

typedef enum PathSimplifyFlags {
        PATH_SIMPLIFY_KEEP_TRAILING_SLASH = 1 << 0,
} PathSimplifyFlags;

char* path_simplify_full(char *path, PathSimplifyFlags flags);
static inline char* path_simplify(char *path) {
        return path_simplify_full(path, 0);
}

int path_simplify_alloc(const char *path, char **ret);

/* Note: the search terminates on the first NULL item. */
#define PATH_IN_SET(p, ...) path_strv_contains(STRV_MAKE(__VA_ARGS__), p)

char* path_startswith_strv(const char *p, char * const *strv);
#define PATH_STARTSWITH_SET(p, ...) path_startswith_strv(p, STRV_MAKE(__VA_ARGS__))

int path_strv_make_absolute_cwd(char **l);
char** path_strv_resolve(char **l, const char *root);
char** path_strv_resolve_uniq(char **l, const char *root);

int open_and_check_executable(const char *name, const char *root, char **ret_path, int *ret_fd);
int find_executable_full(
                const char *name,
                const char *root,
                char * const *exec_search_path,
                bool use_path_envvar,
                char **ret_filename,
                int *ret_fd);
static inline int find_executable(const char *name, char **ret_filename) {
        return find_executable_full(name, /* root= */ NULL, NULL, true, ret_filename, NULL);
}

bool paths_check_timestamp(const char* const* paths, usec_t *paths_ts_usec, bool update);

int fsck_exists(void);
int fsck_exists_for_fstype(const char *fstype);

/* Iterates through the path prefixes of the specified path, going up
 * the tree, to root. Also returns "" (and not "/"!) for the root
 * directory. Excludes the specified directory itself */
#define PATH_FOREACH_PREFIX(prefix, path)                               \
        for (char *_slash = ({                                          \
                                path_simplify(strcpy(prefix, path));    \
                                streq(prefix, "/") ? NULL : strrchr(prefix, '/'); \
                        });                                             \
             _slash && ((*_slash = 0), true);                           \
             _slash = strrchr((prefix), '/'))

/* Same as PATH_FOREACH_PREFIX but also includes the specified path itself */
#define PATH_FOREACH_PREFIX_MORE(prefix, path)                          \
        for (char *_slash = ({                                          \
                                path_simplify(strcpy(prefix, path));    \
                                if (streq(prefix, "/"))                 \
                                        prefix[0] = 0;                  \
                                strrchr(prefix, 0);                     \
                        });                                             \
             _slash && ((*_slash = 0), true);                           \
             _slash = strrchr((prefix), '/'))

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);
const char* last_path_component(const char *path);
int path_extract_filename(const char *path, char **ret);
int path_extract_directory(const char *path, char **ret);

bool filename_part_is_valid(const char *p) _pure_;
bool filename_is_valid(const char *p) _pure_;
bool path_is_valid_full(const char *p, bool accept_dot_dot) _pure_;
static inline bool path_is_valid(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ true);
}
static inline bool path_is_safe(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ false);
}
bool path_is_normalized(const char *p) _pure_;
static inline bool filename_or_absolute_path_is_valid(const char *p) {
        if (path_is_absolute(p))
                return path_is_valid(p);

        return filename_is_valid(p);
}

int file_in_same_dir(const char *path, const char *filename, char **ret);

bool hidden_or_backup_file(const char *filename) _pure_;

bool is_device_path(const char *path) _pure_;

bool valid_device_node_path(const char *path) _pure_;
bool valid_device_allow_pattern(const char *path) _pure_;

bool dot_or_dot_dot(const char *path) _pure_;

bool path_implies_directory(const char *path) _pure_;

static inline const char* skip_dev_prefix(const char *p) {
        const char *e;

        /* Drop any /dev prefix if there is any */

        e = path_startswith(p, "/dev/");

        return e ?: p;
}

bool empty_or_root(const char *path) _pure_;
const char* empty_to_root(const char *path) _pure_;

bool path_strv_contains(char * const *l, const char *path);
bool prefixed_path_strv_contains(char * const *l, const char *path);

int path_glob_can_match(const char *pattern, const char *prefix, char **ret);

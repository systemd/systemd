/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "architecture.h"

typedef enum PickFlags {
        PICK_ARCHITECTURE = 1 << 0,   /* Look for an architecture suffix */
        PICK_TRIES        = 1 << 1,   /* Look for tries left/tries done counters */
        PICK_RESOLVE      = 1 << 2,   /* Return the fully resolved (chased) path, rather than the path to the entry */
} PickFlags;

typedef struct PickFilter {
        uint32_t type_mask;           /* A mask of 1U << DT_REG, 1U << DT_DIR, … */
        const char *basename;         /* Can be overriden by search pattern */
        const char *version;
        Architecture architecture;
        const char *suffix;           /* Can be overriden by search pattern */
} PickFilter;

typedef struct PickResult {
        char *path;
        int fd; /* O_PATH */
        struct stat st;
        char *version;
        Architecture architecture;
        unsigned tries_left;
        unsigned tries_done;
} PickResult;

#define PICK_RESULT_NULL                                \
        (const PickResult) {                            \
                .fd = -EBADF,                           \
                .st.st_mode = MODE_INVALID,             \
                .architecture = _ARCHITECTURE_INVALID,  \
                .tries_left = UINT_MAX,                 \
                .tries_done = UINT_MAX,                 \
        }

#define TAKE_PICK_RESULT(ptr) TAKE_GENERIC(ptr, PickResult, PICK_RESULT_NULL)

void pick_result_done(PickResult *p);

int path_pick(const char *toplevel_path,
              int toplevel_fd,
              const char *path,
              const PickFilter *filter,
              PickFlags flags,
              PickResult *ret);

int path_pick_update_warn(
                char **path,
                const PickFilter *filter,
                PickFlags flags,
                PickResult *ret);

extern const PickFilter pick_filter_image_raw;
extern const PickFilter pick_filter_image_dir;

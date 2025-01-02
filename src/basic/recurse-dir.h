/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <limits.h>

#include "errno-list.h"
#include "stat-util.h"
#include "macro.h"

typedef enum RecurseDirFlags {
        /* Interpreted by readdir_all() */
        RECURSE_DIR_SORT         = 1 << 0,  /* sort file directory entries before processing them */
        RECURSE_DIR_IGNORE_DOT   = 1 << 1,  /* ignore all dot files ("." and ".." are always ignored) */
        RECURSE_DIR_ENSURE_TYPE  = 1 << 2,  /* guarantees that 'd_type' field of 'de' is not DT_UNKNOWN */

        /* Interpreted by recurse_dir() */
        RECURSE_DIR_SAME_MOUNT   = 1 << 3,  /* skips over subdirectories that are submounts */
        RECURSE_DIR_INODE_FD     = 1 << 4,  /* passes an opened inode fd (O_DIRECTORY fd in case of dirs, O_PATH otherwise) */
        RECURSE_DIR_TOPLEVEL     = 1 << 5,  /* call RECURSE_DIR_ENTER/RECURSE_DIR_LEAVE once for top-level dir, too, with dir_fd=-1 and NULL dirent */
} RecurseDirFlags;

typedef struct DirectoryEntries {
        size_t n_entries;
        struct dirent **entries;
        size_t buffer_size;
        struct dirent buffer[];
} DirectoryEntries;

int readdir_all(int dir_fd, RecurseDirFlags flags, DirectoryEntries **ret);
int readdir_all_at(int fd, const char *path, RecurseDirFlags flags, DirectoryEntries **ret);

typedef enum RecurseDirEvent {
        RECURSE_DIR_ENTER,      /* only for dir inodes */
        RECURSE_DIR_LEAVE,      /* only for dir inodes */
        RECURSE_DIR_ENTRY,      /* only for non-dir inodes */
        RECURSE_DIR_SKIP_MOUNT, /* only for dir inodes: when we don't descent into submounts */
        RECURSE_DIR_SKIP_DEPTH, /* only for dir inodes: when we reached the max depth */

        /* If we hit an error opening/stating an entry, then we'll fire a
         * 'RECURSE_DIR_SKIP_{OPEN_DIR|OPEN_INODE|STAT_INODE}_ERROR_BASE + errno' event. In this case 'de'
         * will be valid, but the statx data NULL and the inode fd -1. */
        RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE,
        RECURSE_DIR_SKIP_OPEN_DIR_ERROR_MAX = RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE + ERRNO_MAX,

        RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE,
        RECURSE_DIR_SKIP_OPEN_INODE_ERROR_MAX = RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE + ERRNO_MAX,

        RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE,
        RECURSE_DIR_SKIP_STAT_INODE_ERROR_MAX = RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE + ERRNO_MAX,

        _RECURSE_DIR_EVENT_MAX,
        _RECURSE_DIR_EVENT_INVALID = -EINVAL,
} RecurseDirEvent;

#define RECURSE_DIR_CONTINUE 0
#define RECURSE_DIR_LEAVE_DIRECTORY INT_MIN
#define RECURSE_DIR_SKIP_ENTRY (INT_MIN+1)

/* Make sure that the negative errno range and these two special returns don't overlap */
assert_cc(RECURSE_DIR_LEAVE_DIRECTORY < -ERRNO_MAX);
assert_cc(RECURSE_DIR_SKIP_ENTRY < -ERRNO_MAX);

/* Prototype for the callback function that is called whenever we enter or leave a dir inode, or find another dir entry. Return values are:
 *
 * RECURSE_DIR_CONTINUE (i.e. 0) → continue with next entry
 * RECURSE_DIR_LEAVE_DIRECTORY   → leave current directory immediately, don't process further siblings
 * RECURSE_DIR_SKIP_ENTRY        → skip this entry otherwise (only makes sense on RECURSE_DIR_ENTER)
 * others                        → terminate iteration entirely, return the specified value (idea is that
 *                                 < 0 indicates errors and > 0 indicates various forms of success)
 */
typedef int (*recurse_dir_func_t)(
                RecurseDirEvent event,
                const char *path,        /* Full non-normalized path, i.e. the path specified during recurise_dir() with what we found appended */
                int dir_fd,              /* fd of the current dir */
                int inode_fd,            /* fd of the current entry in the current dir (O_DIRECTORY if directory, and O_PATH otherwise, but only if RECURSE_DIR_INODE_FD was set) */
                const struct dirent *de, /* directory entry (always valid) */
                const struct statx *sx,  /* statx data (only if statx_mask was non-zero) */
                void *userdata);

int recurse_dir(int dir_fd, const char *path, unsigned statx_mask, unsigned n_depth_max, RecurseDirFlags flags, recurse_dir_func_t func, void *userdata);
int recurse_dir_at(int atfd, const char *path, unsigned statx_mask, unsigned n_depth_max, RecurseDirFlags flags, recurse_dir_func_t func, void *userdata);

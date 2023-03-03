/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "architecture.h"

int path_pick(const char *toplevel_path,
              int toplevel_fd,
              const char *path,
              mode_t search_mode,
              const char *search_basename,
              const char *search_version,
              Architecture search_architecture,
              const char *search_suffix,
              char **ret_inode_path,
              int *ret_inode_fd,
              mode_t *ret_inode_mode,
              char **ret_version,
              Architecture *ret_architecture);

int path_pick_update_warn(
                char **path,
                mode_t search_mode,
                Architecture search_architecture,
                const char *search_suffix,
                Architecture *ret_architecture);

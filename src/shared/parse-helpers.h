/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "list.h"

enum {
        PATH_CHECK_FATAL    = 1 << 0,  /* If not set, then error message is appended with 'ignoring'. */
        PATH_CHECK_ABSOLUTE = 1 << 1,
        PATH_CHECK_RELATIVE = 1 << 2,
};

typedef enum OpenFileFlags {
        OPENFILE_RDONLY         = 1 << 0,
        _OPENFILE_TYPE_MAX,
        _OPENFILE_TYPE_INVALID  = -EINVAL,
} OpenFileFlags;

typedef struct OpenFile {
        char *path;
        char *fdname;
        int flags;
        LIST_FIELDS(struct OpenFile, open_files);
} OpenFile;

int path_simplify_and_warn(
                char *path,
                unsigned flag,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue);

int parse_socket_bind_item(
        const char *str,
        int *address_family,
        int *ip_protocol,
        uint16_t *nr_ports,
        uint16_t *port_min);

int open_file_parse(const char *v, OpenFile **ret);

const char *open_file_to_string(const OpenFile *of);
OpenFile* open_file_free(OpenFile *of);
DEFINE_TRIVIAL_CLEANUP_FUNC(OpenFile*, open_file_free);

#define open_file_free_and_replace(a, b)          \
        free_and_replace_full(a, b, open_file_free)

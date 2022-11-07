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
        OPENFILE_RDONLY         = 0,
        OPENFILE_WRONLY         = 1 << 0,
        OPENFILE_RDWR           = 1 << 1,
} OpenFileFlags;

typedef struct OpenFile {
        char *path;
        char *fdname;
        int flags;
        int fd;
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

int parse_open_file(
        const char *v,
        OpenFile* of);

const char *open_file_to_string(const OpenFile *open_file);
void open_file_free(OpenFile *open_file);

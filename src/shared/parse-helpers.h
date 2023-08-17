/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

enum {
        PATH_CHECK_FATAL    =      1 << 0,  /* If not set, then error message is appended with 'ignoring'. */
        PATH_CHECK_ABSOLUTE =      1 << 1,
        PATH_CHECK_RELATIVE =      1 << 2,
        PATH_KEEP_TRAILING_SLASH = 1 << 3,
};

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

int config_parse_path_or_ignore(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata);

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "macro.h"
#include "strv.h"

char* get_default_hostname(void);
char* gethostname_malloc(void);
char* gethostname_short_malloc(void);
int gethostname_strict(char **ret);

bool valid_ldh_char(char c) _const_;

typedef enum ValidHostnameFlags {
        VALID_HOSTNAME_TRAILING_DOT = 1 << 0,   /* Accept trailing dot on multi-label names */
        VALID_HOSTNAME_DOT_HOST     = 1 << 1,   /* Accept ".host" as valid hostname */
} ValidHostnameFlags;

bool hostname_is_valid(const char *s, ValidHostnameFlags flags) _pure_;
char* hostname_cleanup(char *s);

bool is_localhost(const char *hostname);

static inline bool is_gateway_hostname(const char *hostname) {
        /* This tries to identify the valid syntaxes for the our synthetic "gateway" host. */
        return STRCASE_IN_SET(hostname, "_gateway", "_gateway.");
}

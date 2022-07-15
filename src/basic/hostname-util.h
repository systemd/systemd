/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "macro.h"
#include "strv.h"

typedef enum GetHostnameFlags {
        GET_HOSTNAME_ALLOW_LOCALHOST  = 1 << 0, /* accepts "localhost" or friends. */
        GET_HOSTNAME_FALLBACK_DEFAULT = 1 << 1, /* use default hostname if no hostname is set. */
        GET_HOSTNAME_SHORT            = 1 << 2, /* kills the FQDN part if present. */
} GetHostnameFlags;

int gethostname_full(GetHostnameFlags flags, char **ret);
static inline int gethostname_strict(char **ret) {
        return gethostname_full(0, ret);
}

static inline char* gethostname_malloc(void) {
        char *s;

        if (gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &s) < 0)
                return NULL;

        return s;
}

static inline char* gethostname_short_malloc(void) {
        char *s;

        if (gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT | GET_HOSTNAME_SHORT, &s) < 0)
                return NULL;

        return s;
}

char* get_default_hostname(void);

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

static inline bool is_outbound_hostname(const char *hostname) {
        /* This tries to identify the valid syntaxes for the our synthetic "outbound" host. */
        return STRCASE_IN_SET(hostname, "_outbound", "_outbound.");
}

int get_pretty_hostname(char **ret);

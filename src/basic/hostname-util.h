/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "strv.h"

char* get_default_hostname_raw(void);

bool valid_ldh_char(char c) _const_;

typedef enum ValidHostnameFlags {
        VALID_HOSTNAME_TRAILING_DOT  = 1 << 0,   /* Accept trailing dot on multi-label names */
        VALID_HOSTNAME_DOT_HOST      = 1 << 1,   /* Accept ".host" as valid hostname */
        VALID_HOSTNAME_QUESTION_MARK = 1 << 2,   /* Accept "?" as place holder for hashed machine ID value */
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

static inline bool is_dns_stub_hostname(const char *hostname) {
        return STRCASE_IN_SET(hostname, "_localdnsstub", "_localdnsstub.");
}

static inline bool is_dns_proxy_stub_hostname(const char *hostname) {
        return STRCASE_IN_SET(hostname, "_localdnsproxy", "_localdnsproxy.");
}

const char* etc_hostname(void);
const char* etc_machine_info(void);

int get_pretty_hostname(char **ret);

int machine_spec_valid(const char *s);
int split_user_at_host(const char *s, char **ret_user, char **ret_host);

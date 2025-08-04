/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum HostnameSource {
        HOSTNAME_STATIC,     /* from /etc/hostname */
        HOSTNAME_TRANSIENT,  /* a transient hostname set through systemd, hostnamed, the container manager, or otherwise */
        HOSTNAME_DEFAULT,    /* the os-release default or the compiled-in fallback were used */
        _HOSTNAME_INVALID = -EINVAL,
} HostnameSource;

const char* hostname_source_to_string(HostnameSource source) _const_;
HostnameSource hostname_source_from_string(const char *str) _pure_;

int sethostname_idempotent(const char *s);

int shorten_overlong(const char *s, char **ret);

int read_etc_hostname_stream(FILE *f, bool substitute_wildcards, char **ret);
int read_etc_hostname(const char *path, bool substitute_wildcards, char **ret);

void hostname_update_source_hint(const char *hostname, HostnameSource source);
int hostname_setup(bool really);

int hostname_substitute_wildcards(char *name);

char* get_default_hostname(void);

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

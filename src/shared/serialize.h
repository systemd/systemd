/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "sd-id128.h"

#include "fdset.h"
#include "image-policy.h"
#include "macro.h"
#include "pidref.h"
#include "ratelimit.h"
#include "set.h"
#include "string-util.h"
#include "time-util.h"

int serialize_item(FILE *f, const char *key, const char *value);
int serialize_item_escaped(FILE *f, const char *key, const char *value);
int serialize_item_format(FILE *f, const char *key, const char *value, ...) _printf_(3,4);
int serialize_item_hexmem(FILE *f, const char *key, const void *p, size_t l);
int serialize_item_base64mem(FILE *f, const char *key, const void *p, size_t l);
int serialize_fd(FILE *f, FDSet *fds, const char *key, int fd);
int serialize_fd_many(FILE *f, FDSet *fds, const char *key, const int fd_array[], size_t n_fd_array);
int serialize_usec(FILE *f, const char *key, usec_t usec);
int serialize_dual_timestamp(FILE *f, const char *key, const dual_timestamp *t);
int serialize_strv(FILE *f, const char *key, char * const *l);
int serialize_id128(FILE *f, const char *key, sd_id128_t id);
int serialize_pidref(FILE *f, FDSet *fds, const char *key, PidRef *pidref);
int serialize_ratelimit(FILE *f, const char *key, const RateLimit *rl);
int serialize_string_set(FILE *f, const char *key, const Set *s);
int serialize_image_policy(FILE *f, const char *key, const ImagePolicy *p);

static inline int serialize_bool(FILE *f, const char *key, bool b) {
        return serialize_item(f, key, yes_no(b));
}
static inline int serialize_bool_elide(FILE *f, const char *key, bool b) {
        return b ? serialize_item(f, key, yes_no(b)) : 0;
}

static inline int serialize_item_tristate(FILE *f, const char *key, int value) {
        return value >= 0 ? serialize_item_format(f, key, "%i", value) : 0;
}

int deserialize_read_line(FILE *f, char **ret);

int deserialize_fd(FDSet *fds, const char *value);
int deserialize_fd_many(FDSet *fds, const char *value, size_t n, int *ret);
int deserialize_usec(const char *value, usec_t *ret);
int deserialize_dual_timestamp(const char *value, dual_timestamp *ret);
int deserialize_environment(const char *value, char ***environment);
int deserialize_strv(const char *value, char ***l);
int deserialize_pidref(FDSet *fds, const char *value, PidRef *ret);
void deserialize_ratelimit(RateLimit *rl, const char *name, const char *value);

int open_serialization_fd(const char *ident);
int open_serialization_file(const char *ident, FILE **ret);

int finish_serialization_fd(int fd);
int finish_serialization_file(FILE *f);

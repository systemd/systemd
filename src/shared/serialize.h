/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "fdset.h"
#include "macro.h"
#include "string-util.h"
#include "time-util.h"

int serialize_item(FILE *f, const char *key, const char *value);
int serialize_item_escaped(FILE *f, const char *key, const char *value);
int serialize_item_format(FILE *f, const char *key, const char *value, ...) _printf_(3,4);
int serialize_fd(FILE *f, FDSet *fds, const char *key, int fd);
int serialize_usec(FILE *f, const char *key, usec_t usec);
int serialize_dual_timestamp(FILE *f, const char *key, const dual_timestamp *t);
int serialize_strv(FILE *f, const char *key, char **l);

static inline int serialize_bool(FILE *f, const char *key, bool b) {
        return serialize_item(f, key, yes_no(b));
}

int deserialize_usec(const char *value, usec_t *timestamp);
int deserialize_dual_timestamp(const char *value, dual_timestamp *t);
int deserialize_environment(const char *value, char ***environment);

int open_serialization_fd(const char *ident);

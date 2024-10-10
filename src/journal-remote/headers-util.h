/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "macro.h"
#include "string.h"

bool headers_name_is_valid(const char *e);
bool headers_value_is_valid(const char *e);
bool headers_assignment_is_valid(const char *e);

bool strv_headers_is_valid(char **e);

bool strv_headers_name_is_valid(char **l);
bool strv_headers_name_or_assignment_is_valid(char **l);

char **strv_headers_delete(char **x, size_t n_lists, ...); /* New copy */

char **strv_headers_unset(char **l, const char *p);   /* In place ... */
int strv_headers_replace_consume(char ***l, char *p); /* In place ... */
char *convert_header(char *src);

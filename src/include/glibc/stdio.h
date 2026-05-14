/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <stdio.h>      /* IWYU pragma: export */

/* Route sscanf/fscanf through dlsym shims so we don't pin a particular libc symbol version at
 * link time. glibc 2.38 redirects these to __isoc23_* (binary "0b" prefix in %i conversions);
 * before that they were redirected to __isoc99_* for C99 scanf semantics. We want to keep the
 * C99 semantics and avoid the GLIBC_2.38 dependency, so the shims internally dlsym
 * __isoc99_v{s,f}scanf and forward via a va_list. Skipped on musl. */

int sscanf_shim(const char *str, const char *format, ...) __attribute__((format(scanf, 2, 3)));
int fscanf_shim(FILE *stream, const char *format, ...) __attribute__((format(scanf, 2, 3)));
#define sscanf sscanf_shim
#define fscanf fscanf_shim

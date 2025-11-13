/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <stdio.h>

#if !HAVE_RENAMEAT2
#  define RENAME_NOREPLACE (1 << 0)
#  define RENAME_EXCHANGE  (1 << 1)
#  define RENAME_WHITEOUT  (1 << 2)

int missing_renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned __flags);
#  define renameat2 missing_renameat2
#endif

/* When a stream is opened read-only under glibc, fputs() and friends fail with EBADF. However, they
 * unexpectedly succeed under musl. The following _bugfix() functions first check if the passed stream is
 * writable, and refuse to write with EBADF if not. */

int putc_bugfix(int c, FILE *stream);
int putc_unlocked_bugfix(int c, FILE *stream);
int fputc_bugfix(int c, FILE *stream);
int fputc_unlocked_bugfix(int c, FILE *stream);
int fputs_bugfix(const char *s, FILE *stream);
int fputs_unlocked_bugfix(const char *s, FILE *stream);

#define putc           putc_bugfix
#define putc_unlocked  putc_unlocked_bugfix
#define fputc          fputc_bugfix
#define fputc_unlocked fputc_unlocked_bugfix
#define fputs          fputs_bugfix
#define fputs_unlocked fputs_unlocked_bugfix

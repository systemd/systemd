/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2014 Emil Renner Berthing <systemd@esmil.dk> */
#pragma once

#if HAVE_PRINTF_H
#include_next <printf.h>
#else

#include <features.h>
#include <stddef.h>

enum {        /* C type: */
  PA_INT,     /* int */
  PA_CHAR,    /* int, cast to char */
  PA_WCHAR,   /* wide char */
  PA_STRING,  /* const char *, a '\0'-terminated string */
  PA_WSTRING, /* const wchar_t *, wide character string */
  PA_POINTER, /* void * */
  PA_FLOAT,   /* float */
  PA_DOUBLE,  /* double */
  PA_LAST,
};

/* Flag bits that can be set in a type returned by `parse_printf_format'.  */
#define PA_FLAG_MASK        0xff00
#define PA_FLAG_LONG_LONG   (1 << 8)
#define PA_FLAG_LONG_DOUBLE PA_FLAG_LONG_LONG
#define PA_FLAG_LONG        (1 << 9)
#define PA_FLAG_SHORT       (1 << 10)
#define PA_FLAG_PTR         (1 << 11)

size_t parse_printf_format(const char *fmt, size_t n, int *types);

#endif /* HAVE_PRINTF_H */

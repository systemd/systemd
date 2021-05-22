/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2014 Emil Renner Berthing <systemd@esmil.dk> */
#pragma once

#include <features.h>
#include <stddef.h>

#ifdef __GLIBC__
#include_next <printf.h>
#else

enum {              /* C type: */
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
#  define PA_FLAG_MASK        0xff00
#  define PA_FLAG_LONG_LONG   (1 << 8)
#  define PA_FLAG_LONG_DOUBLE PA_FLAG_LONG_LONG
#  define PA_FLAG_LONG        (1 << 9)
#  define PA_FLAG_SHORT       (1 << 10)
#  define PA_FLAG_PTR         (1 << 11)

#  define parse_printf_format missing_parse_printf_format
#endif

size_t missing_parse_printf_format(const char *fmt, size_t n, int *types);

/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <printf.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

#define snprintf_ok(buf, len, fmt, ...) \
        ((size_t) snprintf(buf, len, fmt, __VA_ARGS__) < (len))

#define xsprintf(buf, fmt, ...) \
        assert_message_se(snprintf_ok(buf, ELEMENTSOF(buf), fmt, __VA_ARGS__), "xsprintf: " #buf "[] must be big enough")

#define VA_FORMAT_ADVANCE(format, ap)                                   \
do {                                                                    \
        int _argtypes[128];                                             \
        size_t _i, _k;                                                  \
        _k = parse_printf_format((format), ELEMENTSOF(_argtypes), _argtypes); \
        assert(_k < ELEMENTSOF(_argtypes));                             \
        for (_i = 0; _i < _k; _i++) {                                   \
                if (_argtypes[_i] & PA_FLAG_PTR)  {                     \
                        (void) va_arg(ap, void*);                       \
                        continue;                                       \
                }                                                       \
                                                                        \
                switch (_argtypes[_i]) {                                \
                case PA_INT:                                            \
                case PA_INT|PA_FLAG_SHORT:                              \
                case PA_CHAR:                                           \
                        (void) va_arg(ap, int);                         \
                        break;                                          \
                case PA_INT|PA_FLAG_LONG:                               \
                        (void) va_arg(ap, long int);                    \
                        break;                                          \
                case PA_INT|PA_FLAG_LONG_LONG:                          \
                        (void) va_arg(ap, long long int);               \
                        break;                                          \
                case PA_WCHAR:                                          \
                        (void) va_arg(ap, wchar_t);                     \
                        break;                                          \
                case PA_WSTRING:                                        \
                case PA_STRING:                                         \
                case PA_POINTER:                                        \
                        (void) va_arg(ap, void*);                       \
                        break;                                          \
                case PA_FLOAT:                                          \
                case PA_DOUBLE:                                         \
                        (void) va_arg(ap, double);                      \
                        break;                                          \
                case PA_DOUBLE|PA_FLAG_LONG_DOUBLE:                     \
                        (void) va_arg(ap, long double);                 \
                        break;                                          \
                default:                                                \
                        assert_not_reached("Unknown format string argument."); \
                }                                                       \
        }                                                               \
} while (false)

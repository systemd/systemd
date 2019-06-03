/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stddef.h>

#include "macro.h"

size_t strnpcpy(char **dest, size_t size, const char *src, size_t len);
size_t strpcpy(char **dest, size_t size, const char *src);
size_t strpcpyf(char **dest, size_t size, const char *src, ...) _printf_(3, 4);
size_t strpcpyl(char **dest, size_t size, const char *src, ...) _sentinel_;
size_t strnscpy(char *dest, size_t size, const char *src, size_t len);
size_t strscpy(char *dest, size_t size, const char *src);
size_t strscpyl(char *dest, size_t size, const char *src, ...) _sentinel_;

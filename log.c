/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

void log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        const char *prefix, *suffix;
        va_list ap;

        if (LOG_PRI(level) <= LOG_ERR) {
                prefix = "\x1B[1;31m";
                suffix = "\x1B[0m";
        } else {
                prefix = "";
                suffix = "";
        }

        va_start(ap, format);

        fprintf(stderr, "(%s:%u) %s", file, line, prefix);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "%s\n", suffix);

        va_end(ap);

}

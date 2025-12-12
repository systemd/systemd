/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cleanup-util.h"

/* Argument list for parsers of specific configuration settings. */
#define CONFIG_PARSER_ARGUMENTS                 \
        const char *unit,                       \
        const char *filename,                   \
        unsigned line,                          \
        const char *section,                    \
        unsigned section_line,                  \
        const char *lvalue,                     \
        int ltype,                              \
        const char *rvalue,                     \
        void *data,                             \
        void *userdata

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(CONFIG_PARSER_ARGUMENTS);

/* A macro declaring a function prototype, following the typedef above, simply because it's so cumbersomely long
 * otherwise. (And current emacs gets irritatingly slow when editing files that contain lots of very long function
 * prototypes on the same screen…) */
#define CONFIG_PARSER_PROTOTYPE(name) int name(CONFIG_PARSER_ARGUMENTS)

typedef struct ConfigSection {
        unsigned line;
        bool invalid;
        char filename[];
} ConfigSection;

#define DEFINE_SECTION_CLEANUP_FUNCTIONS(type, free_func)               \
        static inline type* free_func##_or_set_invalid(type *p) {       \
                assert(p);                                              \
                                                                        \
                if (p->section)                                         \
                        p->section->invalid = true;                     \
                else                                                    \
                        free_func(p);                                   \
                return NULL;                                            \
        }                                                               \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func);                  \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func##_or_set_invalid);

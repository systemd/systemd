/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "path-lookup.h"

typedef struct EditFile {
        char *path;
        char *original_path;
        char **comment_paths;
        char *temp;
        unsigned line;
} EditFile;

typedef struct EditFileContext {
        EditFile *files;
        size_t n_files;
        const char *marker_start;
        const char *marker_end;
} EditFileContext;

#define _EDIT_FILE_FOREACH(s, e, i)                                     \
        for (typeof(*(e)) *s, *i = (e); (s = i) && i->path; i++)

#define EDIT_FILE_FOREACH(s, e)                                         \
        _EDIT_FILE_FOREACH(s, e, UNIQ_T(i, UNIQ))

#define EDIT_FILE_CONTAINS(s, e)                                        \
        ({                                                              \
                bool _found = false;                                    \
                EDIT_FILE_FOREACH(_i, e)                                \
                        if (streq(s, _i->path)) {                       \
                                _found = true;                          \
                                break;                                  \
                        }                                               \
                _found;                                                 \
        })

void edit_file_context_done(EditFileContext *context);

int edit_files_add(
                EditFileContext *context,
                const char *path,
                const char *original_path,
                char * const *comment_paths);

int do_edit_files_and_install(EditFileContext *context);

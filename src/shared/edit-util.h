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

#define _EDIT_FILES_FOREACH(s, c, i)                                    \
        for (size_t i = 0, EditFile *s = c.files; i < c.n_files; s += i++)

#define EDIT_FILES_FOREACH(s, c)                                        \
        _EDIT_FILES_FOREACH(s, c, UNIQ_T(i, UNIQ))

void edit_file_context_done(EditFileContext *context);

bool edit_files_contains(EditFileContext *context, const char *path);

int edit_files_add(
                EditFileContext *context,
                const char *path,
                const char *original_path,
                char * const *comment_paths);

int do_edit_files_and_install(EditFileContext *context);

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
} EditFileContext;

#define _EDIT_FILE_FOREACH(s, e, i)                                     \
        for (typeof(*(e)) *s, *i = (e); (s = i) && i->path; i++)

#define EDIT_FILE_FOREACH(s, e)                                         \
        _EDIT_FILE_FOREACH(s, e, UNIQ_T(i, UNIQ))

void edit_file_free_all(EditFile **ef);
void edit_file_free_and_unlink_all(EditFile **ef);
void edit_file_context_done(EditFileContext *context);

int create_edit_temp_file(
                const char *target_path,
                const char *original_path,
                char * const *comment_paths,
                const char *marker_start,
                const char *marker_end,
                char **ret_temp_filename,
                unsigned *ret_edit_line);

int edit_files_add(
                EditFileContext *context,
                const char *path,
                const char *original_path,
                char * const *comment_paths);

int run_editor(const EditFileContext *context);
int trim_edit_markers(const char *path, const char *marker_start, const char *marker_end);

int do_edit_files_and_install(
                EditFileContext *context,
                const char *marker_start,
                const char *marker_end);

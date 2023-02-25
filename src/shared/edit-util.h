/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "path-lookup.h"

typedef struct EditFile {
        char *path;
        char *tmp;
        unsigned line;
} EditFile;

void edit_file_free_all(EditFile **ef);

int create_edit_temp_file(
                const char *new_path,
                const char *original_path,
                char ** const original_unit_paths,
                const char *marker_start,
                const char *marker_end,
                char **ret_tmp_fn,
                unsigned *ret_edit_line);

int run_editor(const EditFile *files);

int trim_edit_markers(const char *path, const char *marker_start, const char *marker_end);

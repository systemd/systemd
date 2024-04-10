/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "macro.h"

typedef enum OpenFileFlag {
        OPENFILE_READ_ONLY = 1 << 0,
        OPENFILE_APPEND    = 1 << 1,
        OPENFILE_TRUNCATE  = 1 << 2,
        OPENFILE_GRACEFUL  = 1 << 3,
        _OPENFILE_MAX,
        _OPENFILE_INVALID  = -EINVAL,
        _OPENFILE_MASK_PUBLIC = OPENFILE_READ_ONLY | OPENFILE_APPEND | OPENFILE_TRUNCATE | OPENFILE_GRACEFUL,
} OpenFileFlag;

typedef struct OpenFile {
        char *path;
        char *fdname;
        OpenFileFlag flags;
        LIST_FIELDS(struct OpenFile, open_files);
} OpenFile;

int open_file_parse(const char *v, OpenFile **ret);

int open_file_validate(const OpenFile *of);

int open_file_to_string(const OpenFile *of, char **ret);

OpenFile* open_file_free(OpenFile *of);
DEFINE_TRIVIAL_CLEANUP_FUNC(OpenFile*, open_file_free);

static inline void open_file_free_many(OpenFile **head) {
        LIST_CLEAR(open_files, *ASSERT_PTR(head), open_file_free);
}

const char* open_file_flags_to_string(OpenFileFlag t) _const_;
OpenFileFlag open_file_flags_from_string(const char *t) _pure_;

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "macro.h"

typedef struct FileDescriptor {
        int fd;
        char *fdname;
        LIST_FIELDS(struct FileDescriptor, fds);
} FileDescriptor;

int file_descriptor_parse(const char *v, FileDescriptor **ret);

int file_descriptor_validate(const FileDescriptor *fd);

int file_descriptor_to_string(const FileDescriptor *fd, char **ret);

FileDescriptor* file_descriptor_free(FileDescriptor *fd);
DEFINE_TRIVIAL_CLEANUP_FUNC(FileDescriptor*, file_descriptor_free);

static inline void file_descriptor_free_many(FileDescriptor **head) {
        LIST_CLEAR(fds, *ASSERT_PTR(head), file_descriptor_free);
}

FileDescriptor* file_descriptor_free_and_close(FileDescriptor *fd);

static inline void file_descriptor_free_and_close_many(FileDescriptor **head) {
        LIST_CLEAR(fds, *ASSERT_PTR(head), file_descriptor_free_and_close);
}

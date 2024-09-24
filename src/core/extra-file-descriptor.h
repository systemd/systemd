/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "macro.h"

typedef struct ExtraFileDescriptor {
        int fd;
        char *fdname;
        LIST_FIELDS(struct ExtraFileDescriptor, fds);
} ExtraFileDescriptor;

int extra_file_descriptor_parse(const char *v, ExtraFileDescriptor **ret);

int extra_file_descriptor_validate(const ExtraFileDescriptor *fd);

int extra_file_descriptor_to_string(const ExtraFileDescriptor *fd, char **ret);

ExtraFileDescriptor* extra_file_descriptor_free(ExtraFileDescriptor *fd);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExtraFileDescriptor*, extra_file_descriptor_free);

static inline void extra_file_descriptor_free_many(ExtraFileDescriptor **head) {
        LIST_CLEAR(fds, *ASSERT_PTR(head), extra_file_descriptor_free);
}

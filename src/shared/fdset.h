/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"
#include "set.h"

typedef struct FDSet FDSet;

FDSet* fdset_new(void);
FDSet* fdset_free(FDSet *s);

int fdset_put(FDSet *s, int fd);
int fdset_put_dup(FDSet *s, int fd);

bool fdset_contains(FDSet *s, int fd);
int fdset_remove(FDSet *s, int fd);

int fdset_new_array(FDSet **ret, const int *fds, size_t n_fds);
int fdset_new_fill(FDSet **ret);
int fdset_new_listen_fds(FDSet **ret, bool unset);

int fdset_cloexec(FDSet *fds, bool b);

int fdset_close_others(FDSet *fds);

unsigned fdset_size(FDSet *fds);
bool fdset_isempty(FDSet *fds);

int fdset_iterate(FDSet *s, Iterator *i);

int fdset_steal_first(FDSet *fds);

void fdset_close(FDSet *fds);

#define FDSET_FOREACH(fd, fds, i) \
        for ((i) = ITERATOR_FIRST, (fd) = fdset_iterate((fds), &(i)); (fd) >= 0; (fd) = fdset_iterate((fds), &(i)))

DEFINE_TRIVIAL_CLEANUP_FUNC(FDSet*, fdset_free);
#define _cleanup_fdset_free_ _cleanup_(fdset_freep)

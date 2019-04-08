/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"

typedef struct Prioq Prioq;

#define PRIOQ_IDX_NULL ((unsigned) -1)

Prioq *prioq_new(compare_func_t compare);
Prioq *prioq_free(Prioq *q);
DEFINE_TRIVIAL_CLEANUP_FUNC(Prioq*, prioq_free);
int prioq_ensure_allocated(Prioq **q, compare_func_t compare_func);

int prioq_put(Prioq *q, void *data, unsigned *idx);
int prioq_remove(Prioq *q, void *data, unsigned *idx);
int prioq_reshuffle(Prioq *q, void *data, unsigned *idx);

void *prioq_peek_by_index(Prioq *q, unsigned idx) _pure_;
static inline void *prioq_peek(Prioq *q) {
        return prioq_peek_by_index(q, 0);
}
void *prioq_pop(Prioq *q);

#define PRIOQ_FOREACH_ITEM(q, p)                                \
        for (unsigned _i = 0; (p = prioq_peek_by_index(q, _i)); _i++)

unsigned prioq_size(Prioq *q) _pure_;
bool prioq_isempty(Prioq *q) _pure_;

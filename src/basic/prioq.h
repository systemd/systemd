/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"

typedef struct Prioq Prioq;

#define PRIOQ_IDX_NULL ((unsigned) -1)

Prioq *prioq_new(compare_func_t compare);
Prioq *prioq_free(Prioq *q);
int prioq_ensure_allocated(Prioq **q, compare_func_t compare_func);

int prioq_put(Prioq *q, void *data, unsigned *idx);
int prioq_remove(Prioq *q, void *data, unsigned *idx);
int prioq_reshuffle(Prioq *q, void *data, unsigned *idx);

void *prioq_peek(Prioq *q) _pure_;
void *prioq_pop(Prioq *q);

unsigned prioq_size(Prioq *q) _pure_;
bool prioq_isempty(Prioq *q) _pure_;

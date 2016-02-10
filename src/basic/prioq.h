#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

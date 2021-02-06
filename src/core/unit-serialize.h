/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "unit.h"
#include "fdset.h"

int unit_serialize(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs);
int unit_deserialize(Unit *u, FILE *f, FDSet *fds);
int unit_deserialize_skip(FILE *f);

void unit_dump(Unit *u, FILE *f, const char *prefix);

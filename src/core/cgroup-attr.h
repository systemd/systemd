/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

typedef struct CGroupAttribute CGroupAttribute;

#include "unit.h"
#include "cgroup.h"
#include "cgroup-semantics.h"

struct CGroupAttribute {
        char *controller;
        char *name;
        char *value;

        Unit *unit;

        const CGroupSemantics *semantics;

        LIST_FIELDS(CGroupAttribute, by_unit);
};

int cgroup_attribute_apply(CGroupAttribute *a, CGroupBonding *b);
int cgroup_attribute_apply_list(CGroupAttribute *first, CGroupBonding *b);

bool cgroup_attribute_matches(CGroupAttribute *a, const char *controller, const char *name) _pure_;
CGroupAttribute *cgroup_attribute_find_list(CGroupAttribute *first, const char *controller, const char *name) _pure_;

void cgroup_attribute_free(CGroupAttribute *a);
void cgroup_attribute_free_list(CGroupAttribute *first);
void cgroup_attribute_free_some(CGroupAttribute *first, const char *controller, const char *name);

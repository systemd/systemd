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

typedef struct CGroupSemantics CGroupSemantics;

struct CGroupSemantics {
        const char *controller;
        const char *name;
        const char *pretty;

        bool multiple;

        /* This call is used for parsing the pretty value to the actual attribute value */
        int (*map_pretty)(const CGroupSemantics *semantics, const char *value, char **ret);

        /* Right before writing this attribute the attribute value is converted to a low-level value */
        int (*map_write)(const CGroupSemantics *semantics, const char *value, char **ret);

        /* If this attribute takes a list, this call can be used to reset the list to empty */
        int (*reset)(const CGroupSemantics *semantics, const char *group);
};

int cgroup_semantics_find(const char *controller, const char *name, const char *value, char **ret, const CGroupSemantics **semantics);

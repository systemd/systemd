/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Link Link;
typedef struct Manager Manager;

void link_dirty(Link *link);
void link_clean(Link *link);
int link_save(Link *link);
int link_save_and_clean(Link *link);

int manager_save(Manager *m);

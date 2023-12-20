/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Link Link;
typedef struct Manager Manager;

void link_dirty(Link *link);
void link_clean(Link *link);
int link_save_and_clean_full(Link *link, bool also_save_manager);
static inline int link_save_and_clean(Link *link) {
        return link_save_and_clean_full(link, false);
}

int manager_save(Manager *m);
int manager_clean_all(Manager *manager);

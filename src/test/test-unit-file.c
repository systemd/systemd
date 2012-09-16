/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "install.h"
#include "util.h"
#include "macro.h"
#include "hashmap.h"

int main(int argc, char *argv[]) {

        int r;
        Hashmap *h;
        Iterator i;
        UnitFileList *p;

        h = hashmap_new(string_hash_func, string_compare_func);
        assert(h);

        r = unit_file_get_list(UNIT_FILE_SYSTEM, NULL, h);
        log_info("unit_file_get_list: %s", strerror(-r));
        assert(r >= 0);

        HASHMAP_FOREACH(p, h, i)
                printf("%s = %s\n", p->path, unit_file_state_to_string(p->state));

        unit_file_list_free(h);

        return 0;
}

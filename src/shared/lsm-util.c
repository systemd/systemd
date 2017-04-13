/***
  This file is part of systemd.

  Copyright 2017 Djalal Harouni

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

#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "lsm-util.h"
#include "fileio.h"
#include "string-util.h"

bool is_lsm_loaded(const char *lsm_name) {
        _cleanup_free_ char *lsms = NULL;
        const char *word, *state;
        size_t l, z;
        int r;

        assert(lsm_name);

        r = read_one_line_file("/sys/kernel/security/lsm", &lsms);
        if (r < 0)
                return false;

        z = strlen(lsm_name);
        FOREACH_WORD_SEPARATOR(word, l, lsms, ",", state)
                if (l == z && streq(word, lsm_name))
                        return true;

        return false;
}

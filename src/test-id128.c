/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "sd-id128.h"
#include "util.h"
#include "macro.h"

#define ID128_WALDI SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10)

int main(int argc, char *argv[]) {
        sd_id128_t id, id2;
        char t[33];

        assert_se(sd_id128_randomize(&id) == 0);
        printf("random: %s\n", sd_id128_to_string(id, t));

        assert_se(sd_id128_from_string(t, &id2) == 0);
        assert_se(sd_id128_equal(id, id2));

        assert_se(sd_id128_get_machine(&id) == 0);
        printf("machine: %s\n", sd_id128_to_string(id, t));

        assert_se(sd_id128_get_boot(&id) == 0);
        printf("boot: %s\n", sd_id128_to_string(id, t));

        printf("waldi: %s\n", sd_id128_to_string(ID128_WALDI, t));

        printf("waldi2: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(ID128_WALDI));

        return 0;
}

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

#include <locale.h>

#include "util.h"
#include "log.h"
#include "catalog.h"
#include "sd-messages.h"

int main(int argc, char *argv[]) {

        _cleanup_free_ char *text = NULL;

        setlocale(LC_ALL, "de_DE.UTF-8");

        log_set_max_level(LOG_DEBUG);

        assert_se(catalog_update() >= 0);

        assert_se(catalog_list(stdout) >= 0);

        assert_se(catalog_get(SD_MESSAGE_COREDUMP, &text) >= 0);

        printf(">>>%s<<<\n", text);

        fflush(stdout);

        return 0;
}

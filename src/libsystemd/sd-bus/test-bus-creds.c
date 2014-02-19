/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "sd-bus.h"
#include "bus-dump.h"
#include "bus-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        int r;

        r = sd_bus_creds_new_from_pid(&creds, 0, _SD_BUS_CREDS_ALL);
        assert_se(r >= 0);

        bus_creds_dump(creds, NULL);

        creds = sd_bus_creds_unref(creds);

        r = sd_bus_creds_new_from_pid(&creds, 1, _SD_BUS_CREDS_ALL);
        if (r != -EACCES) {
                assert_se(r >= 0);
                putchar('\n');
                bus_creds_dump(creds, NULL);
        }

        return 0;
}

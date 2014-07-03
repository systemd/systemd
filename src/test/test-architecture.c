/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers

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

#include "virt.h"
#include "architecture.h"
#include "util.h"
#include "log.h"

int main(int argc, char *argv[]) {
        Architecture a;
        int v;
        const char *id = NULL;

        v = detect_virtualization(&id);
        if (v == -EPERM || v == -EACCES)
                return EXIT_TEST_SKIP;

        assert_se(v >= 0);

        log_info("virtualization=%s id=%s",
                 v == VIRTUALIZATION_CONTAINER ? "container" : v == VIRTUALIZATION_VM ? "vm" : "n/a",
                 strna(id));

        a = uname_architecture();
        assert_se(a >= 0);

        log_info("uname architecture=%s", architecture_to_string(a));

        a = native_architecture();
        assert_se(a >= 0);

        log_info("native architecture=%s", architecture_to_string(a));

        log_info("primary library architecture=" LIB_ARCH_TUPLE);

        return 0;
}

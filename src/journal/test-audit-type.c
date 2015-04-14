/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Zbigniew Jędrzejewski-Szmek

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

#include <stdio.h>
#include <linux/audit.h>

#include "audit-type.h"

static void print_audit_label(int i) {
        const char *name;

        name = audit_type_name_alloca(i);
        /* This is a separate function only because of alloca */
        printf("%i → %s → %s\n", i, audit_type_to_string(i), name);
}

static void test_audit_type(void) {
        int i;

        for (i = 0; i <= AUDIT_KERNEL; i++)
                print_audit_label(i);
}

int main(int argc, char **argv) {
        test_audit_type();
}

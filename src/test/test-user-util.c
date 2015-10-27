/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "alloc-util.h"
#include "macro.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

static void test_uid_to_name_one(uid_t uid, const char *name) {
        _cleanup_free_ char *t = NULL;

        assert_se(t = uid_to_name(uid));
        assert_se(streq_ptr(t, name));
}

static void test_gid_to_name_one(gid_t gid, const char *name) {
        _cleanup_free_ char *t = NULL;

        assert_se(t = gid_to_name(gid));
        assert_se(streq_ptr(t, name));
}

int main(int argc, char*argv[]) {

        test_uid_to_name_one(0, "root");
        test_uid_to_name_one(0xFFFF, "65535");
        test_uid_to_name_one(0xFFFFFFFF, "4294967295");

        test_gid_to_name_one(0, "root");
        test_gid_to_name_one(TTY_GID, "tty");
        test_gid_to_name_one(0xFFFF, "65535");
        test_gid_to_name_one(0xFFFFFFFF, "4294967295");

        return 0;
}

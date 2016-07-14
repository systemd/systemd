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

static void test_parse_uid(void) {
        int r;
        uid_t uid;

        r = parse_uid("100", &uid);
        assert_se(r == 0);
        assert_se(uid == 100);

        r = parse_uid("65535", &uid);
        assert_se(r == -ENXIO);

        r = parse_uid("asdsdas", &uid);
        assert_se(r == -EINVAL);
}

static void test_uid_ptr(void) {

        assert_se(UID_TO_PTR(0) != NULL);
        assert_se(UID_TO_PTR(1000) != NULL);

        assert_se(PTR_TO_UID(UID_TO_PTR(0)) == 0);
        assert_se(PTR_TO_UID(UID_TO_PTR(1000)) == 1000);
}

static void test_valid_user_group_name(void) {
        assert_se(!valid_user_group_name(NULL));
        assert_se(!valid_user_group_name(""));
        assert_se(!valid_user_group_name("1"));
        assert_se(!valid_user_group_name("65535"));
        assert_se(!valid_user_group_name("-1"));
        assert_se(!valid_user_group_name("-kkk"));
        assert_se(!valid_user_group_name("rööt"));
        assert_se(!valid_user_group_name("."));
        assert_se(!valid_user_group_name("eff.eff"));
        assert_se(!valid_user_group_name("foo\nbar"));
        assert_se(!valid_user_group_name("0123456789012345678901234567890123456789"));
        assert_se(!valid_user_group_name_or_id("aaa:bbb"));

        assert_se(valid_user_group_name("root"));
        assert_se(valid_user_group_name("lennart"));
        assert_se(valid_user_group_name("LENNART"));
        assert_se(valid_user_group_name("_kkk"));
        assert_se(valid_user_group_name("kkk-"));
        assert_se(valid_user_group_name("kk-k"));

        assert_se(valid_user_group_name("some5"));
        assert_se(!valid_user_group_name("5some"));
        assert_se(valid_user_group_name("INNER5NUMBER"));
}

static void test_valid_user_group_name_or_id(void) {
        assert_se(!valid_user_group_name_or_id(NULL));
        assert_se(!valid_user_group_name_or_id(""));
        assert_se(valid_user_group_name_or_id("0"));
        assert_se(valid_user_group_name_or_id("1"));
        assert_se(valid_user_group_name_or_id("65534"));
        assert_se(!valid_user_group_name_or_id("65535"));
        assert_se(valid_user_group_name_or_id("65536"));
        assert_se(!valid_user_group_name_or_id("-1"));
        assert_se(!valid_user_group_name_or_id("-kkk"));
        assert_se(!valid_user_group_name_or_id("rööt"));
        assert_se(!valid_user_group_name_or_id("."));
        assert_se(!valid_user_group_name_or_id("eff.eff"));
        assert_se(!valid_user_group_name_or_id("foo\nbar"));
        assert_se(!valid_user_group_name_or_id("0123456789012345678901234567890123456789"));
        assert_se(!valid_user_group_name_or_id("aaa:bbb"));

        assert_se(valid_user_group_name_or_id("root"));
        assert_se(valid_user_group_name_or_id("lennart"));
        assert_se(valid_user_group_name_or_id("LENNART"));
        assert_se(valid_user_group_name_or_id("_kkk"));
        assert_se(valid_user_group_name_or_id("kkk-"));
        assert_se(valid_user_group_name_or_id("kk-k"));

        assert_se(valid_user_group_name_or_id("some5"));
        assert_se(!valid_user_group_name_or_id("5some"));
        assert_se(valid_user_group_name_or_id("INNER5NUMBER"));
}

static void test_valid_gecos(void) {

        assert_se(!valid_gecos(NULL));
        assert_se(valid_gecos(""));
        assert_se(valid_gecos("test"));
        assert_se(valid_gecos("Ümläüt"));
        assert_se(!valid_gecos("In\nvalid"));
        assert_se(!valid_gecos("In:valid"));
}

static void test_valid_home(void) {

        assert_se(!valid_home(NULL));
        assert_se(!valid_home(""));
        assert_se(!valid_home("."));
        assert_se(!valid_home("/home/.."));
        assert_se(!valid_home("/home/../"));
        assert_se(!valid_home("/home\n/foo"));
        assert_se(!valid_home("./piep"));
        assert_se(!valid_home("piep"));
        assert_se(!valid_home("/home/user:lennart"));

        assert_se(valid_home("/"));
        assert_se(valid_home("/home"));
        assert_se(valid_home("/home/foo"));
}

int main(int argc, char*argv[]) {

        test_uid_to_name_one(0, "root");
        test_uid_to_name_one(0xFFFF, "65535");
        test_uid_to_name_one(0xFFFFFFFF, "4294967295");

        test_gid_to_name_one(0, "root");
        test_gid_to_name_one(TTY_GID, "tty");
        test_gid_to_name_one(0xFFFF, "65535");
        test_gid_to_name_one(0xFFFFFFFF, "4294967295");

        test_parse_uid();
        test_uid_ptr();

        test_valid_user_group_name();
        test_valid_user_group_name_or_id();
        test_valid_gecos();
        test_valid_home();

        return 0;
}

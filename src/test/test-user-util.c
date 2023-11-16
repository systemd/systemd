/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "format-util.h"
#include "libcrypt-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "user-util.h"

static void test_uid_to_name_one(uid_t uid, const char *name) {
        _cleanup_free_ char *t = NULL;

        log_info("/* %s("UID_FMT", \"%s\") */", __func__, uid, name);

        assert_se(t = uid_to_name(uid));
        if (!synthesize_nobody() && streq(name, NOBODY_USER_NAME)) {
                log_info("(skipping detailed tests because nobody is not synthesized)");
                return;
        }
        assert_se(streq_ptr(t, name));
}

TEST(uid_to_name) {
        test_uid_to_name_one(0, "root");
        test_uid_to_name_one(UID_NOBODY, NOBODY_USER_NAME);
        test_uid_to_name_one(0xFFFF, "65535");
        test_uid_to_name_one(0xFFFFFFFF, "4294967295");
}

static void test_gid_to_name_one(gid_t gid, const char *name) {
        _cleanup_free_ char *t = NULL;

        log_info("/* %s("GID_FMT", \"%s\") */", __func__, gid, name);

        assert_se(t = gid_to_name(gid));
        if (!synthesize_nobody() && streq(name, NOBODY_GROUP_NAME)) {
                log_info("(skipping detailed tests because nobody is not synthesized)");
                return;
        }
        assert_se(streq_ptr(t, name));
}

TEST(gid_to_name) {
        test_gid_to_name_one(0, "root");
        test_gid_to_name_one(GID_NOBODY, NOBODY_GROUP_NAME);
        test_gid_to_name_one(0xFFFF, "65535");
        test_gid_to_name_one(0xFFFFFFFF, "4294967295");
}

TEST(parse_uid) {
        int r;
        uid_t uid;

        r = parse_uid("0", &uid);
        assert_se(r == 0);
        assert_se(uid == 0);

        r = parse_uid("1", &uid);
        assert_se(r == 0);
        assert_se(uid == 1);

        r = parse_uid("01", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 1);

        r = parse_uid("001", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 1);

        r = parse_uid("100", &uid);
        assert_se(r == 0);
        assert_se(uid == 100);

        r = parse_uid("65535", &uid);
        assert_se(r == -ENXIO);
        assert_se(uid == 100);

        r = parse_uid("0x1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("0o1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("0b1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("+1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("-1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid(" 1234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("01234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("001234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("0001234", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("-0", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("+0", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("00", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("000", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);

        r = parse_uid("asdsdas", &uid);
        assert_se(r == -EINVAL);
        assert_se(uid == 100);
}

TEST(uid_ptr) {
        assert_se(UID_TO_PTR(0) != NULL);
        assert_se(UID_TO_PTR(1000) != NULL);

        assert_se(PTR_TO_UID(UID_TO_PTR(0)) == 0);
        assert_se(PTR_TO_UID(UID_TO_PTR(1000)) == 1000);
}

TEST(valid_user_group_name_relaxed) {
        assert_se(!valid_user_group_name(NULL, VALID_USER_RELAX));
        assert_se(!valid_user_group_name("", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("1", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("65535", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("-1", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("foo\nbar", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("0123456789012345678901234567890123456789", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("aaa:bbb", VALID_USER_RELAX|VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name(".aaa:bbb", VALID_USER_RELAX|VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name(".", VALID_USER_RELAX));
        assert_se(!valid_user_group_name("..", VALID_USER_RELAX));

        assert_se(valid_user_group_name("root", VALID_USER_RELAX));
        assert_se(valid_user_group_name("lennart", VALID_USER_RELAX));
        assert_se(valid_user_group_name("LENNART", VALID_USER_RELAX));
        assert_se(valid_user_group_name("_kkk", VALID_USER_RELAX));
        assert_se(valid_user_group_name("kkk-", VALID_USER_RELAX));
        assert_se(valid_user_group_name("kk-k", VALID_USER_RELAX));
        assert_se(valid_user_group_name("eff.eff", VALID_USER_RELAX));
        assert_se(valid_user_group_name("eff.", VALID_USER_RELAX));
        assert_se(valid_user_group_name("-kkk", VALID_USER_RELAX));
        assert_se(valid_user_group_name("rööt", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".eff", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".1", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".65535", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".-1", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".-kkk", VALID_USER_RELAX));
        assert_se(valid_user_group_name(".rööt", VALID_USER_RELAX));
        assert_se(valid_user_group_name("...", VALID_USER_RELAX));

        assert_se(valid_user_group_name("some5", VALID_USER_RELAX));
        assert_se(valid_user_group_name("5some", VALID_USER_RELAX));
        assert_se(valid_user_group_name("INNER5NUMBER", VALID_USER_RELAX));

        assert_se(valid_user_group_name("piff.paff@ad.domain.example", VALID_USER_RELAX));
        assert_se(valid_user_group_name("Dāvis", VALID_USER_RELAX));
}

TEST(valid_user_group_name) {
        assert_se(!valid_user_group_name(NULL, 0));
        assert_se(!valid_user_group_name("", 0));
        assert_se(!valid_user_group_name("1", 0));
        assert_se(!valid_user_group_name("65535", 0));
        assert_se(!valid_user_group_name("-1", 0));
        assert_se(!valid_user_group_name("-kkk", 0));
        assert_se(!valid_user_group_name("rööt", 0));
        assert_se(!valid_user_group_name(".", 0));
        assert_se(!valid_user_group_name(".eff", 0));
        assert_se(!valid_user_group_name("foo\nbar", 0));
        assert_se(!valid_user_group_name("0123456789012345678901234567890123456789", 0));
        assert_se(!valid_user_group_name("aaa:bbb", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name(".", 0));
        assert_se(!valid_user_group_name("..", 0));
        assert_se(!valid_user_group_name("...", 0));
        assert_se(!valid_user_group_name(".1", 0));
        assert_se(!valid_user_group_name(".65535", 0));
        assert_se(!valid_user_group_name(".-1", 0));
        assert_se(!valid_user_group_name(".-kkk", 0));
        assert_se(!valid_user_group_name(".rööt", 0));
        assert_se(!valid_user_group_name(".aaa:bbb", VALID_USER_ALLOW_NUMERIC));

        assert_se(valid_user_group_name("root", 0));
        assert_se(valid_user_group_name("lennart", 0));
        assert_se(valid_user_group_name("LENNART", 0));
        assert_se(valid_user_group_name("_kkk", 0));
        assert_se(valid_user_group_name("kkk-", 0));
        assert_se(valid_user_group_name("kk-k", 0));
        assert_se(!valid_user_group_name("eff.eff", 0));
        assert_se(!valid_user_group_name("eff.", 0));

        assert_se(valid_user_group_name("some5", 0));
        assert_se(!valid_user_group_name("5some", 0));
        assert_se(valid_user_group_name("INNER5NUMBER", 0));

        assert_se(!valid_user_group_name("piff.paff@ad.domain.example", 0));
        assert_se(!valid_user_group_name("Dāvis", 0));
}

TEST(valid_user_group_name_or_numeric_relaxed) {
        assert_se(!valid_user_group_name(NULL, VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("0", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("1", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("65534", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("65535", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("65536", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("-1", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("foo\nbar", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("0123456789012345678901234567890123456789", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("aaa:bbb", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name(".", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(!valid_user_group_name("..", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));

        assert_se(valid_user_group_name("root", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("lennart", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("LENNART", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("_kkk", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("kkk-", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("kk-k", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("-kkk", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("rööt", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name(".eff", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("eff.eff", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("eff.", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("...", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));

        assert_se(valid_user_group_name("some5", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("5some", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("INNER5NUMBER", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));

        assert_se(valid_user_group_name("piff.paff@ad.domain.example", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
        assert_se(valid_user_group_name("Dāvis", VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX));
}

TEST(valid_user_group_name_or_numeric) {
        assert_se(!valid_user_group_name(NULL, VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("0", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("1", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("65534", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("65535", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("65536", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("-1", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("-kkk", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("rööt", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name(".", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("..", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("...", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name(".eff", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("eff.eff", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("eff.", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("foo\nbar", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("0123456789012345678901234567890123456789", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("aaa:bbb", VALID_USER_ALLOW_NUMERIC));

        assert_se(valid_user_group_name("root", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("lennart", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("LENNART", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("_kkk", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("kkk-", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("kk-k", VALID_USER_ALLOW_NUMERIC));

        assert_se(valid_user_group_name("some5", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("5some", VALID_USER_ALLOW_NUMERIC));
        assert_se(valid_user_group_name("INNER5NUMBER", VALID_USER_ALLOW_NUMERIC));

        assert_se(!valid_user_group_name("piff.paff@ad.domain.example", VALID_USER_ALLOW_NUMERIC));
        assert_se(!valid_user_group_name("Dāvis", VALID_USER_ALLOW_NUMERIC));
}

TEST(valid_gecos) {
        assert_se(!valid_gecos(NULL));
        assert_se(valid_gecos(""));
        assert_se(valid_gecos("test"));
        assert_se(valid_gecos("Ümläüt"));
        assert_se(!valid_gecos("In\nvalid"));
        assert_se(!valid_gecos("In:valid"));
}

TEST(valid_home) {
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

static void test_get_user_creds_one(const char *id, const char *name, uid_t uid, gid_t gid, const char *home, const char *shell) {
        const char *rhome = NULL;
        const char *rshell = NULL;
        uid_t ruid = UID_INVALID;
        gid_t rgid = GID_INVALID;
        int r;

        log_info("/* %s(\"%s\", \"%s\", "UID_FMT", "GID_FMT", \"%s\", \"%s\") */",
                 __func__, id, name, uid, gid, home, shell);

        r = get_user_creds(&id, &ruid, &rgid, &rhome, &rshell, 0);
        log_info_errno(r, "got \"%s\", "UID_FMT", "GID_FMT", \"%s\", \"%s\": %m",
                       id, ruid, rgid, strnull(rhome), strnull(rshell));
        if (!synthesize_nobody() && streq(name, NOBODY_USER_NAME)) {
                log_info("(skipping detailed tests because nobody is not synthesized)");
                return;
        }
        assert_se(r == 0);
        assert_se(streq_ptr(id, name));
        assert_se(ruid == uid);
        assert_se(rgid == gid);
        assert_se(path_equal(rhome, home));
}

TEST(get_user_creds) {
        test_get_user_creds_one("root", "root", 0, 0, "/root", DEFAULT_USER_SHELL);
        test_get_user_creds_one("0", "root", 0, 0, "/root", DEFAULT_USER_SHELL);
        test_get_user_creds_one(NOBODY_USER_NAME, NOBODY_USER_NAME, UID_NOBODY, GID_NOBODY, "/", NOLOGIN);
        test_get_user_creds_one("65534", NOBODY_USER_NAME, UID_NOBODY, GID_NOBODY, "/", NOLOGIN);
}

static void test_get_group_creds_one(const char *id, const char *name, gid_t gid) {
        gid_t rgid = GID_INVALID;
        int r;

        log_info("/* %s(\"%s\", \"%s\", "GID_FMT") */", __func__, id, name, gid);

        r = get_group_creds(&id, &rgid, 0);
        log_info_errno(r, "got \"%s\", "GID_FMT": %m", id, rgid);
        if (!synthesize_nobody() && streq(name, NOBODY_GROUP_NAME)) {
                log_info("(skipping detailed tests because nobody is not synthesized)");
                return;
        }
        assert_se(r == 0);
        assert_se(streq_ptr(id, name));
        assert_se(rgid == gid);
}

TEST(get_group_creds) {
        test_get_group_creds_one("root", "root", 0);
        test_get_group_creds_one("0", "root", 0);
        test_get_group_creds_one(NOBODY_GROUP_NAME, NOBODY_GROUP_NAME, GID_NOBODY);
        test_get_group_creds_one("65534", NOBODY_GROUP_NAME, GID_NOBODY);
}

TEST(make_salt) {
        _cleanup_free_ char *s, *t;

        assert_se(make_salt(&s) == 0);
        log_info("got %s", s);

        assert_se(make_salt(&t) == 0);
        log_info("got %s", t);

        assert_se(!streq(s, t));
}

TEST(in_gid) {
        assert_se(in_gid(getgid()) >= 0);
        assert_se(in_gid(getegid()) >= 0);
        assert_se(in_gid(GID_INVALID) < 0);
        assert_se(in_gid(TTY_GID) == 0); /* The TTY gid is for owning ttys, it would be really really weird if we were in it. */
}

TEST(gid_lists_ops) {
        static const gid_t l1[] = { 5, 10, 15, 20, 25};
        static const gid_t l2[] = { 1, 2, 3, 15, 20, 25};
        static const gid_t l3[] = { 5, 10, 15, 20, 25, 26, 27};
        static const gid_t l4[] = { 25, 26, 20, 15, 5, 27, 10};

        static const gid_t result1[] = {1, 2, 3, 5, 10, 15, 20, 25, 26, 27};
        static const gid_t result2[] = {5, 10, 15, 20, 25, 26, 27};

        _cleanup_free_ gid_t *gids = NULL;
        _cleanup_free_ gid_t *res1 = NULL;
        _cleanup_free_ gid_t *res2 = NULL;
        _cleanup_free_ gid_t *res3 = NULL;
        _cleanup_free_ gid_t *res4 = NULL;
        int nresult;

        nresult = merge_gid_lists(l2, ELEMENTSOF(l2), l3, ELEMENTSOF(l3), &res1);
        assert_se(nresult >= 0);
        assert_se(memcmp_nn(res1, nresult, result1, ELEMENTSOF(result1)) == 0);

        nresult = merge_gid_lists(NULL, 0, l2, ELEMENTSOF(l2), &res2);
        assert_se(nresult >= 0);
        assert_se(memcmp_nn(res2, nresult, l2, ELEMENTSOF(l2)) == 0);

        nresult = merge_gid_lists(l1, ELEMENTSOF(l1), l1, ELEMENTSOF(l1), &res3);
        assert_se(nresult >= 0);
        assert_se(memcmp_nn(l1, ELEMENTSOF(l1), res3, nresult) == 0);

        nresult = merge_gid_lists(l1, ELEMENTSOF(l1), l4, ELEMENTSOF(l4), &res4);
        assert_se(nresult >= 0);
        assert_se(memcmp_nn(result2, ELEMENTSOF(result2), res4, nresult) == 0);

        nresult = getgroups_alloc(&gids);
        assert_se(nresult >= 0 || nresult == -EINVAL || nresult == -ENOMEM);
        assert_se(gids);
}

TEST(parse_uid_range) {
        uid_t a = 4711, b = 4711;

        assert_se(parse_uid_range("", &a, &b) == -EINVAL && a == 4711 && b == 4711);
        assert_se(parse_uid_range(" ", &a, &b) == -EINVAL && a == 4711 && b == 4711);
        assert_se(parse_uid_range("x", &a, &b) == -EINVAL && a == 4711 && b == 4711);

        assert_se(parse_uid_range("0", &a, &b) >= 0 && a == 0 && b == 0);
        assert_se(parse_uid_range("1", &a, &b) >= 0 && a == 1 && b == 1);
        assert_se(parse_uid_range("2-2", &a, &b) >= 0 && a == 2 && b == 2);
        assert_se(parse_uid_range("3-3", &a, &b) >= 0 && a == 3 && b == 3);
        assert_se(parse_uid_range("4-5", &a, &b) >= 0 && a == 4 && b == 5);

        assert_se(parse_uid_range("7-6", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("-1", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("01", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("001", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("+1", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1--1", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range(" 1", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range(" 1-2", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1 -2", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1- 2", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1-2 ", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("01-2", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1-02", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("001-2", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range("1-002", &a, &b) == -EINVAL && a == 4 && b == 5);
        assert_se(parse_uid_range(" 01", &a, &b) == -EINVAL && a == 4 && b == 5);
}

static void test_mangle_gecos_one(const char *input, const char *expected) {
        _cleanup_free_ char *p = NULL;

        assert_se(p = mangle_gecos(input));
        assert_se(streq(p, expected));
        assert_se(valid_gecos(p));
}

TEST(mangle_gecos) {
        test_mangle_gecos_one("", "");
        test_mangle_gecos_one("root", "root");
        test_mangle_gecos_one("wuff\nwuff", "wuff wuff");
        test_mangle_gecos_one("wuff:wuff", "wuff wuff");
        test_mangle_gecos_one("wuff\r\n:wuff", "wuff   wuff");
        test_mangle_gecos_one("\n--wüff-wäff-wöff::", " --wüff-wäff-wöff  ");
        test_mangle_gecos_one("\xc3\x28", " (");
        test_mangle_gecos_one("\xe2\x28\xa1", " ( ");
}

DEFINE_TEST_MAIN(LOG_INFO);

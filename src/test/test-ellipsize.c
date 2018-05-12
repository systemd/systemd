/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2013 Shawn Landden
***/

#include <stdio.h>

#include "alloc-util.h"
#include "def.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"

static void test_one(const char *p) {
        _cleanup_free_ char *t;
        t = ellipsize(p, columns(), 70);
        puts(t);
        free(t);
        t = ellipsize(p, columns(), 0);
        puts(t);
        free(t);
        t = ellipsize(p, columns(), 100);
        puts(t);
        free(t);
        t = ellipsize(p, 0, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 1, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 2, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 3, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 4, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 5, 50);
        puts(t);
}

int main(int argc, char *argv[]) {
        test_one(DIGITS LETTERS DIGITS LETTERS);
        test_one("한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어");
        test_one("-日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国");
        test_one("中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国-中国中国中国中国中国中国中国中国中国中国中国中国中国");
        test_one("sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd");
        test_one("🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮");
        test_one("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
        test_one("shórt");

        return 0;
}

/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Shawn Landden

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

#include "util.h"
#include "terminal-util.h"
#include "def.h"

static void test_one(const char *p) {
        _cleanup_free_ char *t;
        t = ellipsize(p, columns(), 70);
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

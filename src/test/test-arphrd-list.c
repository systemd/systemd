/***
  This file is part of systemd

  Copyright 2015 Daniel Mack

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

#include <net/if_arp.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"
#include "util.h"

static const struct arphrd_name* lookup_arphrd(register const char *str, register unsigned int len);

#include "arphrd-from-name.h"
#include "arphrd-list.h"
#include "arphrd-to-name.h"

int main(int argc, const char *argv[]) {

        unsigned int i;

        for (i = 1; i < ELEMENTSOF(arphrd_names); i++) {
                if (arphrd_names[i]) {
                        assert_se(streq(arphrd_to_name(i), arphrd_names[i]));
                        assert_se(arphrd_from_name(arphrd_names[i]) == (int) i);
                }
        }

        assert_se(arphrd_to_name(arphrd_max()) == NULL);
        assert_se(arphrd_to_name(0) == NULL);
        assert_se(arphrd_from_name("huddlduddl") == 0);

        return 0;
}

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

#include <string.h>
#include <sys/socket.h>

#include "macro.h"
#include "string-util.h"
#include "util.h"

static const struct af_name* lookup_af(register const char *str, register unsigned int len);

#include "af-from-name.h"
#include "af-list.h"
#include "af-to-name.h"

int main(int argc, const char *argv[]) {

        unsigned int i;

        for (i = 0; i < ELEMENTSOF(af_names); i++) {
                if (af_names[i]) {
                        assert_se(streq(af_to_name(i), af_names[i]));
                        assert_se(af_from_name(af_names[i]) == (int) i);
                }
        }

        assert_se(af_to_name(af_max()) == NULL);
        assert_se(af_to_name(-1) == NULL);
        assert_se(af_from_name("huddlduddl") == AF_UNSPEC);

        return 0;
}

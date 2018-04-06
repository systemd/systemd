/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering
***/

#include "sd-utf8.h"

#include "utf8.h"
#include "util.h"

_public_ const char *sd_utf8_is_valid(const char *s) {
        assert_return(s, NULL);

        return utf8_is_valid(s);
}

_public_ const char *sd_ascii_is_valid(const char *s) {
        assert_return(s, NULL);

        return ascii_is_valid(s);
}

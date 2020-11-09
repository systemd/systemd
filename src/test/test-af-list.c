/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "macro.h"
#include "string-util.h"
#include "util.h"

_unused_
static const struct af_name* lookup_af(register const char *str, register GPERF_LEN_TYPE len);

#include "af-from-name.h"
#include "af-list.h"
#include "af-to-name.h"

int main(int argc, const char *argv[]) {

        unsigned i;

        for (i = 0; i < ELEMENTSOF(af_names); i++) {
                if (af_names[i]) {
                        assert_se(streq(af_to_name(i), af_names[i]));
                        assert_se(af_from_name(af_names[i]) == (int) i);
                }
        }

        assert_se(af_to_name(af_max()) == NULL);
        assert_se(af_to_name(-1) == NULL);
        assert_se(af_from_name("huddlduddl") == -EINVAL);
        assert_se(af_from_name("") == -EINVAL);

        return 0;
}

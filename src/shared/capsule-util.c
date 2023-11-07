/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "capsule-util.h"
#include "path-util.h"
#include "user-util.h"

int capsule_name_is_valid(const char *name) {

        if (!filename_is_valid(name))
                return false;

        _cleanup_free_ char *prefixed = strjoin("c-", name);
        if (!prefixed)
                return -ENOMEM;

        return valid_user_group_name(prefixed, /* flags= */ 0);
}

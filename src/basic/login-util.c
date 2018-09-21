/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

#include "login-util.h"
#include "string-util.h"

bool session_id_valid(const char *id) {

        if (isempty(id))
                return false;

        return id[strspn(id, LETTERS DIGITS)] == '\0';
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-has-tpm2.h"
#include "tpm2-util.h"

int verb_has_tpm2(int argc, char **argv, void *userdata) {
        return verb_has_tpm2_generic(arg_quiet);
}

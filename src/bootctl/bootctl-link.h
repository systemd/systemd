/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int verb_link(int argc, char *argv[], uintptr_t data, void *userdata);

int vl_method_link(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

static bool entry_commit_valid(uint64_t commit) {
        return commit > 0 && commit < UINT64_MAX;
}

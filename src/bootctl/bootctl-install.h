/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int verb_install(int argc, char *argv[], void *userdata);
int verb_remove(int argc, char *argv[], void *userdata);
int verb_is_installed(int argc, char *argv[], void *userdata);

int vl_method_install(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

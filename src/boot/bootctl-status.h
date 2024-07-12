/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

int verb_status(int argc, char *argv[], void *userdata);
int verb_list(int argc, char *argv[], void *userdata);
int verb_unlink(int argc, char *argv[], void *userdata);

int vl_method_list_boot_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

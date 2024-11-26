/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

int verb_reboot_to_firmware(int argc, char *argv[], void *userdata);

int vl_method_set_reboot_to_firmware(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_get_reboot_to_firmware(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

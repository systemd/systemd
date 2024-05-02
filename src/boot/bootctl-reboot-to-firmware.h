/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink.h"

int verb_reboot_to_firmware(int argc, char *argv[], void *userdata);

int vl_method_set_reboot_to_firmware(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);
int vl_method_get_reboot_to_firmware(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#define VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE               "io.systemd.MachineImage.NoSuchImage"
#define VARLINK_ERROR_MACHINE_IMAGE_TOO_MANY_OPERATIONS         "io.systemd.MachineImage.TooManyOperations"
#define VARLINK_ERROR_MACHINE_IMAGE_NOT_SUPPORTED               "io.systemd.MachineImage.NotSupported"

int vl_method_update_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_clone_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_remove_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_set_pool_limit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

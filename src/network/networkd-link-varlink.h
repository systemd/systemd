/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int dispatch_interface(sd_varlink *vlink, sd_json_variant *parameters, Manager *manager, bool polkit, Link **ret);

int vl_method_link_up(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_link_down(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

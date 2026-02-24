/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

typedef enum DispatchLinkFlag {
        DISPATCH_LINK_POLKIT    = 1 << 0,
        DISPATCH_LINK_MANDATORY = 1 << 1,
} DispatchLinkFlag;

int dispatch_link(sd_varlink *vlink, sd_json_variant *parameters, Manager *manager, DispatchLinkFlag flags, Link **ret);

int vl_method_link_up(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_link_down(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

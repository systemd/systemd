/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "varlink.h"
#include "varlink-idl.h"

extern const VarlinkInterface vl_interface_io_systemd_service;

int varlink_method_ping(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);
int varlink_method_set_log_level(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);

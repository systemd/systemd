/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

#include "forward.h"
#include "udev-def.h"

int find_device(const char *id, const char *prefix, sd_device **ret);
int find_device_with_action(const char *id, sd_device_action_t action, sd_device **ret);
int parse_device_action(const char *str, sd_device_action_t *ret);
int parse_resolve_name_timing(const char *str, ResolveNameTiming *ret);
int parse_key_value_argument(const char *str, bool require_value, char **key, char **value);
int udev_ping(usec_t timeout, bool ignore_connection_failure);
int search_rules_files(char * const *a, const char *root, ConfFile ***ret_files, size_t *ret_n_files);

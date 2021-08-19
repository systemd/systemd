/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef enum DevlinkKind {
        _DEVLINK_KIND_MAX,
        _DEVLINK_KIND_INVALID = -EINVAL,
} DevlinkKind;

const char *devlink_kind_to_string(DevlinkKind d) _const_;
DevlinkKind devlink_kind_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_kind);

/* gperf */
const struct ConfigPerfItem* devlink_kind_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

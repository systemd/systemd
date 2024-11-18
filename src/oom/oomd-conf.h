/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "oomd-manager.h"

int manager_set_defaults(Manager *m);

int manager_parse_config_file(Manager *m);

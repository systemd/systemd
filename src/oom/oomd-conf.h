/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

void manager_set_defaults(Manager *m);

void manager_parse_config_file(Manager *m);

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

int context_installdb_record(Context *c, const char *path, char **patterns);

int installdb_cleanup_component(const char *node, const char *component);
int installdb_list_components(char ***ret);

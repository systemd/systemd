/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "sd-varlink.h"

#include "fdset.h"

int varlink_server_serialize(sd_varlink_server *s, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds);

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "imds-util.h"

/* Helpers shared between imds-tool.c and imds-tool-metrics.c for talking to systemd-imdsd. */

int connect_imdsd(sd_varlink **ret);
int acquire_imds_key_as_string(sd_varlink *link, ImdsWellKnown wk, const char *key, char **ret);
int acquire_imds_vendor(sd_varlink *link, char **ret);

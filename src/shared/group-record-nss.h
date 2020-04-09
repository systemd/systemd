/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <grp.h>
#include <gshadow.h>

#include "group-record.h"

/* Synthesize GroupRecord objects from NSS data */

int nss_group_to_group_record(const struct group *grp, const struct sgrp *sgrp, GroupRecord **ret);
int nss_sgrp_for_group(const struct group *grp, struct sgrp *ret_sgrp, char **ret_buffer);

int nss_group_record_by_name(const char *name, bool with_shadow, GroupRecord **ret);
int nss_group_record_by_gid(gid_t gid, bool with_shadow, GroupRecord **ret);

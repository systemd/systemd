/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-util.h"
#include "shared-forward.h"
#include "vmspawn-qmp.h"

/* Empty/NULL defaults to virtio-blk; otherwise delegates to disk_type_from_string(). */
DiskType disk_type_from_bind_volume_config(const char *config);

/* Acquires the volume and builds a DriveInfo with id="<provider>:<volume>" (the
 * bridge-visible name; QMP-side names are still allocated by add_block_device). */
int vmspawn_bind_volume_acquire(
                RuntimeScope scope,
                const BindVolume *v,
                bool removable,
                sd_varlink *link,
                DriveInfo **ret,
                char **reterr_error_id);

int vmspawn_bind_volume_prepare_boot(
                RuntimeScope scope,
                BindVolume **items,
                size_t n_items,
                DriveInfos *drives);

/* Takes ownership of fd unconditionally. */
int vmspawn_bind_volume_attach_fd(
                VmspawnQmpBridge *bridge,
                sd_varlink *link,
                int fd,
                const char *name,
                const char *config);

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Builds a new CPIO archive containing each credential as a
 * file under .extra/credentials/<id>.cred, writes it to a
 * freshly-created temp file, and returns the path in *ret_path.
 * Caller takes ownership and is responsible for unlink()+free().
 * If creds contains no credentials, no file will be created and
 * *ret_path is set to NULL. */
int initrd_cpio_credentials_to_tempfile(
                const MachineCredentialContext *creds,
                char **ret_path);

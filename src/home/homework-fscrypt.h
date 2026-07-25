/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework-forward.h"

int home_setup_fscrypt(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, const PasswordCache *cache);

int home_create_fscrypt(UserRecord *h, HomeSetup *setup, char **effective_passwords, UserRecord **ret_home);

int home_passwd_fscrypt(UserRecord *h, HomeSetup *setup, const PasswordCache *cache, char **effective_passwords);

int home_flush_keyring_fscrypt(UserRecord *h);

/* Fire the pending v2 master-key rollback (remove the key from the filesystem keyring) if armed; called
 * from home_setup_done() on every teardown/error path. No-op if unarmed or v1. */
void fscrypt_v2_key_undo_done(FscryptV2KeyUndo *u);
/* Cancel a pending v2 rollback without removing the key: the home is staying active and now owns it. */
void fscrypt_v2_key_undo_disarm(FscryptV2KeyUndo *u);

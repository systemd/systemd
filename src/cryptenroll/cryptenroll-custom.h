/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptsetup-util.h"
#include "varlink.h"

int enroll_slot_and_token(struct crypt_device *cd,
                          void *volume_key,
                          size_t volume_key_size,
                          const char *passpharse,
                          size_t passphrase_size,
                          JsonVariant *token);

int enroll_slot_and_tokenb(struct crypt_device *cd,
                           void *volume_key,
                           size_t volume_key_size,
                           const char *passpharse,
                           size_t passphrase_size,
                           ...);

int vl_method_enroll_custom(Varlink *link,
                            JsonVariant *params,
                            VarlinkMethodFlags flags,
                            void *userdata);

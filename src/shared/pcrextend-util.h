/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"

int pcrextend_machine_id_word(char **ret);
int pcrextend_product_id_word(char **ret);
int pcrextend_verity_word(const char *name, const struct iovec *root_hash, const struct iovec *root_hash_sig, char **ret);
int pcrextend_imds_userdata_word(const struct iovec *data, char **ret);
int pcrextend_login_word(UserRecord *ur, char **ret);

int pcrextend_verity_now(const char *name, const struct iovec *root_hash, const struct iovec *root_hash_sig);
int pcrextend_imds_userdata_now(const struct iovec *data);

int pcrextend_volume_key_now(unsigned pcr, const char *word, const struct iovec *volume_key);
int pcrextend_keyslot_now(const char *nvpcr, const char *word);

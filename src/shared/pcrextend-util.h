/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int pcrextend_file_system_word(const char *path, char **ret, char **ret_normalized_path);
int pcrextend_machine_id_word(char **ret);
int pcrextend_product_id_word(char **ret);
int pcrextend_verity_word(const char *name, const struct iovec *root_hash, const struct iovec *root_hash_sig, char **ret);

int pcrextend_verity_now(const char *name, const struct iovec *root_hash,const struct iovec *root_hash_sig);

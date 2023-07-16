/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int pcrextend_file_system_word(const char *path, char **ret, char **ret_normalized_path);
int pcrextend_machine_id_word(char **ret);

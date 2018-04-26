/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
  Copyright 2010-2012 Kay Sievers
***/

enum {
        CONF_FILES_EXECUTABLE = 1,
};

int conf_files_list(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dir, ...);
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, unsigned flags, const char* const* dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dirs);
int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path);
int conf_files_insert_nulstr(char ***strv, const char *root, const char *dirs, const char *path);
int conf_files_cat(const char *name);

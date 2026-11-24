/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int manager_setup_directory_reports(Manager *m);
int exec_report_directory(const ExecParameters *p, ExecDirectoryType type, const char *path, const char *symlink_path);
int unit_add_owned_directory(Unit *u, ExecDirectoryType type, const char *path);
void unit_prune_owned_directories(Unit *u);

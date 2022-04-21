/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

/* This needs to be after sys/mount.h */
#include <libmount.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct libmnt_table*, mnt_free_table, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct libmnt_iter*, mnt_free_iter, NULL);

int libmount_drain(struct libmnt_monitor *monitor);

int libmount_parse(const char *path, FILE *source, struct libmnt_table **ret_table,
                   struct libmnt_iter **ret_iter);

/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#ifndef LIB_DMTARGETS_H
#define LIB_DMTARGETS_H

#include <inttypes.h>

struct dm_ioctl;
struct dm_ioctl_v1;

struct target {
	uint64_t start;
	uint64_t length;
	char *type;
	char *params;

	struct target *next;
};

struct dm_task {
	int type;
	char *dev_name;

	struct target *head, *tail;

	int read_only;
	uint32_t event_nr;
	int major;
	int minor;
	union {
		struct dm_ioctl *v4;
		struct dm_ioctl_v1 *v1;
	} dmi;
	char *newname;

	char *uuid;
};

struct cmd_data {
	const char *name;
	const int cmd;
	const int version[3];
};

int dm_check_version(void);

#endif

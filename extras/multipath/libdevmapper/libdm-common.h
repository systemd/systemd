/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#ifndef LIB_DMCOMMON_H
#define LIB_DMCOMMON_H

#include "libdevmapper.h"

#define _LOG_DEBUG 7
#define _LOG_INFO 6
#define _LOG_NOTICE 5
#define _LOG_WARN 4
#define _LOG_ERR 3
#define _LOG_FATAL 2

extern dm_log_fn _log;

#define log_error(msg, x...) _log(_LOG_ERR, __FILE__, __LINE__, msg, ## x)
#define log_print(msg, x...) _log(_LOG_WARN, __FILE__, __LINE__, msg, ## x)
#define log_verbose(msg, x...) _log(_LOG_NOTICE, __FILE__, __LINE__, msg, ## x)
#define log_very_verbose(msg, x...) _log(_LOG_INFO, __FILE__, __LINE__, msg, ## x)
#define log_debug(msg, x...) _log(_LOG_DEBUG, __FILE__, __LINE__, msg, ## x)

struct target *create_target(uint64_t start,
			     uint64_t len,
			     const char *type, const char *params);

int add_dev_node(const char *dev_name, uint32_t minor, uint32_t major);
int rm_dev_node(const char *dev_name);
int rename_dev_node(const char *old_name, const char *new_name);
void update_devs(void);

#define DM_LIB_VERSION "1.00.07-ioctl (2003-11-21)"

#endif

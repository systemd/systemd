/*
 * volume_id_logging - this file is used to map the dbg() function
 *                     to the user's logging facility
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _VOLUME_ID_LOGGING_H_
#define _VOLUME_ID_LOGGING_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* just use the udev version */
#include "../../../logging.h"

#endif /* _VOLUME_ID_LOGGING_H_ */

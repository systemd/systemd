/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) Andre Masella <andre@masella.no-ip.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _VOLUME_ID_OCFS2_
#define _VOLUME_ID_OCFS2_

extern int volume_id_probe_ocfs2(struct volume_id *id, uint64_t off);

#endif

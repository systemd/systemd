/*
 * dasdlabel - read label from s390 block device
 *
 * Copyright (C) 2004 Arnd Bergmann <arnd@arndb.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _VOLUME_ID_DASDLABEL_
#define _VOLUME_ID_DASDLABEL_

extern int volume_id_probe_dasd_partition(struct volume_id *id);

#endif

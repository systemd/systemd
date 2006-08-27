/*
 * Copyright (C) 2004 Daniel Walsh
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#ifndef _UDEV_SELINUX_H
#define _UDEV_SELINUX_H

#ifdef USE_SELINUX

extern void selinux_setfilecon(const char *file, const char *devname, unsigned int mode);
extern void selinux_setfscreatecon(const char *file, const char *devname, unsigned int mode);
extern void selinux_resetfscreatecon(void);
extern void selinux_init(void);
extern void selinux_exit(void);

#else

static inline void selinux_setfilecon(const char *file, const char *devname, unsigned int mode) {}
static inline void selinux_setfscreatecon(const char *file, const char *devname, unsigned int mode) {}
static inline void selinux_resetfscreatecon(void) {}
static inline void selinux_init(void) {}
static inline void selinux_exit(void) {}

#endif /* USE_SELINUX */
#endif /* _UDEV_USE_SELINUX */

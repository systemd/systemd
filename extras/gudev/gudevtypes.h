/* -*- Mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2008 David Zeuthen <davidz@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#if !defined (_GUDEV_COMPILATION) && !defined(_GUDEV_INSIDE_GUDEV_H)
#error "Only <gudev/gudev.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __G_UDEV_TYPES_H__
#define __G_UDEV_TYPES_H__

#include <gudev/gudevenums.h>
#include <sys/types.h>

G_BEGIN_DECLS

typedef struct _GUdevClient GUdevClient;
typedef struct _GUdevDevice GUdevDevice;

/**
 * GUdevDeviceNumber:
 *
 * Corresponds to the standard #dev_t type as defined by POSIX (Until
 * bug 584517 is resolved this work-around is needed).
 */
#ifdef _GUDEV_WORK_AROUND_DEV_T_BUG
typedef guint64 GUdevDeviceNumber; /* __UQUAD_TYPE */
#else
typedef dev_t GUdevDeviceNumber;
#endif

G_END_DECLS

#endif /* __G_UDEV_TYPES_H__ */

/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Copyright © 2012 Harald Hoyer <harald@redhat.com>
 */

#ifndef __SDBOOT_SPLASH_H
#define __SDBOOT_SPLASH_H

EFI_STATUS graphics_splash(UINT8 *content, UINTN len, const EFI_GRAPHICS_OUTPUT_BLT_PIXEL *background);
#endif

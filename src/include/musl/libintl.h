/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* On musl-based systems, libintl.h may be provided by GNU gettext even though musl itself provides
 * dgettext(). Declare dgettext() directly to avoid an unnecessary dependency on libintl.so. */

char* dgettext(const char *domainname, const char *msgid) __attribute__((format_arg(2)));

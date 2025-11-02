/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef SBAT_DISTRO
#  include "version.h"
#  define SBAT_MAGIC "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
#  define SBAT_BOOT_SECTION_TEXT \
        SBAT_MAGIC \
        SBAT_PROJECT "-boot" ",1,The systemd Developers," SBAT_PROJECT "," PROJECT_VERSION "," PROJECT_URL "\n" \
        SBAT_PROJECT "-boot" "." SBAT_DISTRO "," STRINGIFY(SBAT_DISTRO_GENERATION) "," SBAT_DISTRO_SUMMARY "," SBAT_DISTRO_PKGNAME "," SBAT_DISTRO_VERSION "," SBAT_DISTRO_URL "\n"
#  define SBAT_STUB_SECTION_TEXT \
        SBAT_MAGIC \
        SBAT_PROJECT "-stub" ",1,The systemd Developers," SBAT_PROJECT "," PROJECT_VERSION "," PROJECT_URL "\n" \
        SBAT_PROJECT "-stub" "." SBAT_DISTRO "," STRINGIFY(SBAT_DISTRO_GENERATION) "," SBAT_DISTRO_SUMMARY "," SBAT_DISTRO_PKGNAME "," SBAT_DISTRO_VERSION "," SBAT_DISTRO_URL "\n"
#endif

#ifdef SBAT_DISTRO
#  define DECLARE_SBAT(text) DECLARE_NOALLOC_SECTION(".sbat", text)
#  define DECLARE_SBAT_PADDED(text) DECLARE_NOALLOC_SECTION_PADDED(".sbat", text)
#else
#  define DECLARE_SBAT(text)
#  define DECLARE_SBAT_PADDED(text)
#endif

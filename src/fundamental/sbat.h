/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef SBAT_DISTRO
#  define SBAT_SECTION_TEXT \
        "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n" \
        SBAT_PROJECT ",1,The systemd Developers," SBAT_PROJECT "," PROJECT_VERSION "," PROJECT_URL "\n" \
        SBAT_PROJECT "." SBAT_DISTRO "," STRINGIFY(SBAT_DISTRO_GENERATION) "," SBAT_DISTRO_SUMMARY "," SBAT_DISTRO_PKGNAME "," SBAT_DISTRO_VERSION "," SBAT_DISTRO_URL "\n"
#endif

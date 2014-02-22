/***
  This file is part of systemd, but is heavily based on
  glibc's libc-symbols.h.

  Copyright (C) 1995-1998,2000-2006,2008,2009 Free Software Foundation, Inc

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#define __make_section_unallocated(section_string)      \
  asm (".section " section_string "\n\t.previous");

#define __sec_comment "\n#APP\n\t#"

#define link_warning(symbol, msg) \
  __make_section_unallocated (".gnu.warning." #symbol)  \
  static const char __evoke_link_warning_##symbol[]     \
    __attribute__ ((used, section (".gnu.warning." #symbol __sec_comment))) \
    = msg

#define obsolete_lib(name, lib)                         \
  link_warning(name, #name " was moved to libsystemd. Do not use " #lib ".")

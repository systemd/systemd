/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Linker Script that gives the .note.gnu_build_id section a nice symbol name
   we can reference via "extern" */

"_elf_note_build_id" = ADDR(.note.gnu.build-id) ;

/*
 * sys/elf32.h
 */

#ifndef _SYS_ELF32_H
#define _SYS_ELF32_H

#include <sys/elfcommon.h>

/* ELF standard typedefs (yet more proof that <stdint.h> was way overdue) */
typedef uint16_t  Elf32_Half;
typedef int16_t   Elf32_SHalf;
typedef uint32_t  Elf32_Word;
typedef int32_t   Elf32_Sword;
typedef uint64_t  Elf32_Xword;
typedef int64_t   Elf32_Sxword;

typedef uint32_t  Elf32_Off;
typedef uint32_t  Elf32_Addr;
typedef uint16_t  Elf32_Section;

/* Dynamic header */

typedef struct elf32_dyn {
  Elf32_Sword d_tag;
  union{
    Elf32_Sword d_val;
    Elf32_Addr  d_ptr;
  } d_un;
} Elf32_Dyn;

/* Relocations */

#define ELF32_R_SYM(x)	((x) >> 8)
#define ELF32_R_TYPE(x)	((x) & 0xff)

typedef struct elf32_rel {
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
} Elf32_Rel;

typedef struct elf32_rela {
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
  Elf32_Sword   r_addend;
} Elf32_Rela;

/* Symbol */

typedef struct elf32_sym {
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half    st_shndx;
} Elf32_Sym;

/* Main file header */

typedef struct elf32_hdr {
  unsigned char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

/* Program header */

typedef struct elf32_phdr {
  Elf32_Word    p_type;
  Elf32_Off     p_offset;
  Elf32_Addr    p_vaddr;
  Elf32_Addr    p_paddr;
  Elf32_Word    p_filesz;
  Elf32_Word    p_memsz;
  Elf32_Word    p_flags;
  Elf32_Word    p_align;
} Elf32_Phdr;


/* Section header */

typedef struct elf32_shdr {
  Elf32_Word    sh_name;
  Elf32_Word    sh_type;
  Elf32_Word    sh_flags;
  Elf32_Addr    sh_addr;
  Elf32_Off     sh_offset;
  Elf32_Word    sh_size;
  Elf32_Word    sh_link;
  Elf32_Word    sh_info;
  Elf32_Word    sh_addralign;
  Elf32_Word    sh_entsize;
} Elf32_Shdr;

/* Note header */
typedef struct elf32_note {
  Elf32_Word    n_namesz;       /* Name size */
  Elf32_Word    n_descsz;       /* Content size */
  Elf32_Word    n_type;         /* Content type */
} Elf32_Nhdr;

#endif /* _SYS_ELF32_H */


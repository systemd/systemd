/*
 * sys/elf64.h
 */

#ifndef _SYS_ELF64_H
#define _SYS_ELF64_H

#include <sys/elfcommon.h>

/* ELF standard typedefs (yet more proof that <stdint.h> was way overdue) */
typedef uint16_t  Elf64_Half;
typedef int16_t   Elf64_SHalf;
typedef uint32_t  Elf64_Word;
typedef int32_t   Elf64_Sword;
typedef uint64_t  Elf64_Xword;
typedef int64_t   Elf64_Sxword;

typedef uint64_t  Elf64_Off;
typedef uint64_t  Elf64_Addr;
typedef uint16_t  Elf64_Section;

/* Dynamic header */

typedef struct elf64_dyn {
  Elf64_Sxword d_tag;
  union{
    Elf64_Xword d_val;
    Elf64_Addr  d_ptr;
  } d_un;
} Elf64_Dyn;

/* Relocations */

#define ELF64_R_SYM(x)	((x) >> 32)
#define ELF64_R_TYPE(x)	((x) & 0xffffffff)

typedef struct elf64_rel {
  Elf64_Addr    r_offset;
  Elf64_Xword   r_info;
} Elf64_Rel;

typedef struct elf64_rela {
  Elf64_Addr    r_offset;
  Elf64_Xword   r_info;
  Elf64_Sxword  r_addend;
} Elf64_Rela;

/* Symbol */

typedef struct elf64_sym {
  Elf64_Word    st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Half    st_shndx;
  Elf64_Addr    st_value;
  Elf64_Xword   st_size;
} Elf64_Sym;

/* Main file header */

typedef struct elf64_hdr {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half    e_type;
  Elf64_Half    e_machine;
  Elf64_Word    e_version;
  Elf64_Addr    e_entry;
  Elf64_Off     e_phoff;
  Elf64_Off     e_shoff;
  Elf64_Word    e_flags;
  Elf64_Half    e_ehsize;
  Elf64_Half    e_phentsize;
  Elf64_Half    e_phnum;
  Elf64_Half    e_shentsize;
  Elf64_Half    e_shnum;
  Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

/* Program header */

typedef struct elf64_phdr {
  Elf64_Word    p_type;
  Elf64_Word    p_flags;
  Elf64_Off     p_offset;
  Elf64_Addr    p_vaddr;
  Elf64_Addr    p_paddr;
  Elf64_Xword   p_filesz;
  Elf64_Xword   p_memsz;
  Elf64_Xword   p_align;
} Elf64_Phdr;


/* Section header */

typedef struct elf64_shdr {
  Elf64_Word    sh_name;
  Elf64_Word    sh_type;
  Elf64_Xword   sh_flags;
  Elf64_Addr    sh_addr;
  Elf64_Off     sh_offset;
  Elf64_Xword   sh_size;
  Elf64_Word    sh_link;
  Elf64_Word    sh_info;
  Elf64_Xword   sh_addralign;
  Elf64_Xword   sh_entsize;
} Elf64_Shdr;

/* Note header */
typedef struct elf64_note {
  Elf64_Word    n_namesz;       /* Name size */
  Elf64_Word    n_descsz;       /* Content size */
  Elf64_Word    n_type;         /* Content type */
} Elf64_Nhdr;

#endif /* _SYS_ELF64_H */


/*
 * sys/elfcommon.h
 */

#ifndef _SYS_ELFCOMMON_H
#define _SYS_ELFCOMMON_H

#include <stdint.h>

/* Segment types */
#define PT_NULL    	0
#define PT_LOAD    	1
#define PT_DYNAMIC 	2
#define PT_INTERP  	3
#define PT_NOTE    	4
#define PT_SHLIB   	5
#define PT_PHDR    	6
#define PT_LOOS    	0x60000000
#define PT_HIOS    	0x6fffffff
#define PT_LOPROC  	0x70000000
#define PT_HIPROC  	0x7fffffff
#define PT_GNU_EH_FRAME	0x6474e550 /* Extension, eh? */

/* ELF file types */
#define ET_NONE   	0
#define ET_REL    	1
#define ET_EXEC   	2
#define ET_DYN    	3
#define ET_CORE   	4
#define ET_LOPROC 	0xff00
#define ET_HIPROC 	0xffff

/* ELF machine types */
#define EM_NONE  	0
#define EM_M32   	1
#define EM_SPARC 	2
#define EM_386   	3
#define EM_68K   	4
#define EM_88K   	5
#define EM_486   	6	/* Not used in Linux at least */
#define EM_860   	7
#define EM_MIPS         8       /* R3k, bigendian(?) */
#define EM_MIPS_RS4_BE 	10      /* R4k BE */
#define EM_PARISC      	15
#define EM_SPARC32PLUS 	18
#define EM_PPC         	20
#define EM_PPC64       	21
#define EM_S390         22
#define EM_SH          	42
#define EM_SPARCV9	43	/* v9 = SPARC64 */
#define EM_H8_300H      47
#define EM_H8S          48
#define EM_IA_64        50	/* Itanic */
#define EM_X86_64       62
#define EM_CRIS         76
#define EM_V850         87
#define EM_ALPHA        0x9026	/* Interrim Alpha that stuck around */
#define EM_CYGNUS_V850  0x9080	/* Old v850 ID used by Cygnus */
#define EM_S390_OLD     0xA390	/* Obsolete interrim value for S/390 */

/* Dynamic type values */
#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH	15
#define DT_SYMBOLIC	16
#define DT_REL		17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TEXTREL	22
#define DT_JMPREL	23
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

/* Auxilliary table entries */
#define AT_NULL		0       /* end of vector */
#define AT_IGNORE	1	/* entry should be ignored */
#define AT_EXECFD	2	/* file descriptor of program */
#define AT_PHDR		3	/* program headers for program */
#define AT_PHENT	4	/* size of program header entry */
#define AT_PHNUM	5	/* number of program headers */
#define AT_PAGESZ	6	/* system page size */
#define AT_BASE		7	/* base address of interpreter */
#define AT_FLAGS	8	/* flags */
#define AT_ENTRY	9	/* entry point of program */
#define AT_NOTELF	10	/* program is not ELF */
#define AT_UID		11	/* real uid */
#define AT_EUID		12	/* effective uid */
#define AT_GID		13	/* real gid */
#define AT_EGID		14	/* effective gid */
#define AT_PLATFORM	15	/* string identifying CPU for optimizations */
#define AT_HWCAP  	16	/* arch dependent hints at CPU capabilities */
#define AT_CLKTCK 	17	/* frequency at which times() increments */
/* 18..22 = ? */
#define AT_SECURE 	23	/* secure mode boolean */

/* Program header permission flags */
#define PF_X            0x1
#define PF_W            0x2
#define PF_R            0x4

/* Section header types */
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_SHLIB       10
#define SHT_DYNSYM      11
#define SHT_NUM         12
#define SHT_LOPROC      0x70000000
#define SHT_HIPROC      0x7fffffff
#define SHT_LOUSER      0x80000000
#define SHT_HIUSER      0xffffffff

/* Section header flags */
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4
#define SHF_MASKPROC    0xf0000000

/* Special section numbers */
#define SHN_UNDEF       0
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1
#define SHN_COMMON      0xfff2
#define SHN_HIRESERVE   0xffff

/* Lenght of magic at the start of a file */
#define EI_NIDENT	16

/* Magic number constants... */
#define EI_MAG0         0	/* e_ident[] indexes */
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4
#define EI_DATA         5
#define EI_VERSION      6
#define EI_OSABI        7
#define EI_PAD          8

#define ELFMAG0         0x7f	/* EI_MAG */
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'
#define ELFMAG          "\177ELF"
#define SELFMAG         4

#define ELFCLASSNONE    0	/* EI_CLASS */
#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFCLASSNUM     3

#define ELFDATANONE     0	/* e_ident[EI_DATA] */
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2

#define EV_NONE         0	/* e_version, EI_VERSION */
#define EV_CURRENT      1
#define EV_NUM          2

#define ELFOSABI_NONE   0
#define ELFOSABI_LINUX  3

#endif /* _SYS_ELFCOMMON_H */


SECTIONS {
        /* We skip the first page because the space will be occupied by the PE headers after conversion. */
        . = CONSTANT(MAXPAGESIZE);
        .text ALIGN(CONSTANT(MAXPAGESIZE)) : {
                *(.text .text.*)
        }
        .rodata ALIGN(CONSTANT(MAXPAGESIZE)) : {
                *(.rodata .rodata.*)
                *(.srodata .srodata.*)
        }
        .data ALIGN(CONSTANT(MAXPAGESIZE)) : {
                *(.data .data.*)
                *(.sdata .sdata.*)
                *(.got .got.*)
                *(.got.plt .got.plt.*)

                /* EDK2 says some firmware cannot handle BSS sections properly. */
                *(.bss .bss.*)
                *(.sbss .sbss.*)
                *(COMMON)
        }

        .sdmagic ALIGN(CONSTANT(MAXPAGESIZE)) : { *(.sdmagic) }
        .osrel   ALIGN(CONSTANT(MAXPAGESIZE)) : { *(.osrel) }
        .sbat    ALIGN(CONSTANT(MAXPAGESIZE)) : { *(.sbat) }

        /* These are used for PE conversion and then discarded. */
        .dynsym   : { *(.dynsym) }
        .dynstr   : { *(.dynstr) }
        .dynamic  : { *(.dynamic) }
        .rel.dyn  : { *(.rel.dyn) }
        .rela.dyn : { *(.rela.dyn) }

        /* These aren't needed and could be discarded. Just in case that they're useful to the debugger
         * we keep them, but move them out of the way to keep the PE binary more compact. */
        .ARM.exidx         : { *(.ARM.exidx) }
        .eh_frame          : { *(.eh_frame) }
        .eh_frame_hdr      : { *(.eh_frame_hdr) }
        .gnu.hash          : { *(.gnu.hash) }
        .hash              : { *(.hash) }
        .note.gnu.build-id : { *(.note.gnu.build-id ) }

        /DISCARD/ : {
                *(.ARM.attributes)
                *(.comment)
                *(.note.*)
                *(.riscv.attributes)
        }
}

#
# This is a hack to generate the .intrp section, which then
# ld turns into an PT_INTERP header.
#

        .section ".interp","a"
        .ascii LIBDIR
	.ascii "/klibc-"
        .ascii SOHASH
        .ascii ".so"
        .byte 0

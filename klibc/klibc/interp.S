#
# This is a hack to generate the .intrp section, which then
# ld turns into an PT_INTERP header.
#
# NOTE: The .interp section needs to be "a", or it doesnt work...
#
	
        .section ".interp","a"
        .ascii LIBDIR
	.ascii "/klibc-"
        .ascii SOHASH
        .ascii ".so"
        .byte 0

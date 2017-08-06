all:
	ninja -C build

install:
	DESTDIR=$(DESTDIR) ninja -C build install

# $Id$

CFLAGS=-Wall -pipe -W -O2 -Wextra -Wno-unused-parameter
VERSION=0.1

libnss_myhostname.so.2: nss-myhostname.o
	$(CC) $(CFLAGS) -shared -o $@ -Wl,-soname,$@ $^
	strip $@

install:
	install -D -g root -m 644 -o root -v libnss_myhostname.so.2 /lib/libnss_myhostname.so.2

clean:
	rm -f *.o *~ libnss_myhostname.so.2

nss-myhostname.tar.gz:
	rm -rf "nss-myhostname-$(VERSION)"
	mkdir "nss-myhostname-$(VERSION)"
	cp Makefile README *.c "nss-myhostname-$(VERSION)"/
	tar czf "nss-myhostname-$(VERSION).tar.gz" "nss-myhostname-$(VERSION)"/
	rm -rf "nss-myhostname-$(VERSION)"

tar: nss-myhostname.tar.gz

.PHONY: clean install tar

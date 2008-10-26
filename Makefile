# $Id$

CFLAGS=-Wall -pipe -W -O2 -Wextra -Wno-unused-parameter -fPIC
VERSION=0.1

libnss_myhostname.so.2: nss-myhostname.o
	$(CC) $(CFLAGS) -shared -o $@ -Wl,-soname,$@ $^
	strip $@

install:
	install -D -g root -m 644 -o root -v libnss_myhostname.so.2 /lib/libnss_myhostname.so.2

clean:
	rm -f *.o *~ libnss_myhostname.so.2

nss-myhostname-$(VERSION).tar.gz:
	rm -rf "nss-myhostname-$(VERSION)"
	mkdir "nss-myhostname-$(VERSION)"
	cp Makefile LICENSE README *.c "nss-myhostname-$(VERSION)"/
	rm -f "nss-myhostname-$(VERSION).tar.gz"
	tar czf "nss-myhostname-$(VERSION).tar.gz" "nss-myhostname-$(VERSION)"/
	rm -rf "nss-myhostname-$(VERSION)"

tar: nss-myhostname-$(VERSION).tar.gz

homepage: tar
	test -d $$HOME/homepage/private
	mkdir -p $$HOME/homepage/private/projects/nss-myhostname
	cp nss-myhostname-$(VERSION).tar.gz README $$HOME/homepage/private/projects/nss-myhostname
	ln -sf README $$HOME/homepage/private/projects/nss-myhostname/README.txt

.PHONY: clean install tar homepage

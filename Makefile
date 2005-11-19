CFLAGS=-Wall -pipe -W -O2 -Wextra -Wno-unused-parameter

libnss_myhostname.so.2: nss-myhostname.o
	$(CC) -shared -o $@ -Wl,-soname,$@ $^
	strip $@

install:
	install -D -g root -m 644 -o root -s -v libnss_myhostname.so.2 /usr/lib/libnss_myhostname.so.2

clean:
	rm -f *.o *~ libnss_myhostname.so.2

.PHONY: clean	

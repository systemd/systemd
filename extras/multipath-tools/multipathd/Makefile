EXEC = multipathd

CC = gcc
GZIP = /bin/gzip -9 -c

bindir = /usr/bin
mandir = /usr/share/man/man8
rcdir = /etc/init.d

CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -DDEBUG=1
LDFLAGS = -lpthread -ldevmapper -lsysfs

OBJS = main.o devinfo.o checkers.o

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(EXEC)
	strip $(EXEC)

install:
	install -d $(bindir)
	install -m 755 $(EXEC) $(bindir)
	install -d $(rcdir)
	install -m 755 multipathd.init $(rcdir)/$(EXEC)

uninstall:
	rm -f $(bindir)/$(EXEC)
	rm -f $(rcdir)/$(EXEC)

clean:
	rm -f core *.o $(EXEC) *.gz


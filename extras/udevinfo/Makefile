PROG=udevinfo
LD=$(CC)
OBJS=udevinfo.o

all:	$(PROG)

clean:
	rm -f $(PROG) $(OBJS)

$(PROG):	$(OBJS)
	$(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) $(SYSFS)

me:
	cd ../..; make EXTRAS=extras/udevinfo

PROG=udevinfo
OBJS=	../../udev_config.o \
	../../udev-add.o \
	../../udev-remove.o \
	../../udevdb.o \
	../../logging.o \
	../../namedev.o  \
	../../namedev_parse.o \
	../../libsysfs/sysfs_bus.o \
	../../libsysfs/sysfs_class.o \
	../../libsysfs/sysfs_device.o \
	../../libsysfs/sysfs_dir.o \
	../../libsysfs/sysfs_driver.o \
	../../libsysfs/sysfs_utils.o \
	../../libsysfs/dlist.o \
	../../tdb/tdb.o \
	../../tdb/spinlock.o \

all: $(PROG)

$(PROG): $(PROG).o
	$(LD) $(LDFLAGS) -o $(PROG) $(PROG).o $(OBJS) -lc

clean:
	rm -f $(PROG) $(OBJS) $(PROG).o

me:
	cd ../..; make EXTRAS=extras/udevinfo

CFLAGS=-Wall -Wextra -O0 -g -pipe -D_GNU_SOURCE -fdiagnostics-show-option -Wno-unused-parameter -DUNIT_PATH=\"/tmp/does/not/exist\" `pkg-config --cflags libudev dbus-1`
LIBS=-lrt -lcap `pkg-config --libs libudev dbus-1`

COMMON= \
	unit.o \
	util.o \
	set.o \
	hashmap.o \
	strv.o \
	job.o \
	manager.o \
	conf-parser.o \
	load-fragment.o \
	socket-util.o \
	log.o \
	service.o \
	automount.o \
	mount.o \
	device.o \
	target.o \
	snapshot.o \
	socket.o \
	timer.o \
	load-dropin.o \
	execute.o \
	ratelimit.o \
	dbus.o \
	dbus-manager.o \
	dbus-unit.o \
	dbus-job.o

all: systemd test-engine test-job-type systemd-logger systemctl systemadm

systemd: main.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

systemd-logger: logger.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

test-engine: test-engine.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

test-job-type: test-job-type.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

systemctl: systemctl.vala
	valac -g --save-temps systemctl.vala systemd-interfaces.vala --pkg=dbus-glib-1 --pkg=posix

systemadm: systemadm.vala
	valac -g --save-temps systemadm.vala systemd-interfaces.vala --pkg=dbus-glib-1 --pkg=posix --pkg gee-1.0 --pkg gtk+-2.0

clean:
	rm -f *.o systemd test-engine systemctl systemadm

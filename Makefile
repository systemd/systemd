CFLAGS=-Wall -Wextra -O0 -g -pipe -D_GNU_SOURCE -fdiagnostics-show-option -Wno-unused-parameter -DUNIT_PATH=\"/tmp/does/not/exist\" `pkg-config --cflags libudev`
LIBS=-lrt -lcap `pkg-config --libs libudev`

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
	load-fstab.o \
	load-dropin.o \
	execute.o

all: systemd test-engine test-job-type systemd-logger

systemd: main.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

systemd-logger: logger.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

test-engine: test-engine.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

test-job-type: test-job-type.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

clean:
	rm -f *.o systemd test-engine

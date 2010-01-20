CFLAGS=-Wall -Wextra -O0 -g -pipe -D_GNU_SOURCE -fdiagnostics-show-option -Wno-unused-parameter
LIBS=-lrt

COMMON=name.o util.o set.o hashmap.o strv.o job.o manager.o conf-parser.o load-fragment.o socket-util.o log.o

all: systemd test-engine

systemd: main.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

test-engine: test-engine.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

clean:
	rm -f *.o systemd test-engine

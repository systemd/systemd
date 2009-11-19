CFLAGS=-Wall -Wextra -O0 -g -pipe -D_GNU_SOURCE -fdiagnostics-show-option -Wno-unused-parameter
LIBS=-lrt

systemd: main.o name.o util.o set.o hashmap.o strv.o job.o manager.o conf-parser.o load-fragment.o
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

clean:
	rm -f *.o systemd

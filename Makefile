CFLAGS=-Wall -Wextra -O0 -g -pipe
LIBS=-lrt

systemd: main.o name.o util.o set.o hashmap.o strv.o job.o manager.o
	$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

clean:
	rm -f *.o systemd

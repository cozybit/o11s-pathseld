VERSION_STR="\"0.1\""

CFLAGS=-DVERSION_STR=$(VERSION_STR) -g
LDFLAGS=-lnl -lnl-genl -L/usr/local/lib

OBJECTS=main.o netlink.o

o11s_pathseld: $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(OBJECTS) o11s_pathseld

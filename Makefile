LDFLAGS += -lgcrypt 
CFLAGS += -g -Wall -fPIC -O0 -Wstrict-prototypes -pthread -fno-strict-aliasing

libecc.so: libecc.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl -o libecc.so libecc.o


CFLAGS = -g -I../ 
CFLAGS +=`pkg-config --cflags glib-2.0`
LDFLAGS += -L../ -lecc
LDFLAGS += `pkg-config --libs glib-2.0`

test_libecc: 
	$(CC) $(CFLAGS) $(LDFLAGS) test_libecc.c -o test_libecc

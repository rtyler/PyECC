LDFLAGS += -lgcrypt 
CFLAGS += -g -Wall -fPIC -O0 -Wstrict-prototypes -pthread -fno-strict-aliasing

default: binaries doc libseccure.so

binaries: seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify seccure-signcrypt seccure-veridec seccure-dh \

OBJS = numtheory.o libseccure.o ecc.o serialize.o protocol.o curves.o aes256ctr.o

doc: seccure.1 seccure.1.html

install: default
	install -m0755 seccure-key $(DESTDIR)/usr/bin
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-encrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-decrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-sign
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-verify
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-signcrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-veridec
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-dh
	install -m0644 seccure.1 $(DESTDIR)/usr/share/man/man1

clean:
	rm -f *.o *~ seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify seccure-signcrypt seccure-veridec \
	seccure-dh  seccure.1 seccure.1.html *.so*

rebuild: clean default

libseccure.o:
	$(CC) $(CFLAGS) -pedantic -Werror -c libseccure.c

seccure-key: seccure.o $(OBJS)
	$(CC) $(CFLAGS) -o seccure-key $(LDFLAGS) seccure.o $(OBJS)
	strip seccure-key

libseccure.so: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl -o libseccure.so $(OBJS) 

seccure-encrypt: seccure-key
	ln -f seccure-key seccure-encrypt

seccure-decrypt: seccure-key
	ln -f seccure-key seccure-decrypt

seccure-sign: seccure-key
	ln -f seccure-key seccure-sign

seccure-verify: seccure-key
	ln -f seccure-key seccure-verify

seccure-signcrypt: seccure-key
	ln -f seccure-key seccure-signcrypt

seccure-veridec: seccure-key
	ln -f seccure-key seccure-veridec

seccure-dh: seccure-key
	ln -f seccure-key seccure-dh

seccure.1: seccure.manpage.xml
	xmltoman seccure.manpage.xml > seccure.1

seccure.1.html: seccure.manpage.xml
	xmlmantohtml seccure.manpage.xml > seccure.1.html

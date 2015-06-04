all: ddnsv6d

CFLAGS = -O2 -g

ddnsv6d: ddnsv6d.c
	$(CC) $(CFLAGS) -o $@ $^

install:
	if [ ! -f /etc/ddnsv6d.conf ]; then install -m 0644 ddnsv6d.conf /etc/; fi
	install -m 0755 ddnsv6d /sbin/

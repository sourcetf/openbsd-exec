# Makefile for exec.c - OpenBSD pledge/unveil launcher
PROG = exec
SRCS = exec.c
OBJS = exec.o

CC ?= cc
CFLAGS += -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE
LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c -o $@ $(SRCS)

clean:
	rm -f $(PROG) $(OBJS)

install: $(PROG)
	install -m 755 $(PROG) /usr/local/bin/

.PHONY: all clean install

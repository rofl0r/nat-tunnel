-include config.mak

PROG = natsrv
PYTHON = python3

LIBS = -lpthread
CFLAGS += -Wall -std=c99

ifdef USE_SODIUM
CPPFLAGS += -DUSE_SODIUM
LIBS += -lsodium
SRCS = natsrv.c sha256.c
else
SRCS = natsrv.c sha256.c tweetnacl.c
endif
OBJS = $(SRCS:.c=.o)

all: $(PROG)

clean:
	rm -f $(PROG)
	rm -f $(OBJS)
	rm -f tweetnacl.o

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

# Test framework, see tests/natt.py. It starts real server and
# client processes on loopback ports and injects faults. Slow
# tests (TCP keepalive detection, ~45s) need NATT_SLOW=1.
test: $(PROG)
	$(PYTHON) tests/natt.py

test-slow: $(PROG)
	NATT_SLOW=1 $(PYTHON) tests/natt.py

test-list:
	$(PYTHON) tests/natt.py --list

.PHONY: all clean test test-slow test-list

-include config.mak

PROG = natsrv

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

.PHONY: all clean

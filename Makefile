PROG = natsrv
SRCS = natsrv.c sha256.c
OBJS = $(SRCS:.c=.o)

LIBS = -lpthread
CFLAGS += -Wall -std=c99

all: $(PROG)

clean:
	rm -f $(PROG)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

.PHONY: all clean

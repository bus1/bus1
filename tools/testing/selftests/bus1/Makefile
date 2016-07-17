TEST_PROGS := bus1-test

OBJS =				\
	bus1-client.o		\
	test.o			\
	test-api.o		\
	test-io.o		\
	test-peer.o		\
	test-xfer.o

CFLAGS += -Wall -I../../../../usr/include/

all: $(TEST_PROGS)

include ../lib.mk

clean:
	$(RM) $(TEST_PROGS)

%.o: %.c bus1-client.h test.h ../../../../usr/include/linux/bus1.h
	$(CC) $(CFLAGS) -c $< -o $@

bus1-test: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

TEST_PROGS := bus1-test

OBJS =				\
	bus1-peer.o		\
	test.o			\
	test-api.o		\
	test-peer.o		\
	test-xfer.o		\
	test-hive.o		\
	test-io.o

CFLAGS += -Wall -I../../../../usr/include/
LDLIBS += -lpthread

all: $(TEST_PROGS)

include ../lib.mk

clean:
	$(RM) $(TEST_PROGS)

%.o: %.c bus1-peer.h test.h ../../../../usr/include/linux/bus1.h
	$(CC) $(CFLAGS) -c $< -o $@

bus1-test: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

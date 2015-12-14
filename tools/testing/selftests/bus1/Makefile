TEST_PROGS := b1-test

OBJS =				\
	b1-client.c		\
	b1-test.c		\
	test-filesystem.c	\
	test-peer.c

CFLAGS += -I../../../../usr/include/

all: $(TEST_PROGS)

include ../lib.mk

clean:
	$(RM) $(TEST_PROGS)

%.o: %.c b1-client.h b1-test.h
	$(CC) $(CFLAGS) -c $< -o $@

b1-test: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

# Makefile for bus1 selftests

CC = $(CROSS_COMPILE)gcc
CFLAGS += -D_FILE_OFFSET_BITS=64 -Wall -g -O2
CFLAGS += -I../../../../include/uapi/
CFLAGS += -I../../../../include/
CFLAGS += -I../../../../usr/include/

TEST_PROGS := test-api test-io

all: $(TEST_PROGS)

%: %.c bus1-ioctl.h test.h ../../../../usr/include/linux/bus1.h
	$(CC) $(CFLAGS) $< -o $@

include ../lib.mk

clean:
	$(RM) $(TEST_PROGS)

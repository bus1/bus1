#
# Out-of-tree Bus1 Module
# This makefile builds the out-of-tree Bus1 module and all complementary
# elements, including documentation provided alongside the module.
#
# This Makefile serves two purposes. It serves as main Makefile for this
# project, but also as entry point for the out-of-tree kernel makefile hook.
# Therefore, this makefile is split into two parts. To avoid any conflicts, we
# move fixups, etc., into separate makefiles that are called from within here.
#

#
# Kernel Makefile
# This part builds the kernel module and everything related. It uses the kbuild
# infrastructure to hook into the obj- build of the kernel.
# The Documentation cannot be added here, as the kernel doesn't support that
# for out-of-tree modules.
#

obj-$(CONFIG_BUS1) += ipc/bus1/

#
# Project Makefile
# Everything below is part of the out-of-tree module and builds the related
# tools if the kernel makefile cannot be used.
#

BUS1EXT			?= 1
KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
SHELL			:= /bin/bash
PWD			:= $(shell pwd)
EXTRA_CFLAGS		+= -I$(PWD)/include -DCONFIG_BUS1_TESTS=1

#
# Default Target
# By default, build the out-of-tree module and everything that belongs into the
# same build.
#
all: module
.PHONY: all

#
# Module Target
# The 'module' target maps to the default out-of-tree target of the current
# tree. This builds the obj-{y,m} contents and also any hostprogs. We need a
# fixup for cflags and configuration options. Everything else is taken directly
# from the kernel makefiles.
#
module:
	@$(MAKE) -C $(KERNELDIR) \
		M=$(PWD) \
		BUS1EXT=$(BUS1EXT) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CONFIG_BUS1=m \
		CONFIG_BUS1_TESTS=y
.PHONY: module

#
# Documentation Target
# The out-of-tree support in the upstream makefile lacks integration with
# documentation targets. Therefore, we need a fixup makefile to make sure our
# documentation makefile works properly.
#
%docs:
	@$(MAKE) -f Makefile.docs $@

#
# Test
# This builds the self-tests, as 'kselftest' does not provide any out-of-tree
# integration..
#
tests:
	@$(MAKE) -C tools/testing/selftests/bus1/ \
		BUS1EXT=$(BUS1EXT) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CONFIG_BUS1=m \
		CONFIG_BUS1_TESTS=y
.PHONY: tests

#
# Check
# This runs sparse as part of the build process to try to detect any common
# errors in the kernel code.
#
check:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN" \
		BUS1EXT=$(BUS1EXT) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CONFIG_BUS1=m \
		CONFIG_BUS1_TESTS=y
.PHONY: check

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f ipc/bus1/{*.ko,*.o,.*.cmd,*.order,*.mod.c}
	rm -f Module.markers Module.symvers modules.order
	rm -f Documentation/bus1/{*.7,*.html}
	rm -f tools/testing/selftests/bus1/*.o
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)
.PHONY: clean

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/ipc/bus1/
	cp -f ipc/bus1/bus$(BUS1EXT).ko /lib/modules/$(KERNELVER)/kernel/ipc/bus1/
	depmod $(KERNELVER)
.PHONY: install

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/ipc/bus1/bus$(BUS1EXT).ko
.PHONY: uninstall

tt-prepare: module
	-sudo sh -c 'dmesg -c > /dev/null'
	-sudo sh -c 'rmmod bus$(BUS1EXT)'
	sudo sh -c 'insmod ipc/bus1/bus$(BUS1EXT).ko'
.PHONY: tt-prepare

tt: tests tt-prepare
	@$(MAKE) -C tools/testing/selftests/bus1/ \
		BUS1EXT=$(BUS1EXT) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CONFIG_BUS1=m \
		CONFIG_BUS1_TESTS=y \
		run_tests ; (R=$$? ; dmesg ; exit $$R)
.PHONY: tt

#
# Out-of-tree Bus1 Module
# This makefile builds the out-of-tree Bus1 module and all complementary
# elements, including samples and documentation provided alongside the module.
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
# Both the actual module and the samples are added. The Documentation cannot be
# added here, as the kernel doesn't support that for out-of-tree modules.
#

obj-$(CONFIG_BUS1) += ipc/bus1/
obj-$(CONFIG_SAMPLES) += samples/bus1/

#
# Project Makefile
# Everything below is part of the out-of-tree module and builds the related
# tools if the kernel makefile cannot be used.
#

BUS1_EXT		?= 1
KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
PWD			:= $(shell pwd)
EXTRA_CFLAGS		+= -I$(PWD)/include -DBUS1_SUPER_MAGIC=0x64766468726d
HOST_EXTRACFLAGS	+= -I$(PWD)/usr/include

#
# Default Target
# By default, build the out-of-tree module and everything that belongs into the
# same build.
#
all: module

#
# Module Target
# The 'module' target maps to the default out-of-tree target of the current
# tree. This builds the obj-{y,m} contents and also any hostprogs. We need a
# fixup for cflags and configuration options. Everything else is taken directly
# from the kernel makefiles.
#
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		HOST_EXTRACFLAGS="$(HOST_EXTRACFLAGS)" BUS1_EXT=$(BUS1_EXT) \
		CONFIG_BUS1=m CONFIG_SAMPLES=y CONFIG_SAMPLE_BUS1=y

#
# Documentation Target
# The out-of-tree support in the upstream makefile lacks integration with
# documentation targets. Therefore, we need a fixup makefile to make sure our
# documentation makefile works properly.
#
%docs:

# XXX: implement
#	$(MAKE) -f Makefile.docs $@

#
# Test
# This builds the self-tests, as 'kselftest' does not provide any out-of-tree
# integration..
#
tests:

# XXX: implement
#	CFLAGS="-g -O0" $(MAKE) -C tools/testing/selftests/bus1/

#
# Print Differences
# This compares the out-of-tree source with an upstream source and prints any
# differences. This should be used by maintainers to make sure we include all
# changes that are present in the in-tree sources.
#
diff:
	-@diff -q -u include/uapi/linux/bus1.h ./$(KERNELSRC)/include/uapi/linux/bus1.h
	-@diff -q -u -r ipc/bus1/ ./$(KERNELSRC)/ipc/bus1
	-@diff -q -u -r samples/bus1/ ./$(KERNELSRC)/samples/bus1
	-@diff -q -u -r Documentation/bus1/ ./$(KERNELSRC)/Documentation/bus1
	-@diff -q -u -r tools/testing/selftests/bus1/ ./$(KERNELSRC)/tools/testing/selftests/bus1

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f ipc/bus1/{*.ko,*.o,.*.cmd,*.order,*.mod.c}
	rm -f Module.markers Module.symvers modules.order
	rm -f samples/bus1/{*.o,modules.order,Module.symvers}
	rm -rf samples/bus1/{.*.cmd,.tmp_versions}
	rm -f Documentation/bus1/{*.7,*.html}
	rm -f tools/testing/selftests/bus1/{*.o}
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/ipc/bus1/
	cp -f ipc/bus1/bus$(BUS1_EXT).ko /lib/modules/$(KERNELVER)/kernel/ipc/bus1/
	depmod $(KERNELVER)

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/ipc/bus1/bus$(BUS1_EXT).ko

tt-prepare: module tests
	-sudo sh -c 'dmesg -c > /dev/null'
	-sudo umount /sys/fs/bus$(BUS1_EXT)
	-sudo sh -c 'rmmod bus$(BUS1_EXT)'
	sudo sh -c 'insmod ipc/bus1/bus$(BUS1_EXT).ko'
	sudo mount -t bus$(BUS1_EXT)fs bus$(BUS1_EXT)fs /sys/fs/bus$(BUS1_EXT)

tt: tt-prepare
	tools/testing/selftests/bus1/bus1-test -m bus$(BUS1_EXT) ; (R=$$? ; dmesg ; exit $$R)

stt: tt-prepare
	sudo tools/testing/selftests/bus1/bus1-test -m bus$(BUS1_EXT) ; (R=$$? ; dmesg ; exit $$R)

www_target = www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd

doc-sync: htmldocs
	rsync -rlv --delete-excluded --include="*.html" --exclude="*" --omit-dir-times Documentation/bus1/ $(www_target)/bus1/

.PHONY: all module tests clean install uninstall tt-prepare tt stt

#
# By setting BUS1EXT=X, the bus1 module will be built as busX.ko, and
# KBUILD_MODNAME=busX. This has the effect that all exported objects have
# different names than usual and you can run your test-infrastructure against
# the busX.ko, while running your system on bus1.ko.
#
# To just build the module, use:
#     make BUS1EXT=2 M=ipc/bus1
#

bus$(BUS1EXT)-y :=		\
	handle.o		\
	main.o			\
	message.o		\
	peer.o			\
	tx.o			\
	user.o			\
	util.o			\
	util/active.o		\
	util/flist.o		\
	util/pool.o		\
	util/queue.o

bus$(BUS1EXT)-$(CONFIG_BUS1_TESTS) += tests.o

obj-$(CONFIG_BUS1) += bus$(BUS1EXT).o

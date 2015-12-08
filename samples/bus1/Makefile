# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# XXX: implement
#hostprogs-$(CONFIG_SAMPLE_BUS1) += bus1-workers

always := $(hostprogs-y)

HOSTCFLAGS_bus1-workers.o += -I$(objtree)/usr/include
HOSTLOADLIBES_bus1-workers := -lrt

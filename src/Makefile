ifneq ($(KERNELRELEASE),)
KBUILD_CFLAGS += -fno-inline -DKERNEL_VERSION=$(VERSION) \
-DKERNEL_PATCHLEVEL=$(PATCHLEVEL)
obj-m := ublkdev.o

else
# Get the kernel version and create a preprocessor macro for it.  This allows
# us to target multiple Linux kernel versions.
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KERNEL_VERSION= $(shell printf "0x%02x%02x" $(shell uname -r | sed -e 's/\..*//') $(shell uname -r | sed -e 's/^[^\.]*\.\([^\.]*\)\..*/\1/'))

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -f Module.markers Module.symvers modules.order *.o *.ko *.mod.c *~ core*

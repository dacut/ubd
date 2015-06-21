ifneq ($(KERNELRELEASE),)
obj-m := ublkdev.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KERNEL_VERSION= $(shell printf "0x%02x%02x" $(shell uname -r | sed -e 's/\..*//') $(shell uname -r | sed -e 's/^[^\.]*\.\([^\.]*\)\..*/\1/'))

default:
	echo "#define KERNEL_VERSION $(KERNEL_VERSION)" > ublkdev_kernel.h
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -f Module.markers Module.symvers modules.order *.o *.ko *.mod.c *~ core*

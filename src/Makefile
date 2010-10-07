ifneq ($(KERNELRELEASE),)
obj-m := ublkdev.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -f Module.markers Module.symvers modules.order *.o *.ko *.mod.c *~ core*

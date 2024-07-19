# atemsys.ko: Provides usermode access to:
# 
#   - PCI configuration space
#   - Device IO memory
#   - Contiguous DMA memory
#   - Single device interrupt
# 
# Copyright (c) 2009 - 2018 acontis technologies GmbH, Ravensburg, Germany <info@acontis.com>
# All rights reserved.
#
# Author: K. Olbrich <k.olbrich@acontis.com>
#
# To compile and load the atemsys driver
#
# make modules 
# [ -c /dev/atemsys ] || sudo mknod /dev/atemsys c 101 0 
# sudo insmod atemsys.ko

CONFIG_MODULE_SIG=n

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += atemsys.o

all: modules

modules:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules clean

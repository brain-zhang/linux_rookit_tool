KERNELDIR=/usr/src/linux-headers-3.2.0-39-generic-pae
PWD:=$(shell pwd)
obj-m :=kscript.o
modules:
    $(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
    rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c *.order *.symvers

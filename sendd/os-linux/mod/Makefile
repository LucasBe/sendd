obj-m += send.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD)/sendd/os/mod modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD)/sendd/os/mod clean

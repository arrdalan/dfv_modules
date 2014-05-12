.PHONY: clean

all: build

dfvserver-objs := dfv_common.o			\
		  dfv_server.o


dfvserver_xen-objs := dfv_common_xen.o 		\
		      dfv_server_xen.o

dfvclient-objs := dfv_common.o			\
		  dfv_client.o


dfvclient_xen-objs := dfv_common_xen.o 		\
		      dfv_client_xen.o

obj-m := dfvserver.o dfvserver_xen.o dfvclient.o dfvclient_xen.o dfv_drm.o dfv_pci.o dfv_gpu.o dfv_input.o
KDIR  := ~/dfv/ubuntu_dfv/debian/build/build-generic-pae/
EXTRA_CFLAGS = -Wall

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.o *.mod.* .*cmd Module.symvers modules.order .tmp_versions

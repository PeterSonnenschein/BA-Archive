obj-m += page_to_nid.o

KBUILD_CFLAGS += -g -O2

KDIR := /lib/modules/$(shell uname -r)/build

BPF_CLANG_FLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86 -I bpf/usr/include
USER_CFLAGS := -g -O2 -Wall -I bpf/usr/include

all: kernel_module profiler

kernel_module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

profiler: vmlinux.h profiler_ebpf.o profiler_ebpf.skel.h profiler.o
	cc $(USER_CFLAGS) profiler.o /lib64/libbpf.a -lelf -lz -o profiler

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

profiler_ebpf.o: profiler_ebpf.c vmlinux.h
	clang $(BPF_CLANG_FLAGS) -c $< -o $@
	llvm-strip -g $@

profiler_ebpf.skel.h: profiler_ebpf.o
	/usr/sbin/bpftool gen skeleton $< > $@

profiler.o: profiler.c profiler_ebpf.skel.h
	cc $(USER_CFLAGS) -c $< -o $@

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* *.order *.symvers
	rm -f profiler vmlinux.h profiler_ebpf.skel.h
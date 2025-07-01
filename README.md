# Archive of Bachelor Thesis Design and Implementation of a NUMA-AWARE Evaluation Framework

## Dependencies:
sudo apt install linux-tools-$(uname -r)
sudo apt install clang llvm

## Compiling:
Use the included Makefile:
     make

## Running the Profiler:
You need to load the page_to_nid.ko module before running the profiler:
    sudo insmod page_to_nid.ko

## Error Handling:
If the kfunc fails to compile with:
     Skipping BTF generation for page_to_nid.ko due to unavailability of vmlinux

 Solution:
     sudo apt install dwarves
     sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/

 Note:
 During testing, libbpf.a was not always in the same folder.
 This Makefile expects it in /lib64. If needed, update the path to:
     bpf/usr/lib64/
 Adjust accordingly if facing linker errors.

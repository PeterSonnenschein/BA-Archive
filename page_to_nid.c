#include <linux/init.h>     
#include <linux/module.h>     
#include <linux/kernel.h>     
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("This kernel module exposes kernel functionallity to eBPF, enable page cache profiling");
MODULE_VERSION("1.0");     

__bpf_kfunc int bpf_page_to_nid(unsigned long flags);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_page_to_nid(unsigned long flags) {

    return ((flags >> NODES_PGSHIFT) & NODES_MASK);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_profiler_id_set)
BTF_ID_FLAGS(func, bpf_page_to_nid)
BTF_KFUNCS_END(bpf_kfunc_profiler_id_set)

static const struct btf_kfunc_id_set bpf_kfunc_profiler_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_profiler_id_set,
};

static int __init page_to_nid_init(void) {
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_profiler_set);
    if(ret) {
        pr_err("bpf_kfunc_profiler_id_set: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_profiler_id_set: Module loaded successfully\n");
    return 0;
}

static void __exit page_to_nid_exit(void) {

    /* For my kernel not needed, need to investigate why that is (probably
    *  unregistering modules is handled automatically) or if this is the
    *  case for other kernels aswell. 
    *
    *  unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    */

    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(page_to_nid_init);
module_exit(page_to_nid_exit);
     


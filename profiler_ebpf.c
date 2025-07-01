#include "vmlinux.h"
#include "profiler.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* kfunc used to expose the kernel func page_to_nid to eBPF programs */
extern int bpf_page_to_nid(int flags) __ksym;

#define PAGE_MAPPING_ANON	0x1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, u64);
} memory_access SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} thread_migration SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} fbatch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("kprobe/filemap_get_pages")
int kprobe_filemap_get_pages(struct pt_regs *ctx) 
{

	u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if(!bpf_map_lookup_elem(&target_pid_map, &tgid)) {
        return 0;
    }
	
    u32 pid = (u32) pid_tgid;

    u64 latency = bpf_ktime_get_ns();
    bpf_map_update_elem(&memory_access, &pid, &latency, BPF_ANY);

    struct folio_batch *fbatch = (struct folio_batch *)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&fbatch_map, &pid_tgid, &fbatch, BPF_ANY);
    return 0;
}

SEC("kretprobe/filemap_get_pages")
int kretprobe_filemap_get_pages(struct pt_regs *ctx) 
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&target_pid_map, &tgid)) {
        return 0;
    }

    u32 pid = (u32) pid_tgid;
    u64 time = bpf_ktime_get_ns();
    u64 *start = bpf_map_lookup_elem(&memory_access, &pid);
    if (!start) {
        return 0;
    }

    int64_t latency = time - *start;

    struct folio_batch **fbatch_ptr = bpf_map_lookup_elem(&fbatch_map, &pid_tgid);

    if (!fbatch_ptr) {
        bpf_printk("fbatch not present\n");
        return 0;
    }
    int nr = BPF_CORE_READ(*fbatch_ptr, nr);
    int curr = nr;
    for (int i = 0; i <= (curr - 1); i++) {
        struct folio *folio = BPF_CORE_READ(*fbatch_ptr, folios[i]);
        unsigned char folio_nid;
        if (folio) {
            unsigned long flags = BPF_CORE_READ(folio, flags);
            folio_nid = bpf_page_to_nid(flags);
            
           	struct report_event *re = bpf_ringbuf_reserve(&rb, sizeof(*re), 0);
            	if (re) {
                	re->type = RW;
                	re->pid = pid;
                	re->thread_nid = bpf_get_numa_node_id();
                	re->folio_nid = folio_nid;
                	re->nr = nr;
					re->latency = latency;
                	re->time  = time;
                	bpf_ringbuf_submit(re, 0);
            	} else {
                	bpf_printk("ringbuffer is full! event: filemap_get_pages\n");
                	return 0;
            	}
        } else {
        	bpf_printk("folio not present\n");
            	return 0;
        }
    }

    bpf_map_delete_elem(&memory_access, &pid);

    return 0;  
}

SEC("kprobe/__filemap_get_folio")
int kprobe__filemap_get_folio(void *ctx) 
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&target_pid_map, &tgid)) {
        return 0;
    }

    u32 pid = (u32) pid_tgid;
    u64 latency = bpf_ktime_get_ns();
    bpf_map_update_elem(&memory_access, &pid, &latency, BPF_ANY);

    return 0;
}

SEC("kretprobe/__filemap_get_folio")
int kretprobe___filemap_get_folio(struct pt_regs *ctx) 
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&target_pid_map, &tgid)) {
        return 0;
    }

    u32 pid = (u32) pid_tgid;
    u64 time = bpf_ktime_get_ns();
    u64 *start = bpf_map_lookup_elem(&memory_access, &pid);
    if (!start) {
        return 0;
    }
    
    int64_t latency = time - *start;

    unsigned char folio_nid;
    struct folio *folio = (struct folio *)PT_REGS_RC(ctx);
    if (folio) {
        unsigned long flags = BPF_CORE_READ(folio, flags);
        folio_nid = bpf_page_to_nid(flags);

        struct report_event *re = bpf_ringbuf_reserve(&rb, sizeof(*re), 0);
        if (re) {
            re->type = RW;
            re->pid = pid;
            re->thread_nid = bpf_get_numa_node_id();
            re->folio_nid = folio_nid;
            re->latency = latency;
            re->nr = 1;
            re->time  = time;
            bpf_ringbuf_submit(re, 0);
            bpf_map_delete_elem(&memory_access, &pid);
            return 0;
        } else {
            bpf_printk("ringbuffer is full! event: filemap_get_folio\n");
            bpf_map_delete_elem(&memory_access, &pid);
            return 0;
        }

    } else {
        bpf_map_delete_elem(&memory_access, &pid);
        return 0;
    }
    
    return 0;
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{

    u32 tgid = BPF_CORE_READ(next, tgid);
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &tgid);

    if (!target_pid) {
        return 0;
    }
    pid_t pid = BPF_CORE_READ(next, pid);

    u32 *prev_nid = bpf_map_lookup_elem(&thread_migration, &pid);
    u32 nid = bpf_get_numa_node_id();
    
    if (prev_nid) {
        if (*prev_nid != nid) {
            struct report_event *re = bpf_ringbuf_reserve(&rb, sizeof(*re), 0);
            if (re) {
                re->type = SCHED;
                re->pid = pid;
                re->thread_nid = nid;
                re->nr = 1;
                re->folio_nid = *prev_nid;
                re->latency = 0;
                re->time = bpf_ktime_get_ns();
                bpf_ringbuf_submit(re, 0);
               bpf_map_update_elem(&thread_migration, &pid, &nid, BPF_ANY); 
            } else {
		    bpf_map_update_elem(&thread_migration, &pid, &nid, BPF_ANY);
		    bpf_printk("ringbuffer is full! event: sched_switch\n");
                return 0;
            }

        } else {
 
            return 0;
        }

    } else {
        bpf_map_update_elem(&thread_migration, &pid, &nid, BPF_ANY);
    }
    
    return 0;
}

SEC("kretprobe/kernel_clone")
int kretprobe_kernel_clone(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32) pid_tgid;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &pid);
    if (!target_pid) {
        return 0;
    }

    u32 created_pid = (u32) PT_REGS_RC(ctx);
    if (created_pid != 0) {
        bpf_map_update_elem(&target_pid_map, &created_pid, &created_pid, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/mpol_misplaced")
int kretprobe_mpol_misplaced(struct pt_regs *ctx)
{

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &tgid);
	if (!target_pid) {
		return 0;
	}

	/* Check if folio is in the Page Cache */ 
	struct folio *folio = (struct folio *)PT_REGS_PARM1(ctx);

	if (!folio) {
		bpf_printk("folio does not exist");
		return 0;
	}

	struct address_space *mapping = BPF_CORE_READ(folio, mapping);
	if (!mapping)
		return 0;

	if (!((unsigned long)mapping & PAGE_MAPPING_ANON))
		return 0;

	int flags = BPF_CORE_READ(folio, flags);
	int folio_nid = bpf_page_to_nid(flags);
	
	struct report_event *re = bpf_ringbuf_reserve(&rb, sizeof(*re), 0);
	if (re) {
		re->type = ANB;
		re->pid = (u32) pid_tgid;
		re->thread_nid = bpf_get_numa_node_id();
		re->folio_nid = folio_nid;
		re->nr = 1;
		re->latency = 0;
		re->time = bpf_ktime_get_ns();
		bpf_ringbuf_submit(re, 0);
		return 0;
	} else {
		bpf_printk("ringbuffer is full! /n");
	}
	return 0;
}



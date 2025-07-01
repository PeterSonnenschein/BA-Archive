#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "profiler_ebpf.skel.h"
#include "profiler.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

const char *filename;
FILE *f;

static int handle_event(void *ctx, void *data, size_t data_sz) 
{
    struct report_event *e = data; 
    if(e->nr > 0) {
        fprintf(f, "%d,%" PRIu32",%u,%u,%u,%lu,%lu\n", e->type, e->pid,e->thread_nid, e->nr, e->folio_nid, (e->latency/e->nr), e->time);
    } else {
        fprintf(f, "%d,%" PRIu32",%u,%u,%u,%lu,%lu\n", e->type, e->pid,e->thread_nid, e->nr, e->folio_nid, e->latency, e->time);
    }
    
    return 0;
}

int main(int argc, char **argv) 
{

    struct profiler_ebpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    uint32_t pid;

    filename = "profiling_data.csv";
    f = fopen(filename, "w");

    if (!f) {
        printf("missing file\n");
        return 0;
    }

    if (argc < 2) {
        printf("flase input format!\n");
        return 0;
    }
    fprintf(f, "%s,%s,%s,%s,%s,%s,%s\n", "type", "thread_id", "thread_nid", "nr", "folio_nid", "latency", "time");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    skel = profiler_ebpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = profiler_ebpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    pid = fork();

    if (pid == 0) {
        sleep(5);
        execvp(argv[1], &argv[1]);
        exit(1);

    } else {

        err = profiler_ebpf__attach(skel);
        if(err) {
            fprintf(stderr, "Failed to attach BPF skeleton\n");
            goto cleanup;
        }

        int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "target_pid_map");
        if (map_fd < 0) {
            fprintf(stderr, "Failed to open map\n");
            goto cleanup;
        }

        if (bpf_map_update_elem(map_fd, &pid, &pid, BPF_ANY) < 0) {
            exit(1);
        }

        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            err = -1;
            fprintf(stderr, "Failed to create folio ring buffer\n");
            goto cleanup;
        }

        while (!exiting) {
            err = ring_buffer__poll(rb, 1);

            int status; 
            pid_t result = waitpid(pid, &status, WNOHANG);
            if(result == pid) {
                printf("child process %d has exited\n", pid);
                break;
            }
        
        }

        /* put this into a function */
        int rounds = 0;
        while (rounds < 5) {
            int res = ring_buffer__poll(rb, 100);
            printf("clearing ringbuff...\n");
            if (res == 0) {
                rounds ++;
            } else {
                rounds = 0;
            }
        }
	fflush(f);

	err = system("python3 profiler_vis.py");
	if (err) {
		fprintf(stderr, "Failed to visualize data\n");
	}
		
    }	

cleanup:
    printf("Made it to cleanup!\n");
    fclose(f);
    ring_buffer__free(rb);
    profiler_ebpf__destroy(skel);
    return err < 0 ? -err : 0;
}

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <numaif.h>
#include <numa.h>
#include <sched.h>

int main(void) {
    int fd;
    int count = 0;
    char test[4096];
    ssize_t bytes_read;
    pid_t pid;
    pid = fork();

    fd = open("test.bin", O_RDWR);
    for(int x  = 0; x < 50; x++) {

        count++;
    
        sleep(1);
        bytes_read = read(fd, test, 4096);
        pid_t real = getpid();
        printf("PID: %d, FD: %d, Coutner: %d, bytes read: %zd\n", real, fd, count, bytes_read);
            
    }

    close(fd);
    
    return 0;
}

 
